// Package scheduler runs periodically to compute the desired policy state
// and synchronize it with the nftables sets. It NEVER flushes or recreates
// the firewall; it only adds/removes MAC addresses from the sets.
package scheduler

import (
    "context"
    "time"

    "lias/internal/database"
    "lias/internal/firewall"
    "lias/internal/logging"
    "lias/internal/policy"
)

// Scheduler handles periodic evaluation and synchronization.
type Scheduler struct {
    db     *database.DB
    fw     *firewall.Firewall
    logger *logging.Logger
}

// New creates a new Scheduler instance.
func New(db *database.DB, fw *firewall.Firewall, logger *logging.Logger) *Scheduler {
    return &Scheduler{
        db:     db,
        fw:     fw,
        logger: logger,
    }
}

// Run starts the periodic evaluation loop.
func (s *Scheduler) Run(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            s.logger.Infof("Scheduler stopped.")
            return
        case <-ticker.C:
            if err := s.RunOnce(); err != nil {
                s.logger.Errorf("Scheduler cycle failed: %v", err)
            }
        }
    }
}

// RunOnce computes the desired state and applies the diff to nftables.
func (s *Scheduler) RunOnce() error {
    startTime := time.Now()
    now := time.Now()

    // 1. Compute desired state from SQLite
    desired, err := policy.ComputeDesiredState(s.db, now)
    if err != nil {
        return err
    }

    // 2. Synchronize blocked_macs set
    if err := s.fw.SyncBlockedMACs(desired.BlockMACs); err != nil {
        s.logger.Errorf("Failed to sync blocked_macs: %v", err)
    } else {
        s.logger.Debugf("Synced %d blocked MACs.", len(desired.BlockMACs))
    }

    // 3. Synchronize override_allow set
    if err := s.fw.SyncOverrideMACs(desired.OverrideMACs); err != nil {
        s.logger.Errorf("Failed to sync override_allow: %v", err)
    } else {
        s.logger.Debugf("Synced %d override MACs.", len(desired.OverrideMACs))
    }

    s.logger.Infof("Scheduler cycle completed in %s", time.Since(startTime))
    return nil
}
