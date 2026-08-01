// Package discovery (discovery.go) is the Discovery Manager.
// v3.1.0: Adds mDNS, SSDP, and NBNS to the passive loop for instant metadata.
package discovery

import (
    "context"
    "time"

    "lias/internal/database"
    "lias/internal/logging"
)

// Provider is an interface for all discovery sources.
type Provider interface {
    Discover() ([]Observation, error)
    Name() string
}

// Manager handles the periodic scanning and merging of LAN devices.
type Manager struct {
    db           *database.DB
    logger       *logging.Logger
    mergeEngine  *MergeEngine
    passiveProvs []Provider
    activeProvs  []Provider
}

// New initializes the Discovery Manager.
func New(db *database.DB, logger *logging.Logger, ouiPath, dhcpPath, iface string) *Manager {
    m := &Manager{
        db:          db,
        logger:      logger,
        mergeEngine: NewMergeEngine(),
    }

    // Initialize Passive Providers (Always on, 30s interval)
    // v3.1.0: Added mDNS, SSDP, NBNS for instant device identification
    m.passiveProvs = []Provider{
        NewNetlinkProvider(iface, logger),
        NewDHCPProvider(dhcpPath, logger),
        NewMDNSProvider(logger),
        NewSSDPProvider(logger),
        NewNBNSProvider(logger),
    }

    // Initialize Active Providers (10m interval)
    m.activeProvs = []Provider{
        NewNmapProvider(db, logger),
    }

    return m
}

// Run starts the periodic discovery loops.
func (m *Manager) Run(ctx context.Context, passiveInterval, activeInterval time.Duration) {
    // Run once immediately
    m.runPassive()
    m.runActive()

    passiveTicker := time.NewTicker(passiveInterval)
    activeTicker := time.NewTicker(activeInterval)
    defer passiveTicker.Stop()
    defer activeTicker.Stop()

    for {
        select {
        case <-ctx.Done():
            m.logger.Infof("Discovery Manager stopped.")
            return
        case <-passiveTicker.C:
            m.runPassive()
        case <-activeTicker.C:
            m.runActive()
        }
    }
}

// runPassive collects observations from fast, passive sources and upserts them.
func (m *Manager) runPassive() {
    var observations []Observation

    for _, p := range m.passiveProvs {
        obs, err := p.Discover()
        if err != nil {
            m.logger.Warnf("%s discovery failed: %v", p.Name(), err)
            continue
        }
        observations = append(observations, obs...)
    }

    merged := m.mergeEngine.Merge(observations)

    for _, devObs := range merged {
        InferDeviceType(&devObs)
        if err := m.db.UpsertDevice(devObs); err != nil {
            m.logger.Errorf("Failed upserting device %s: %v", devObs.MAC, err)
        }
    }

    // Mark devices not seen recently as offline
    cutoff := time.Now().Add(-90 * time.Second).Unix()
    if _, err := m.db.MarkStaleDevicesOffline(cutoff); err != nil {
        m.logger.Errorf("Failed marking stale devices offline: %v", err)
    }
}

// runActive collects observations from slow, active sources (like Nmap)
func (m *Manager) runActive() {
    var observations []Observation

    for _, p := range m.activeProvs {
        obs, err := p.Discover()
        if err != nil {
            m.logger.Warnf("%s discovery failed: %v", p.Name(), err)
            continue
        }
        observations = append(observations, obs...)
    }

    if len(observations) == 0 {
        return
    }

    merged := m.mergeEngine.Merge(observations)

    for _, devObs := range merged {
        InferDeviceType(&devObs)
        if err := m.db.UpsertDevice(devObs); err != nil {
            m.logger.Errorf("Failed upserting device %s: %v", devObs.MAC, err)
        }
    }
}

// ForceRefresh can be called by the API to trigger an immediate active scan.
func (m *Manager) ForceRefresh() {
    go m.runActive()
}
