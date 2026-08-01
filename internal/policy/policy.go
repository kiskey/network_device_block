// Package policy evaluates device and global policies against the current
// time to determine the desired firewall state.
// v4.0.0: Implements the "Never Block" (Immutable Infrastructure) zone.
package policy

import (
    "fmt"
    "time"

    "lias/internal/database"
)

// DesiredState represents the computed lists of MAC addresses.
type DesiredState struct {
    BlockMACs    []string
    OverrideMACs []string
}

// ComputeDesiredState queries the database and returns the desired MAC lists.
func ComputeDesiredState(db *database.DB, now time.Time) (*DesiredState, error) {
    devices, err := db.GetAllDevices()
    if err != nil {
        return nil, fmt.Errorf("get devices: %w", err)
    }

    globalPolicy, err := db.GetGlobalPolicy()
    if err != nil {
        return nil, fmt.Errorf("get global policy: %w", err)
    }

    // Preload global schedules if global policy is active and in a schedule mode
    var globalSchedules []database.Schedule
    if globalPolicy.Enabled && (globalPolicy.Mode == database.ModeScheduleBlock || globalPolicy.Mode == database.ModeScheduleAllow) {
        globalSchedules, err = db.GetSchedulesByPolicy(globalPolicy.ID)
        if err != nil {
            return nil, fmt.Errorf("get global schedules: %w", err)
        }
    }

    state := &DesiredState{
        BlockMACs:    make([]string, 0),
        OverrideMACs: make([]string, 0),
    }

    for _, dev := range devices {
        // v4.0.0: IMMUTABLE INFRASTRUCTURE CHECK
        // If a device is tagged as infrastructure, it is ALWAYS allowed.
        // It ignores global policies, schedules, and instant pauses.
        if dev.IsInfrastructure {
            state.OverrideMACs = append(state.OverrideMACs, dev.MAC)
            continue
        }

        // 1. Instant Pause (Highest priority for non-infrastructure)
        if dev.Paused {
            state.BlockMACs = append(state.BlockMACs, dev.MAC)
            continue
        }

        // 2. Global Policy (If Enabled, supersedes device rules)
        if globalPolicy.Enabled {
            applyPolicy(dev.MAC, globalPolicy.Mode, globalSchedules, now, state)
            continue
        }

        // 3. Device Override (if exists and enabled)
        devPolicy, err := db.GetDevicePolicy(dev.MAC)
        if err != nil {
            return nil, fmt.Errorf("get policy for %s: %w", dev.MAC, err)
        }

        if devPolicy != nil && devPolicy.Enabled && devPolicy.Mode != database.ModeGlobal {
            var devSchedules []database.Schedule
            if devPolicy.Mode == database.ModeScheduleBlock || devPolicy.Mode == database.ModeScheduleAllow {
                devSchedules, err = db.GetSchedulesByPolicy(devPolicy.ID)
                if err != nil {
                    return nil, fmt.Errorf("get schedules for %s: %w", dev.MAC, err)
                }
            }
            applyPolicy(dev.MAC, devPolicy.Mode, devSchedules, now, state)
        } else {
            // Fallback: Allow
            state.OverrideMACs = append(state.OverrideMACs, dev.MAC)
        }
    }

    return state, nil
}

// applyPolicy maps a policy mode to the desired state sets.
func applyPolicy(mac string, mode string, schedules []database.Schedule, now time.Time, state *DesiredState) {
    switch mode {
    case database.ModeBlockAlways:
        state.BlockMACs = append(state.BlockMACs, mac)
    case database.ModeAllowAlways:
        state.OverrideMACs = append(state.OverrideMACs, mac)
    case database.ModeScheduleBlock:
        if IsBlockedNow(schedules, now) {
            state.BlockMACs = append(state.BlockMACs, mac)
        } else {
            state.OverrideMACs = append(state.OverrideMACs, mac)
        }
    case database.ModeScheduleAllow:
        if IsAllowedNow(schedules, now) {
            state.OverrideMACs = append(state.OverrideMACs, mac)
        } else {
            state.BlockMACs = append(state.BlockMACs, mac)
        }
    }
}
