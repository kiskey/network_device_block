// Package policy evaluates device and global policies against the current
// time to determine the desired firewall state (which MACs to block and
// which to explicitly allow).
package policy

import (
    "fmt"
    "time"

    "lias/internal/database"
)

// DesiredState represents the computed lists of MAC addresses that should
// be populated in the nftables sets.
type DesiredState struct {
    BlockMACs    []string
    OverrideMACs []string
}

// ComputeDesiredState queries the database for all devices and policies,
// evaluates them against the provided time, and returns the desired MAC lists.
func ComputeDesiredState(db *database.DB, now time.Time) (*DesiredState, error) {
    devices, err := db.GetAllDevices()
    if err != nil {
        return nil, fmt.Errorf("get devices: %w", err)
    }

    globalPolicy, err := db.GetGlobalPolicy()
    if err != nil {
        return nil, fmt.Errorf("get global policy: %w", err)
    }

    // Preload global schedules if global policy is in SCHEDULE mode
    var globalSchedules []database.Schedule
    if globalPolicy.Enabled && globalPolicy.Mode == database.ModeSchedule {
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
        // Fetch the effective policy (Device override > Global)
        effectiveMode := globalPolicy.Mode
        effectiveEnabled := globalPolicy.Enabled
        var schedules []database.Schedule = globalSchedules

        devPolicy, err := db.GetDevicePolicy(dev.MAC)
        if err != nil {
            return nil, fmt.Errorf("get policy for %s: %w", dev.MAC, err)
        }

        if devPolicy != nil && devPolicy.Enabled && devPolicy.Mode != database.ModeGlobal {
            effectiveMode = devPolicy.Mode
            if effectiveMode == database.ModeSchedule {
                schedules, err = db.GetSchedulesByPolicy(devPolicy.ID)
                if err != nil {
                    return nil, fmt.Errorf("get schedules for %s: %w", dev.MAC, err)
                }
            }
        }

        if !effectiveEnabled {
            // If the effective policy is disabled, treat as ALLOW_ALWAYS
            effectiveMode = database.ModeAllowAlways
        }

        switch effectiveMode {
        case database.ModeBlockAlways:
            state.BlockMACs = append(state.BlockMACs, dev.MAC)
        case database.ModeAllowAlways:
            state.OverrideMACs = append(state.OverrideMACs, dev.MAC)
        case database.ModeSchedule:
            // FIX: SCHEDULE means "Blocked during these times".
            // If inside the schedule, block. If outside, allow.
            if IsBlockedNow(schedules, now) {
                state.BlockMACs = append(state.BlockMACs, dev.MAC)
            } else {
                state.OverrideMACs = append(state.OverrideMACs, dev.MAC)
            }
        }
    }

    return state, nil
}
