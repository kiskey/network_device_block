package api

import (
    "net/http"
    "time"

    "lias/internal/database"
)

// DashboardData represents the payload sent to the UI dashboard.
type DashboardData struct {
    GatewayStatus   string               `json:"gateway_status"`
    InternetStatus  string               `json:"internet_status"`
    VPNStatus       string               `json:"vpn_status"`
    OnlineDevices   int                  `json:"online_devices"`
    BlockedDevices  int                  `json:"blocked_devices"`
    NextSchedule    *database.Schedule   `json:"next_schedule"`
    DeviceCount     int                  `json:"device_count"`
}

// handleGetDashboard processes GET /api/dashboard
func (s *Server) handleGetDashboard(w http.ResponseWriter, r *http.Request) {
    data := DashboardData{
        GatewayStatus:  "Online",  // App is running on the gateway
        InternetStatus: "Connected", // Assume connected if VPN is up
        VPNStatus:      "Connected", // TODO: Could ping a VPN interface IP for real status
    }

    // Get device counts
    devices, err := s.db.GetAllDevices()
    if err == nil {
        data.DeviceCount = len(devices)
        for _, d := range devices {
            if d.Online {
                data.OnlineDevices++
            }
        }
    }

    // Get blocked count from live nftables set
    blockedMacs, err := s.fw.GetBlockedMACs()
    if err == nil {
        data.BlockedDevices = len(blockedMacs)
    }

    // Find next schedule event
    // Iterates all policies, checks their schedules, and finds the closest upcoming time.
    data.NextSchedule = s.findNextScheduleEvent(devices)

    writeJSON(w, http.StatusOK, data)
}

// findNextScheduleEvent scans all schedules and returns the next one that will trigger.
func (s *Server) findNextScheduleEvent(devices []database.Device) *database.Schedule {
    now := time.Now()
    var nextSched *database.Schedule
    var nextTime time.Time

    policies, err := s.db.GetAllPolicies()
    if err != nil {
        return nil
    }

    for _, p := range policies {
        if !p.Enabled || p.Mode != database.ModeSchedule {
            continue
        }
        schedules, err := s.db.GetSchedulesByPolicy(p.ID)
        if err != nil {
            continue
        }

        for _, sched := range schedules {
            if !sched.Enabled {
                continue
            }
            // Calculate the next occurrence of this schedule
            t := nextOccurrence(sched, now)
            if nextTime.IsZero() || t.Before(nextTime) {
                nextTime = t
                sCopy := sched
                nextSched = &sCopy
            }
        }
    }

    return nextSched
}

// nextOccurrence calculates the next time a schedule will start.
// Note: This is a simplified implementation that finds the next start time.
func nextOccurrence(s database.Schedule, now time.Time) time.Time {
    // Parse start time
    var h, m int
    _, err := fmt.Sscanf(s.StartTime, "%d:%d", &h, &m)
    if err != nil {
        return now.AddDate(1, 0, 0) // far future
    }

    // Find the next date that matches DayOfWeek
    currentDay := int(now.Weekday())
    daysUntil := (s.DayOfWeek - currentDay + 7) % 7
    
    nextDate := now.AddDate(0, 0, daysUntil)
    nextTime := time.Date(nextDate.Year(), nextDate.Month(), nextDate.Day(), h, m, 0, 0, nextDate.Location())

    // If it's today but already past, push to next week
    if nextTime.Before(now) {
        nextTime = nextTime.AddDate(0, 0, 7)
    }

    return nextTime
}

// unused import prevention
import (
    "fmt"
)
