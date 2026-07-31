package api

import (
    "fmt"
    "net/http"
    "time"

    "lias/internal/database"
)

// DashboardData represents the payload sent to the UI dashboard.
type DashboardData struct {
    GatewayStatus      string             `json:"gateway_status"`
    InternetStatus     string             `json:"internet_status"`
    VPNStatus          string             `json:"vpn_status"`
    OnlineDevices      int                `json:"online_devices"`
    BlockedDevices     int                `json:"blocked_devices"`
    NextSchedule       *database.Schedule `json:"next_schedule"`
    NextScheduleDevice string             `json:"next_schedule_device"`
    DeviceCount        int                `json:"device_count"`
}

// handleGetDashboard processes GET /api/dashboard
func (s *Server) handleGetDashboard(w http.ResponseWriter, r *http.Request) {
    data := DashboardData{
        GatewayStatus:  "Online",
        InternetStatus: "Connected",
        VPNStatus:      "Connected",
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
    data.NextSchedule, data.NextScheduleDevice = s.findNextScheduleEvent(devices)

    writeJSON(w, http.StatusOK, data)
}

// findNextScheduleEvent scans all schedules and returns the next one that will trigger.
func (s *Server) findNextScheduleEvent(devices []database.Device) (*database.Schedule, string) {
    now := time.Now()
    var nextSched *database.Schedule
    var nextTime time.Time
    var deviceName string

    policies, err := s.db.GetAllPolicies()
    if err != nil {
        return nil, ""
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
            
            t := nextOccurrence(sched, now)
            if nextTime.IsZero() || t.Before(nextTime) {
                nextTime = t
                sCopy := sched
                nextSched = &sCopy
                
                // Resolve device name
                if p.MAC == "" {
                    deviceName = "All Devices (Global)"
                } else {
                    deviceName = "Unknown Device"
                    for _, dev := range devices {
                        if dev.MAC == p.MAC {
                            if dev.FriendlyName != "" {
                                deviceName = dev.FriendlyName
                            } else if dev.Hostname != "" {
                                deviceName = dev.Hostname
                            } else {
                                deviceName = dev.MAC
                            }
                            break
                        }
                    }
                }
            }
        }
    }

    return nextSched, deviceName
}

// nextOccurrence calculates the next time a schedule will start.
func nextOccurrence(s database.Schedule, now time.Time) time.Time {
    var h, m int
    _, err := fmt.Sscanf(s.StartTime, "%d:%d", &h, &m)
    if err != nil {
        return now.AddDate(1, 0, 0) // far future
    }

    currentDay := int(now.Weekday())
    daysUntil := (s.DayOfWeek - currentDay + 7) % 7
    
    nextDate := now.AddDate(0, 0, daysUntil)
    nextTime := time.Date(nextDate.Year(), nextDate.Month(), nextDate.Day(), h, m, 0, 0, nextDate.Location())

    if nextTime.Before(now) {
        nextTime = nextTime.AddDate(0, 0, 7)
    }

    return nextTime
}
