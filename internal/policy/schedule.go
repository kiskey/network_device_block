package policy

import (
    "fmt"
    "time"

    "lias/internal/database"
)

// IsBlockedNow checks if the given time falls within any of the provided
// schedule ranges. It supports multiple ranges per day and cross-midnight
// ranges (where EndTime < StartTime).
func IsBlockedNow(schedules []database.Schedule, now time.Time) bool {
    currentDay := int(now.Weekday()) // 0=Sunday ... 6=Saturday
    currentMinutes := now.Hour()*60 + now.Minute()

    for _, s := range schedules {
        if !s.Enabled {
            continue
        }
        if s.DayOfWeek != currentDay {
            continue
        }

        startMin, err := parseTimeToMinutes(s.StartTime)
        if err != nil {
            continue
        }
        endMin, err := parseTimeToMinutes(s.EndTime)
        if err != nil {
            continue
        }

        if startMin <= endMin {
            // Normal range (e.g., 09:00 to 17:00)
            if currentMinutes >= startMin && currentMinutes < endMin {
                return true
            }
        } else {
            // Cross-midnight range (e.g., 22:00 to 02:00)
            // Current time is blocked if it's >= start OR < end
            if currentMinutes >= startMin || currentMinutes < endMin {
                return true
            }
        }
    }
    return false
}

// parseTimeToMinutes converts "HH:MM" to minutes since midnight.
func parseTimeToMinutes(t string) (int, error) {
    var h, m int
    _, err := fmt.Sscanf(t, "%d:%d", &h, &m)
    if err != nil {
        return 0, fmt.Errorf("invalid time format %s: %w", t, err)
    }
    if h < 0 || h > 23 || m < 0 || m > 59 {
        return 0, fmt.Errorf("time out of bounds %s", t)
    }
    return h*60 + m, nil
}
