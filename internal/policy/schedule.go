package policy

import (
    "fmt"
    "time"

    "lias/internal/database"
)

// IsBlockedNow checks if the given time falls within any schedule range.
// Used for SCHEDULE_BLOCK (Downtime) mode.
func IsBlockedNow(schedules []database.Schedule, now time.Time) bool {
    currentDay := int(now.Weekday())
    currentMinutes := now.Hour()*60 + now.Minute()

    for _, s := range schedules {
        if !s.Enabled || s.DayOfWeek != currentDay {
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
            if currentMinutes >= startMin && currentMinutes < endMin {
                return true
            }
        } else {
            // Cross-midnight
            if currentMinutes >= startMin || currentMinutes < endMin {
                return true
            }
        }
    }
    return false
}

// IsAllowedNow checks if the given time falls within any schedule range.
// Used for SCHEDULE_ALLOW (Whitelist) mode.
func IsAllowedNow(schedules []database.Schedule, now time.Time) bool {
    return IsBlockedNow(schedules, now) // Logic is identical: if inside the range, it's allowed.
}

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
