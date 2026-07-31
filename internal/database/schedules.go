package database

import (
    "fmt"
    "time"
)

// GetSchedulesByPolicy retrieves all schedule ranges for a given policy ID.
func (d *DB) GetSchedulesByPolicy(policyID int64) ([]Schedule, error) {
    rows, err := d.db.Query(`
        SELECT id, policy_id, day_of_week, start_time, end_time, enabled, created_at, updated_at
        FROM schedules WHERE policy_id = ? ORDER BY day_of_week ASC, start_time ASC
    `, policyID)
    if err != nil {
        return nil, fmt.Errorf("get schedules for policy %d: %w", policyID, err)
    }
    defer rows.Close()

    var schedules []Schedule
    for rows.Next() {
        var s Schedule
        var enabledInt int
        if err := rows.Scan(&s.ID, &s.PolicyID, &s.DayOfWeek, &s.StartTime, &s.EndTime, &enabledInt, &s.CreatedAt, &s.UpdatedAt); err != nil {
            return nil, fmt.Errorf("scan schedule: %w", err)
        }
        s.Enabled = enabledInt == 1
        schedules = append(schedules, s)
    }
    return schedules, nil
}

// AddSchedule inserts a new schedule range for a policy.
func (d *DB) AddSchedule(policyID int64, dayOfWeek int, startTime, endTime string, enabled bool) (int64, error) {
    if dayOfWeek < 0 || dayOfWeek > 6 {
        return 0, fmt.Errorf("invalid day of week: %d", dayOfWeek)
    }

    now := time.Now().Unix()
    enabledInt := boolToInt(enabled)

    res, err := d.db.Exec(`
        INSERT INTO schedules (policy_id, day_of_week, start_time, end_time, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, policyID, dayOfWeek, startTime, endTime, enabledInt, now, now)
    if err != nil {
        return 0, fmt.Errorf("add schedule: %w", err)
    }

    id, err := res.LastInsertId()
    if err != nil {
        return 0, fmt.Errorf("get schedule insert id: %w", err)
    }
    return id, nil
}

// UpdateSchedule modifies an existing schedule range.
func (d *DB) UpdateSchedule(id int64, dayOfWeek int, startTime, endTime string, enabled bool) error {
    if dayOfWeek < 0 || dayOfWeek > 6 {
        return fmt.Errorf("invalid day of week: %d", dayOfWeek)
    }

    now := time.Now().Unix()
    enabledInt := boolToInt(enabled)

    _, err := d.db.Exec(`
        UPDATE schedules SET 
            day_of_week = ?, 
            start_time = ?, 
            end_time = ?, 
            enabled = ?, 
            updated_at = ? 
        WHERE id = ?
    `, dayOfWeek, startTime, endTime, enabledInt, now, id)
    if err != nil {
        return fmt.Errorf("update schedule %d: %w", id, err)
    }
    return nil
}

// DeleteSchedule removes a specific schedule range by its ID.
func (d *DB) DeleteSchedule(id int64) error {
    _, err := d.db.Exec(`DELETE FROM schedules WHERE id = ?`, id)
    if err != nil {
        return fmt.Errorf("delete schedule %d: %w", id, err)
    }
    return nil
}

// DeleteSchedulesByPolicy removes all schedule ranges for a given policy.
func (d *DB) DeleteSchedulesByPolicy(policyID int64) error {
    _, err := d.db.Exec(`DELETE FROM schedules WHERE policy_id = ?`, policyID)
    if err != nil {
        return fmt.Errorf("delete schedules for policy %d: %w", policyID, err)
    }
    return nil
}
