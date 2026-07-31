package database

import (
    "fmt"
)

// InsertLog creates a new audit log entry.
func (d *DB) InsertLog(category, message, mac, details string) error {
    now := time.Now().Unix()
    
    // Normalize MAC if provided, but allow empty string
    if mac != "" {
        mac = NormalizeMAC(mac)
    }

    _, err := d.db.Exec(`
        INSERT INTO logs (timestamp, category, message, mac, details)
        VALUES (?, ?, ?, ?, ?)
    `, now, category, message, mac, details)
    if err != nil {
        return fmt.Errorf("insert log: %w", err)
    }
    return nil
}

// GetLogs retrieves recent log entries, optionally filtered by MAC address.
// Pass limit=0 for default (100), mac="" for all devices.
func (d *DB) GetLogs(limit int, mac string) ([]LogEntry, error) {
    if limit <= 0 {
        limit = 100
    }

    var rows *sql.Rows
    var err error

    if mac != "" {
        mac = NormalizeMAC(mac)
        rows, err = d.db.Query(`
            SELECT id, timestamp, category, message, COALESCE(mac, ''), COALESCE(details, '')
            FROM logs WHERE mac = ?
            ORDER BY timestamp DESC
            LIMIT ?
        `, mac, limit)
    } else {
        rows, err = d.db.Query(`
            SELECT id, timestamp, category, message, COALESCE(mac, ''), COALESCE(details, '')
            FROM logs
            ORDER BY timestamp DESC
            LIMIT ?
        `, limit)
    }

    if err != nil {
        return nil, fmt.Errorf("get logs: %w", err)
    }
    defer rows.Close()

    var logs []LogEntry
    for rows.Next() {
        var l LogEntry
        if err := rows.Scan(&l.ID, &l.Timestamp, &l.Category, &l.Message, &l.MAC, &l.Details); err != nil {
            return nil, fmt.Errorf("scan log: %w", err)
        }
        logs = append(logs, l)
    }
    return logs, nil
}

// DeleteLogsBefore deletes logs older than the given Unix timestamp and
// returns the number of deleted rows.
func (d *DB) DeleteLogsBefore(cutoff int64) (int64, error) {
    res, err := d.db.Exec(`DELETE FROM logs WHERE timestamp < ?`, cutoff)
    if err != nil {
        return 0, fmt.Errorf("delete logs before %d: %w", cutoff, err)
    }
    count, _ := res.RowsAffected()
    return count, nil
}
