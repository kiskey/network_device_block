package database

import (
    "database/sql"
    "fmt"
    "time"
)

// GetSetting retrieves a single setting value by its key.
// Returns empty string and nil error if the key does not exist.
func (d *DB) GetSetting(key string) (string, error) {
    var value string
    err := d.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
    if err != nil {
        if err == sql.ErrNoRows {
            return "", nil
        }
        return "", fmt.Errorf("get setting %s: %w", key, err)
    }
    return value, nil
}

// SetSetting inserts or updates a setting value.
func (d *DB) SetSetting(key, value string) error {
    now := time.Now().Unix()
    _, err := d.db.Exec(`
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
    `, key, value, now)
    if err != nil {
        return fmt.Errorf("set setting %s: %w", key, err)
    }
    return nil
}

// GetAllSettings retrieves all key-value pairs from the settings table.
func (d *DB) GetAllSettings() ([]Setting, error) {
    rows, err := d.db.Query(`SELECT key, value, updated_at FROM settings ORDER BY key ASC`)
    if err != nil {
        return nil, fmt.Errorf("get all settings: %w", err)
    }
    defer rows.Close()

    var settings []Setting
    for rows.Next() {
        var s Setting
        if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedAt); err != nil {
            return nil, fmt.Errorf("scan setting: %w", err)
        }
        settings = append(settings, s)
    }
    return settings, nil
}

// GetBoolSetting fetches a boolean setting. Returns fallback if not found or invalid.
func (d *DB) GetBoolSetting(key string, fallback bool) bool {
    val, err := d.GetSetting(key)
    if err != nil || val == "" {
        return fallback
    }
    return val == "true" || val == "1"
}

// GetIntSetting fetches an integer setting. Returns fallback if not found or invalid.
func (d *DB) GetIntSetting(key string, fallback int) int {
    val, err := d.GetSetting(key)
    if err != nil || val == "" {
        return fallback
    }
    var i int
    _, err = fmt.Sscanf(val, "%d", &i)
    if err != nil {
        return fallback
    }
    return i
}
