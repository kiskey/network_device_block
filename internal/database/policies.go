package database

import (
    "database/sql"
    "fmt"
    "time"
)

// GetGlobalPolicy retrieves the single global policy (where mac IS NULL).
func (d *DB) GetGlobalPolicy() (*Policy, error) {
    row := d.db.QueryRow(`
        SELECT id, COALESCE(mac, ''), mode, enabled, created_at, updated_at
        FROM policies WHERE mac IS NULL
    `)
    
    var p Policy
    var enabledInt int
    err := row.Scan(&p.ID, &p.MAC, &p.Mode, &enabledInt, &p.CreatedAt, &p.UpdatedAt)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("global policy not found (database not seeded?)")
        }
        return nil, fmt.Errorf("get global policy: %w", err)
    }
    p.Enabled = enabledInt == 1
    return &p, nil
}

// GetDevicePolicy retrieves a specific device override policy.
func (d *DB) GetDevicePolicy(mac string) (*Policy, error) {
    mac = NormalizeMAC(mac)
    row := d.db.QueryRow(`
        SELECT id, COALESCE(mac, ''), mode, enabled, created_at, updated_at
        FROM policies WHERE mac = ?
    `, mac)

    var p Policy
    var enabledInt int
    err := row.Scan(&p.ID, &p.MAC, &p.Mode, &enabledInt, &p.CreatedAt, &p.UpdatedAt)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil // No override exists, inherits global
        }
        return nil, fmt.Errorf("get device policy %s: %w", mac, err)
    }
    p.Enabled = enabledInt == 1
    return &p, nil
}

// GetEffectivePolicy resolves the actual policy mode for a device.
// If the device has an override policy that is enabled and not set to GLOBAL,
// that mode is used. Otherwise, the global policy's mode is used.
func (d *DB) GetEffectivePolicy(mac string) (*Policy, error) {
    mac = NormalizeMAC(mac)
    
    devPolicy, err := d.GetDevicePolicy(mac)
    if err != nil {
        return nil, err
    }

    // Use device override if it exists, is enabled, and is explicitly set to a mode
    if devPolicy != nil && devPolicy.Enabled && devPolicy.Mode != ModeGlobal {
        return devPolicy, nil
    }

    // Otherwise, fall back to the global policy
    return d.GetGlobalPolicy()
}

// SetDevicePolicy creates or updates a device's override policy.
func (d *DB) SetDevicePolicy(mac string, mode string, enabled bool) error {
    mac = NormalizeMAC(mac)
    if mode != ModeAllowAlways && mode != ModeBlockAlways && mode != ModeSchedule && mode != ModeGlobal {
        return fmt.Errorf("invalid policy mode: %s", mode)
    }

    now := time.Now().Unix()
    enabledInt := boolToInt(enabled)

    _, err := d.db.Exec(`
        INSERT INTO policies (mac, mode, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            mode = excluded.mode,
            enabled = excluded.enabled,
            updated_at = excluded.updated_at
    `, mac, mode, enabledInt, now, now)
    if err != nil {
        return fmt.Errorf("set device policy %s: %w", mac, err)
    }
    return nil
}

// SetGlobalPolicy updates the global policy mode and enabled status.
func (d *DB) SetGlobalPolicy(mode string, enabled bool) error {
    if mode != ModeAllowAlways && mode != ModeBlockAlways && mode != ModeSchedule {
        return fmt.Errorf("invalid global policy mode: %s", mode)
    }

    now := time.Now().Unix()
    enabledInt := boolToInt(enabled)

    _, err := d.db.Exec(`
        UPDATE policies SET mode = ?, enabled = ?, updated_at = ? WHERE mac IS NULL
    `, mode, enabledInt, now)
    if err != nil {
        return fmt.Errorf("set global policy: %w", err)
    }
    return nil
}

// GetAllPolicies retrieves all policies (global + device overrides).
func (d *DB) GetAllPolicies() ([]Policy, error) {
    rows, err := d.db.Query(`
        SELECT id, COALESCE(mac, ''), mode, enabled, created_at, updated_at
        FROM policies ORDER BY (mac IS NULL) DESC, mac ASC
    `)
    if err != nil {
        return nil, fmt.Errorf("get all policies: %w", err)
    }
    defer rows.Close()

    var policies []Policy
    for rows.Next() {
        var p Policy
        var enabledInt int
        if err := rows.Scan(&p.ID, &p.MAC, &p.Mode, &enabledInt, &p.CreatedAt, &p.UpdatedAt); err != nil {
            return nil, fmt.Errorf("scan policy: %w", err)
        }
        p.Enabled = enabledInt == 1
        policies = append(policies, p)
    }
    return policies, nil
}

// DeleteDevicePolicy removes a device's override policy, causing it to inherit
// the global policy.
func (d *DB) DeleteDevicePolicy(mac string) error {
    mac = NormalizeMAC(mac)
    _, err := d.db.Exec(`DELETE FROM policies WHERE mac = ?`, mac)
    if err != nil {
        return fmt.Errorf("delete device policy %s: %w", mac, err)
    }
    return nil
}
