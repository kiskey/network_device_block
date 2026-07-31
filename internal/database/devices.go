package database

import (
    "database/sql"
    "fmt"
    "time"
)

// UpsertDevice inserts or updates a device record based on MAC address.
// FIX: Always update hostname and vendor to the latest discovered values,
// so we don't get stuck with "Unknown Device" forever.
func (d *DB) UpsertDevice(mac, hostname, vendor, ip string, online bool) error {
    mac = NormalizeMAC(mac)
    if mac == "" {
        return fmt.Errorf("cannot upsert device with empty MAC")
    }

    now := time.Now().Unix()
    onlineInt := boolToInt(online)

    _, err := d.db.Exec(`
        INSERT INTO devices (mac, hostname, friendly_name, vendor, current_ip, online, first_seen, last_seen)
        VALUES (?, ?, '', ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            current_ip = excluded.current_ip,
            online = excluded.online,
            last_seen = excluded.last_seen,
            hostname = excluded.hostname,
            vendor = excluded.vendor
    `, mac, hostname, vendor, ip, onlineInt, now, now)
    if err != nil {
        return fmt.Errorf("upsert device %s: %w", mac, err)
    }
    return nil
}

// GetDevice retrieves a single device by MAC address.
func (d *DB) GetDevice(mac string) (*Device, error) {
    mac = NormalizeMAC(mac)
    row := d.db.QueryRow(`
        SELECT mac, hostname, friendly_name, vendor, current_ip, online, first_seen, last_seen
        FROM devices WHERE mac = ?
    `, mac)

    var dev Device
    var onlineInt int
    err := row.Scan(&dev.MAC, &dev.Hostname, &dev.FriendlyName, &dev.Vendor, &dev.CurrentIP, &onlineInt, &dev.FirstSeen, &dev.LastSeen)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, fmt.Errorf("get device %s: %w", mac, err)
    }
    dev.Online = onlineInt == 1
    return &dev, nil
}

// GetAllDevices returns all known devices ordered by most recently seen.
// FIX: Initialize slice with make() so JSON returns [] instead of null.
func (d *DB) GetAllDevices() ([]Device, error) {
    rows, err := d.db.Query(`
        SELECT mac, hostname, friendly_name, vendor, current_ip, online, first_seen, last_seen
        FROM devices ORDER BY online DESC, last_seen DESC
    `)
    if err != nil {
        return nil, fmt.Errorf("get all devices: %w", err)
    }
    defer rows.Close()

    devices := make([]Device, 0)
    for rows.Next() {
        var dev Device
        var onlineInt int
        if err := rows.Scan(&dev.MAC, &dev.Hostname, &dev.FriendlyName, &dev.Vendor, &dev.CurrentIP, &onlineInt, &dev.FirstSeen, &dev.LastSeen); err != nil {
            return nil, fmt.Errorf("scan device: %w", err)
        }
        dev.Online = onlineInt == 1
        devices = append(devices, dev)
    }
    return devices, nil
}

// SetDeviceFriendlyName updates the custom friendly name for a device.
func (d *DB) SetDeviceFriendlyName(mac, name string) error {
    mac = NormalizeMAC(mac)
    _, err := d.db.Exec(`UPDATE devices SET friendly_name = ? WHERE mac = ?`, name, mac)
    if err != nil {
        return fmt.Errorf("set friendly name %s: %w", mac, err)
    }
    return nil
}

// DeleteDevice removes a device and its associated policy.
func (d *DB) DeleteDevice(mac string) error {
    mac = NormalizeMAC(mac)
    
    tx, err := d.db.Begin()
    if err != nil {
        return fmt.Errorf("begin tx: %w", err)
    }
    defer tx.Rollback()

    _, err = tx.Exec(`DELETE FROM devices WHERE mac = ?`, mac)
    if err != nil {
        return fmt.Errorf("delete device %s: %w", mac, err)
    }

    _, err = tx.Exec(`DELETE FROM policies WHERE mac = ?`, mac)
    if err != nil {
        return fmt.Errorf("delete device policy %s: %w", mac, err)
    }

    return tx.Commit()
}

// MarkStaleDevicesOffline marks devices as offline if they haven't been seen
// since the given threshold timestamp.
func (d *DB) MarkStaleDevicesOffline(threshold int64) (int64, error) {
    res, err := d.db.Exec(`
        UPDATE devices SET online = 0 
        WHERE online = 1 AND last_seen < ?
    `, threshold)
    if err != nil {
        return 0, fmt.Errorf("mark stale devices offline: %w", err)
    }
    count, _ := res.RowsAffected()
    return count, nil
}
