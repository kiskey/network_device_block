package database

import (
    "database/sql"
    "fmt"
    "time"
)

// DeviceObservation is used by the discovery merge engine to update a device.
type DeviceObservation struct {
    MAC              string
    Hostname         string
    Vendor           string
    Manufacturer     string
    CurrentIP        string
    DeviceType       string
    OS               string
    Services         string
    DiscoverySources string
    Confidence       int
}

// UpsertDevice inserts or updates a device record based on MAC address.
// v3.2.0: Fixed logic to prevent overwriting known intelligence with empty/generic data.
func (d *DB) UpsertDevice(obs DeviceObservation) error {
    mac := NormalizeMAC(obs.MAC)
    if mac == "" {
        return fmt.Errorf("cannot upsert device with empty MAC")
    }

    now := time.Now().Unix()

    _, err := d.db.Exec(`
        INSERT INTO devices (
            mac, hostname, friendly_name, vendor, current_ip, online, paused, 
            first_seen, last_seen, device_type, manufacturer, os, services, 
            discovery_sources, confidence
        ) 
        VALUES (?, ?, '', ?, ?, 1, 0, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            current_ip = CASE WHEN excluded.current_ip != '' THEN excluded.current_ip ELSE devices.current_ip END,
            online = 1,
            last_seen = excluded.last_seen,
            hostname = CASE 
                WHEN excluded.hostname != '' AND excluded.hostname != 'Unknown Device' AND excluded.confidence >= devices.confidence THEN excluded.hostname 
                ELSE devices.hostname 
            END,
            vendor = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE devices.vendor END,
            device_type = CASE 
                WHEN excluded.device_type != '' AND excluded.device_type != 'Generic' THEN excluded.device_type 
                ELSE devices.device_type 
            END,
            manufacturer = CASE WHEN excluded.manufacturer != '' THEN excluded.manufacturer ELSE devices.manufacturer END,
            os = CASE WHEN excluded.os != '' THEN excluded.os ELSE devices.os END,
            services = CASE WHEN excluded.services != '' THEN excluded.services ELSE devices.services END,
            discovery_sources = excluded.discovery_sources,
            confidence = CASE WHEN excluded.confidence > devices.confidence THEN excluded.confidence ELSE devices.confidence END
    `, mac, obs.Hostname, obs.Vendor, obs.CurrentIP, now, now, 
       obs.DeviceType, obs.Manufacturer, obs.OS, obs.Services, 
       obs.DiscoverySources, obs.Confidence)
    
    if err != nil {
        return fmt.Errorf("upsert device %s: %w", mac, err)
    }
    return nil
}

// GetDevice retrieves a single device by MAC address.
func (d *DB) GetDevice(mac string) (*Device, error) {
    mac = NormalizeMAC(mac)
    row := d.db.QueryRow(`
        SELECT mac, hostname, friendly_name, vendor, current_ip, online, paused, first_seen, last_seen,
               device_type, manufacturer, os, services, discovery_sources, confidence
        FROM devices WHERE mac = ?
    `, mac)

    var dev Device
    var onlineInt, pausedInt int
    err := row.Scan(
        &dev.MAC, &dev.Hostname, &dev.FriendlyName, &dev.Vendor, &dev.CurrentIP, &onlineInt, &pausedInt, &dev.FirstSeen, &dev.LastSeen,
        &dev.DeviceType, &dev.Manufacturer, &dev.OS, &dev.Services, &dev.DiscoverySources, &dev.Confidence,
    )
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, fmt.Errorf("get device %s: %w", mac, err)
    }
    dev.Online = onlineInt == 1
    dev.Paused = pausedInt == 1
    return &dev, nil
}

// GetAllDevices returns all known devices ordered by most recently seen.
func (d *DB) GetAllDevices() ([]Device, error) {
    rows, err := d.db.Query(`
        SELECT mac, hostname, friendly_name, vendor, current_ip, online, paused, first_seen, last_seen,
               device_type, manufacturer, os, services, discovery_sources, confidence
        FROM devices ORDER BY online DESC, last_seen DESC
    `)
    if err != nil {
        return nil, fmt.Errorf("get all devices: %w", err)
    }
    defer rows.Close()

    devices := make([]Device, 0)
    for rows.Next() {
        var dev Device
        var onlineInt, pausedInt int
        if err := rows.Scan(
            &dev.MAC, &dev.Hostname, &dev.FriendlyName, &dev.Vendor, &dev.CurrentIP, &onlineInt, &pausedInt, &dev.FirstSeen, &dev.LastSeen,
            &dev.DeviceType, &dev.Manufacturer, &dev.OS, &dev.Services, &dev.DiscoverySources, &dev.Confidence,
        ); err != nil {
            return nil, fmt.Errorf("scan device: %w", err)
        }
        dev.Online = onlineInt == 1
        dev.Paused = pausedInt == 1
        devices = append(devices, dev)
    }
    return devices, nil
}

// SetDeviceFriendlyName updates the custom friendly name.
func (d *DB) SetDeviceFriendlyName(mac, name string) error {
    mac = NormalizeMAC(mac)
    _, err := d.db.Exec(`UPDATE devices SET friendly_name = ? WHERE mac = ?`, name, mac)
    return err
}

// SetDevicePaused updates the temporary pause state.
func (d *DB) SetDevicePaused(mac string, paused bool) error {
    mac = NormalizeMAC(mac)
    pausedInt := boolToInt(paused)
    _, err := d.db.Exec(`UPDATE devices SET paused = ? WHERE mac = ?`, pausedInt, mac)
    return err
}

// DeleteDevice removes a device and its associated policy.
func (d *DB) DeleteDevice(mac string) error {
    mac = NormalizeMAC(mac)
    tx, err := d.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()

    if _, err := tx.Exec(`DELETE FROM devices WHERE mac = ?`, mac); err != nil {
        return err
    }
    if _, err := tx.Exec(`DELETE FROM policies WHERE mac = ?`, mac); err != nil {
        return err
    }
    return tx.Commit()
}

// MarkStaleDevicesOffline marks devices as offline.
func (d *DB) MarkStaleDevicesOffline(threshold int64) (int64, error) {
    res, err := d.db.Exec(`UPDATE devices SET online = 0 WHERE online = 1 AND last_seen < ?`, threshold)
    if err != nil {
        return 0, err
    }
    count, _ := res.RowsAffected()
    return count, nil
}
