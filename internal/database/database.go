// Package database provides the SQLite persistence layer.
// v4.0.0: Adds migration for is_infrastructure column.
package database

import (
    "database/sql"
    "fmt"
    "strings"
    "time"

    _ "modernc.org/sqlite"
)

type Logger interface {
    Infof(format string, args ...interface{})
    Errorf(format string, args ...interface{})
    Warnf(format string, args ...interface{})
    Debugf(format string, args ...interface{})
}

const (
    ModeGlobal        = "GLOBAL"
    ModeAllowAlways   = "ALLOW_ALWAYS"
    ModeBlockAlways   = "BLOCK_ALWAYS"
    ModeScheduleBlock = "SCHEDULE_BLOCK"
    ModeScheduleAllow = "SCHEDULE_ALLOW"
)

const (
    LogCategoryScheduleApplied  = "schedule_applied"
    LogCategoryScheduleRemoved  = "schedule_removed"
    LogCategoryManualToggle     = "manual_toggle"
    LogCategoryDeviceDiscovered = "device_discovered"
    LogCategoryHostnameChanged  = "hostname_changed"
    LogCategoryPolicyChanged    = "policy_changed"
    LogCategoryFirewallSync     = "firewall_sync"
    LogCategoryAuth             = "auth"
)

type DB struct {
    db     *sql.DB
    logger Logger
}

func New(path string, logger Logger) (*DB, error) {
    dsn := fmt.Sprintf(
        "file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)",
        path,
    )

    db, err := sql.Open("sqlite", dsn)
    if err != nil {
        return nil, fmt.Errorf("open database: %w", err)
    }

    db.SetMaxOpenConns(1)
    db.SetMaxIdleConns(1)
    db.SetConnMaxIdleTime(0)
    db.SetConnMaxLifetime(0)

    d := &DB{db: db, logger: logger}

    if err := d.migrate(); err != nil {
        _ = db.Close()
        return nil, fmt.Errorf("database migration: %w", err)
    }

    if err := d.seedDefaults(); err != nil {
        _ = db.Close()
        return nil, fmt.Errorf("seed defaults: %w", err)
    }

    return d, nil
}

func (d *DB) Close() error { return d.db.Close() }
func (d *DB) SQL() *sql.DB { return d.db }
func (d *DB) Logger() Logger { return d.logger }

func (d *DB) migrate() error {
    statements := []string{
        `CREATE TABLE IF NOT EXISTS devices (
            mac           TEXT    PRIMARY KEY,
            hostname      TEXT    NOT NULL DEFAULT '',
            friendly_name TEXT    NOT NULL DEFAULT '',
            vendor        TEXT    NOT NULL DEFAULT '',
            current_ip    TEXT    NOT NULL DEFAULT '',
            online        INTEGER NOT NULL DEFAULT 0,
            paused        INTEGER NOT NULL DEFAULT 0,
            first_seen    INTEGER NOT NULL,
            last_seen     INTEGER NOT NULL
        );`,

        `CREATE TABLE IF NOT EXISTS policies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac        TEXT    UNIQUE,
            mode       TEXT    NOT NULL DEFAULT 'ALLOW_ALWAYS',
            enabled    INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );`,

        `CREATE TABLE IF NOT EXISTS schedules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id   INTEGER NOT NULL,
            day_of_week INTEGER NOT NULL CHECK(day_of_week BETWEEN 0 AND 6),
            start_time  TEXT    NOT NULL,
            end_time    TEXT    NOT NULL,
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
        );`,

        `CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            category  TEXT    NOT NULL,
            message   TEXT    NOT NULL,
            mac       TEXT,
            details   TEXT
        );`,

        `CREATE TABLE IF NOT EXISTS settings (
            key        TEXT    PRIMARY KEY,
            value      TEXT    NOT NULL,
            updated_at INTEGER NOT NULL
        );`,

        // Indexes
        `CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);`,
        `CREATE INDEX IF NOT EXISTS idx_logs_mac       ON logs(mac);`,
        `CREATE INDEX IF NOT EXISTS idx_logs_category  ON logs(category);`,
        `CREATE INDEX IF NOT EXISTS idx_schedules_pid  ON schedules(policy_id);`,
        `CREATE INDEX IF NOT EXISTS idx_schedules_dow  ON schedules(day_of_week);`,
        `CREATE INDEX IF NOT EXISTS idx_devices_online ON devices(online);`,
        `CREATE INDEX IF NOT EXISTS idx_devices_last   ON devices(last_seen);`,

        // v3.0.0: Migrations for device intelligence fields
        `ALTER TABLE devices ADD COLUMN device_type TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE devices ADD COLUMN manufacturer TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE devices ADD COLUMN os TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE devices ADD COLUMN services TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE devices ADD COLUMN discovery_sources TEXT NOT NULL DEFAULT '';`,
        `ALTER TABLE devices ADD COLUMN confidence INTEGER NOT NULL DEFAULT 0;`,

        // v4.0.0: Migration for Infrastructure flag
        `ALTER TABLE devices ADD COLUMN is_infrastructure INTEGER NOT NULL DEFAULT 0;`,
    }

    for _, stmt := range statements {
        if _, err := d.db.Exec(stmt); err != nil {
            if !strings.Contains(err.Error(), "duplicate column name") {
                return fmt.Errorf("exec [%s]: %w", firstLine(stmt), err)
            }
        }
    }
    return nil
}

func (d *DB) seedDefaults() error {
    now := time.Now().Unix()

    _, err := d.db.Exec(
        `INSERT OR IGNORE INTO policies (mac, mode, enabled, created_at, updated_at)
         VALUES (NULL, ?, 0, ?, ?)`,
        ModeAllowAlways, now, now,
    )
    if err != nil {
        return fmt.Errorf("seed global policy: %w", err)
    }

    defaults := map[string]string{
        "auth_password_hash": "",
        "auth_enabled":       "true",
        "session_secret":     "",
        "https_enabled":      "false",
        "https_cert":         "",
        "https_key":          "",
        "listen_addr":        "0.0.0.0:8443",
        "discovery_interval": "30",
        "schedule_interval":  "60",
        "offline_threshold":  "90",
        "log_retention_days": "30",
        "dashboard_name":     "LAN Access Scheduler",
        "nmap_enabled":       "true",
        "nmap_interval":      "600",
        "nmap_subnet":        "192.168.1.0/24",
    }

    for k, v := range defaults {
        _, err := d.db.Exec(
            `INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)`,
            k, v, now,
        )
        if err != nil {
            return fmt.Errorf("seed setting %q: %w", k, err)
        }
    }
    return nil
}

func NormalizeMAC(mac string) string {
    mac = strings.TrimSpace(strings.ToLower(mac))
    mac = strings.ReplaceAll(mac, "-", ":")
    return mac
}

func firstLine(s string) string {
    s = strings.TrimSpace(s)
    if idx := strings.IndexByte(s, '\n'); idx >= 0 {
        s = s[:idx]
    }
    if len(s) > 80 {
        s = s[:80] + "..."
    }
    return s
}
