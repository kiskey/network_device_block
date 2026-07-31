// Package database provides the SQLite persistence layer for the LAN
// Internet Access Scheduler.
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

// Policy modes (v2.0.0)
const (
    ModeGlobal        = "GLOBAL"
    ModeAllowAlways   = "ALLOW_ALWAYS"
    ModeBlockAlways   = "BLOCK_ALWAYS"
    ModeScheduleBlock = "SCHEDULE_BLOCK" // Downtime: Block during schedule
    ModeScheduleAllow = "SCHEDULE_ALLOW" // Whitelist: Allow during schedule
)

// Log categories
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

// DB wraps the SQLite database connection.
type DB struct {
    db     *sql.DB
    logger Logger
}

// New opens (or creates) the SQLite database.
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

// migrate creates or updates the database schema.
func (d *DB) migrate() error {
    statements := []string{
        `CREATE TABLE IF NOT EXISTS devices (
            mac           TEXT    PRIMARY KEY,
            hostname      TEXT    NOT NULL DEFAULT '',
            friendly_name TEXT    NOT NULL DEFAULT '',
            vendor        TEXT    NOT NULL DEFAULT '',
            current_ip    TEXT    NOT NULL DEFAULT '',
            online        INTEGER NOT NULL DEFAULT 0,
            paused        INTEGER NOT NULL DEFAULT 0, -- v2.0.0
            first_seen    INTEGER NOT NULL,
            last_seen     INTEGER NOT NULL
        );`,

        `CREATE TABLE IF NOT EXISTS policies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac        TEXT    UNIQUE,
            mode       TEXT    NOT NULL DEFAULT 'ALLOW_ALWAYS',
            enabled    INTEGER NOT NULL DEFAULT 0, -- v2.0.0: Global defaults to disabled (device rules take priority)
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

        // v2.0.0: Migration for existing databases
        `ALTER TABLE devices ADD COLUMN paused INTEGER NOT NULL DEFAULT 0;`,
    }

    for _, stmt := range statements {
        if _, err := d.db.Exec(stmt); err != nil {
            // Ignore "duplicate column" errors during migration
            if !strings.Contains(err.Error(), "duplicate column name") {
                return fmt.Errorf("exec [%s]: %w", firstLine(stmt), err)
            }
        }
    }
    return nil
}

// seedDefaults inserts default rows if the database is freshly created.
func (d *DB) seedDefaults() error {
    now := time.Now().Unix()

    // v2.0.0: Global policy defaults to ALLOW_ALWAYS but ENABLED=FALSE
    // Meaning devices use their own rules by default.
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

// NormalizeMAC converts a MAC address to lowercase with colon separators.
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
