// Package database provides the SQLite persistence layer for the LAN
// Internet Access Scheduler. It manages five tables: devices, policies,
// schedules, logs, and settings. All time values are stored as Unix
// timestamps (seconds). MAC addresses are stored as lowercase strings
// with colon separators (e.g. "aa:bb:cc:dd:ee:ff").
package database

import (
    "database/sql"
    "fmt"
    "strings"
    "time"

    _ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Logger interface (satisfied by *logging.Logger via duck typing)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Logger is the minimal logging interface required by the database package.
// The concrete *logging.Logger from lias/internal/logging satisfies this
// interface implicitly — no import of the logging package is needed here,
// keeping the dependency graph clean and testable.
type Logger interface {
    Infof(format string, args ...interface{})
    Errorf(format string, args ...interface{})
    Warnf(format string, args ...interface{})
    Debugf(format string, args ...interface{})
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Policy modes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const (
    // ModeGlobal means the device inherits the global policy.
    ModeGlobal = "GLOBAL"
    // ModeAllowAlways means the device is always allowed (added to override_allow set).
    ModeAllowAlways = "ALLOW_ALWAYS"
    // ModeBlockAlways means the device is always blocked (added to blocked_macs set).
    ModeBlockAlways = "BLOCK_ALWAYS"
    // ModeSchedule means the device is allowed during schedule ranges, blocked outside.
    ModeSchedule = "SCHEDULE"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Log categories
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const (
    LogCategoryScheduleApplied   = "schedule_applied"
    LogCategoryScheduleRemoved   = "schedule_removed"
    LogCategoryManualToggle      = "manual_toggle"
    LogCategoryDeviceDiscovered  = "device_discovered"
    LogCategoryHostnameChanged   = "hostname_changed"
    LogCategoryPolicyChanged     = "policy_changed"
    LogCategoryFirewallSync      = "firewall_sync"
    LogCategoryAuth              = "auth"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DB wrapper
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// DB wraps the SQLite database connection and provides access to all
// persistence operations.
type DB struct {
    db     *sql.DB
    logger Logger
}

// New opens (or creates) the SQLite database at the given path, runs
// schema migrations, and seeds default rows. The connection is configured
// for WAL journal mode with foreign keys enabled and a 5-second busy timeout.
func New(path string, logger Logger) (*DB, error) {
    dsn := fmt.Sprintf(
        "file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)",
        path,
    )

    db, err := sql.Open("sqlite", dsn)
    if err != nil {
        return nil, fmt.Errorf("open database: %w", err)
    }

    // SQLite serializes writes internally; a single connection avoids
    // "database is locked" errors under concurrent access.
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

// Close closes the underlying database connection.
func (d *DB) Close() error {
    return d.db.Close()
}

// SQL returns the raw *sql.DB for direct query access (used by packages
// that need custom queries without adding methods here).
func (d *DB) SQL() *sql.DB {
    return d.db
}

// Logger returns the logger associated with this database instance.
func (d *DB) Logger() Logger {
    return d.logger
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Migrations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// migrate creates or updates the database schema to the latest version.
// All statements are idempotent (use IF NOT EXISTS).
func (d *DB) migrate() error {
    statements := []string{
        // ─── devices ───────────────────────────────────────────────
        // MAC address is the primary key. IP is informational only and
        // may change; it is never used for policy decisions.
        `CREATE TABLE IF NOT EXISTS devices (
            mac           TEXT    PRIMARY KEY,
            hostname      TEXT    NOT NULL DEFAULT '',
            friendly_name TEXT    NOT NULL DEFAULT '',
            vendor        TEXT    NOT NULL DEFAULT '',
            current_ip    TEXT    NOT NULL DEFAULT '',
            online        INTEGER NOT NULL DEFAULT 0,
            first_seen    INTEGER NOT NULL,
            last_seen     INTEGER NOT NULL
        );`,

        // ─── policies ──────────────────────────────────────────────
        // mac IS NULL     → the single global policy (enforced by UNIQUE).
        // mac IS NOT NULL → per-device override policy.
        // mode: GLOBAL | ALLOW_ALWAYS | BLOCK_ALWAYS | SCHEDULE
        `CREATE TABLE IF NOT EXISTS policies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac        TEXT    UNIQUE,
            mode       TEXT    NOT NULL DEFAULT 'BLOCK_ALWAYS',
            enabled    INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );`,

        // ─── schedules ─────────────────────────────────────────────
        // Each row is one time range for one day of the week.
        // Multiple ranges per day are supported (multiple rows).
        // Cross-midnight: end_time < start_time (e.g. 22:00 → 02:00).
        // day_of_week: 0=Sunday … 6=Saturday (matches Go time.Weekday).
        `CREATE TABLE IF NOT EXISTS schedules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id   INTEGER NOT NULL,
            day_of_week INTEGER NOT NULL CHECK(day_of_week BETWEEN 0 AND 6),
            start_time  TEXT    NOT NULL,  -- "HH:MM"
            end_time    TEXT    NOT NULL,  -- "HH:MM"
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
        );`,

        // ─── logs ──────────────────────────────────────────────────
        // 30-day retention enforced by runLogRetention() in main.go.
        `CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            category  TEXT    NOT NULL,
            message   TEXT    NOT NULL,
            mac       TEXT,
            details   TEXT
        );`,

        // ─── settings ──────────────────────────────────────────────
        // Key-value store for runtime configuration (password hash,
        // session secret, UI preferences, etc.).
        `CREATE TABLE IF NOT EXISTS settings (
            key        TEXT    PRIMARY KEY,
            value      TEXT    NOT NULL,
            updated_at INTEGER NOT NULL
        );`,

        // ─── indexes ───────────────────────────────────────────────
        `CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);`,
        `CREATE INDEX IF NOT EXISTS idx_logs_mac       ON logs(mac);`,
        `CREATE INDEX IF NOT EXISTS idx_logs_category  ON logs(category);`,
        `CREATE INDEX IF NOT EXISTS idx_schedules_pid  ON schedules(policy_id);`,
        `CREATE INDEX IF NOT EXISTS idx_schedules_dow  ON schedules(day_of_week);`,
        `CREATE INDEX IF NOT EXISTS idx_devices_online ON devices(online);`,
        `CREATE INDEX IF NOT EXISTS idx_devices_last   ON devices(last_seen);`,
    }

    for _, stmt := range statements {
        if _, err := d.db.Exec(stmt); err != nil {
            return fmt.Errorf("exec [%s]: %w", firstLine(stmt), err)
        }
    }

    d.logger.Debugf("Database migrations complete (%d statements)", len(statements))
    return nil
}

// seedDefaults inserts default rows if the database is freshly created.
func (d *DB) seedDefaults() error {
    now := time.Now().Unix()

    // ── Global policy ─────────────────────────────────────────────
    // Default: BLOCK_ALWAYS — safest for a parental-control gateway.
    // The user can change this via the dashboard after first run.
    _, err := d.db.Exec(
        `INSERT OR IGNORE INTO policies (mac, mode, enabled, created_at, updated_at)
         VALUES (NULL, ?, 1, ?, ?)`,
        ModeBlockAlways, now, now,
    )
    if err != nil {
        return fmt.Errorf("seed global policy: %w", err)
    }

    // ── Default settings ──────────────────────────────────────────
    defaults := map[string]string{
        "auth_password_hash": "",           // empty = first-run setup required
        "auth_enabled":       "true",
        "session_secret":     "",           // generated on first API start if empty
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

    d.logger.Debugf("Default data seeded")
    return nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// NormalizeMAC converts a MAC address to lowercase with colon separators.
// Example: "AA:BB:CC:DD:EE:FF" → "aa:bb:cc:dd:ee:ff"
// Also handles dash-separated input: "AA-BB-CC-DD-EE-FF" → "aa:bb:cc:dd:ee:ff"
func NormalizeMAC(mac string) string {
    mac = strings.TrimSpace(strings.ToLower(mac))
    mac = strings.ReplaceAll(mac, "-", ":")
    return mac
}

// firstLine returns the first line of a (possibly multi-line) SQL statement,
// truncated for use in error messages.
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
