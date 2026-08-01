// Package main is the entry point for the LAN Internet Access Scheduler.
package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"
    "time"

    "lias/internal/api"
    "lias/internal/database"
    "lias/internal/discovery"
    "lias/internal/firewall"
    "lias/internal/logging"
    "lias/internal/scheduler"
)

const (
    appName    = "lias"
    appVersion = "3.0.0"
)

// Config holds all application configuration parsed from flags and env.
type Config struct {
    DBPath            string
    Interface         string
    ListenAddr        string
    LogLevel          string
    HTTPSEnabled      bool
    HTTPSCert         string
    HTTPSKey          string
    OUIPath           string
    DHCPLeasesPath    string
    DiscoveryInterval time.Duration
    ScheduleInterval  time.Duration
    OfflineThreshold  time.Duration
    LogRetentionDays  int
}

// parseConfig reads configuration from command-line flags.
func parseConfig() *Config {
    cfg := &Config{}
    flag.StringVar(&cfg.DBPath, "db", "/var/lib/lias/lias.db", "SQLite database path")
    flag.StringVar(&cfg.Interface, "interface", "eth0", "LAN interface for netdev ingress hook")
    flag.StringVar(&cfg.ListenAddr, "listen", "0.0.0.0:8443", "HTTP/HTTPS listen address")
    flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug/info/warn/error)")
    flag.BoolVar(&cfg.HTTPSEnabled, "https", false, "Enable HTTPS")
    flag.StringVar(&cfg.HTTPSCert, "cert", "", "TLS certificate path")
    flag.StringVar(&cfg.HTTPSKey, "key", "", "TLS private key path")
    flag.StringVar(&cfg.OUIPath, "oui", "/etc/lias/oui.txt", "IEEE OUI vendor database path")
    flag.StringVar(&cfg.DHCPLeasesPath, "dhcp-leases", "/var/lib/dhcpd/dhcpd.leases", "DHCP leases file path")
    flag.DurationVar(&cfg.DiscoveryInterval, "discovery-interval", 30*time.Second, "Passive device discovery interval")
    flag.DurationVar(&cfg.ScheduleInterval, "schedule-interval", 60*time.Second, "Scheduler evaluation interval")
    flag.DurationVar(&cfg.OfflineThreshold, "offline-threshold", 90*time.Second, "Device offline detection threshold")
    flag.IntVar(&cfg.LogRetentionDays, "log-retention", 30, "Log retention in days")
    flag.Parse()
    return cfg
}

func main() {
    cfg := parseConfig()
    logger := logging.New(cfg.LogLevel)

    logger.Infof("╔══════════════════════════════════════════════╗")
    logger.Infof("║  %s v%s%-34s║", appName, appVersion, "")
    logger.Infof("╚══════════════════════════════════════════════╝")
    logger.Infof("Interface : %s", cfg.Interface)
    logger.Infof("Listen    : %s", cfg.ListenAddr)
    logger.Infof("Database  : %s", cfg.DBPath)
    logger.Infof("Discovery : %s  |  Scheduler : %s",
        cfg.DiscoveryInterval, cfg.ScheduleInterval)

    // ── Ensure database directory exists ────────────────────────────
    if dir := filepath.Dir(cfg.DBPath); dir != "" && dir != "." {
        if err := os.MkdirAll(dir, 0755); err != nil {
            logger.Fatalf("Cannot create database directory %s: %v", dir, err)
        }
    }

    // ── Initialize database ────────────────────────────────────────
    db, err := database.New(cfg.DBPath, logger)
    if err != nil {
        logger.Fatalf("Database initialization failed: %v", err)
    }
    defer db.Close()
    logger.Infof("✓ Database ready")

    // ── Initialize firewall manager ────────────────────────────────
    fw, err := firewall.New(cfg.Interface, logger)
    if err != nil {
        logger.Fatalf("Firewall manager initialization failed: %v", err)
    }

    if err := fw.VerifyOrCreate(); err != nil {
        logger.Fatalf("Firewall verification failed — refusing to start without safe nftables state: %v", err)
    }
    logger.Infof("✓ nftables table 'lancontrol' verified on '%s'", cfg.Interface)

    // ── Create scheduler ───────────────────────────────────────────
    sched := scheduler.New(db, fw, logger)

    // ── Initial firewall synchronization ───────────────────────────
    if err := sched.RunOnce(); err != nil {
        logger.Fatalf("Initial firewall sync failed: %v", err)
    }
    logger.Infof("✓ Firewall synchronized with database policies")

    // ── Graceful shutdown context ──────────────────────────────────
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // ── Start device discovery ─────────────────────────────────────
    // v3.0.0: Use the new Discovery Manager signature
    disc := discovery.New(db, logger, cfg.OUIPath, cfg.DHCPLeasesPath, cfg.Interface)
    
    // Determine active scan interval (default 10 minutes)
    activeInterval := 10 * time.Minute
    if val := db.GetIntSetting("nmap_interval", 600); val > 0 {
        activeInterval = time.Duration(val) * time.Second
    }
    
    go disc.Run(ctx, cfg.DiscoveryInterval, activeInterval)
    logger.Infof("✓ Device discovery running (passive: %s, active: %s)", cfg.DiscoveryInterval, activeInterval)

    // ── Start scheduler ────────────────────────────────────────────
    go sched.Run(ctx, cfg.ScheduleInterval)
    logger.Infof("✓ Scheduler running (interval: %s)", cfg.ScheduleInterval)

    // ── Start log retention cleanup ────────────────────────────────
    go runLogRetention(ctx, db, cfg.LogRetentionDays, logger)

    // ── Start API + UI server ──────────────────────────────────────
    serverCfg := api.ServerConfig{
        ListenAddr:   cfg.ListenAddr,
        HTTPSEnabled: cfg.HTTPSEnabled,
        HTTPSCert:    cfg.HTTPSCert,
        HTTPSKey:     cfg.HTTPSKey,
    }
    server := api.NewServer(db, fw, serverCfg, logger)
    go func() {
        logger.Infof("✓ API server starting on %s", cfg.ListenAddr)
        if err := server.Start(); err != nil {
            logger.Fatalf("API server error: %v", err)
        }
    }()

    // ── Wait for interrupt signal ──────────────────────────────────
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    sig := <-sigCh
    logger.Infof("")
    logger.Infof("Received signal %v — initiating graceful shutdown...", sig)

    cancel()

    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer shutdownCancel()

    if err := server.Stop(shutdownCtx); err != nil {
        logger.Errorf("Server shutdown error: %v", err)
    }

    logger.Infof("Shutdown complete. Goodbye.")
}

// runLogRetention periodically deletes log entries older than the configured retention period.
func runLogRetention(ctx context.Context, db *database.DB, days int, logger *logging.Logger) {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    cleanup := func() {
        cutoff := time.Now().AddDate(0, 0, -days).Unix()
        count, err := db.DeleteLogsBefore(cutoff)
        if err != nil {
            logger.Errorf("Log retention cleanup error: %v", err)
            return
        }
        if count > 0 {
            logger.Infof("Log retention: purged %d entries older than %d days", count, days)
        }
    }

    cleanup()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            cleanup()
        }
    }
}

// unused import prevention
var _ = fmt.Sprintf
