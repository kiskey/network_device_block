// Package firewall manages the application's dedicated nftables table.
// It executes the native `nft` binary to ensure perfect compatibility
// with all nftables features (like netdev device binding) without
// relying on third-party Go struct mappings that often break.
//
// CRITICAL: This package ONLY interacts with `table netdev lancontrol`.
// It never touches inet filter, inet nat, VPN rules, routing, or NAT.
package firewall

import (
    "bytes"
    "fmt"
    "os/exec"
    "strings"
    "sync"
)

const (
    TableName       = "lancontrol"
    ChainName       = "ingress"
    BlockedSetName  = "blocked_macs"
    OverrideSetName = "override_allow"
)

// Firewall wraps the nft CLI and provides concurrency-safe access.
type Firewall struct {
    iface  string
    mu     sync.Mutex
    logger Logger
}

// Logger interface for firewall package
type Logger interface {
    Infof(format string, args ...interface{})
    Errorf(format string, args ...interface{})
    Warnf(format string, args ...interface{})
    Debugf(format string, args ...interface{})
}

// New initializes a new Firewall manager.
func New(iface string, logger Logger) (*Firewall, error) {
    if iface == "" {
        return nil, fmt.Errorf("interface name cannot be empty")
    }

    // Ensure nft binary exists
    if _, err := exec.LookPath("nft"); err != nil {
        return nil, fmt.Errorf("nftables binary 'nft' not found in PATH: %w", err)
    }

    return &Firewall{
        iface:  iface,
        logger: logger,
    }, nil
}

// runNft executes an nft command and returns the output.
func (fw *Firewall) runNft(args ...string) (string, error) {
    fw.logger.Debugf("Executing: nft %s", strings.Join(args, " "))
    cmd := exec.Command("nft", args...)
    var out bytes.Buffer
    var stderr bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &stderr
    err := cmd.Run()
    if err != nil {
        return "", fmt.Errorf("%s: %s", err, stderr.String())
    }
    return out.String(), nil
}

// VerifyOrCreate ensures the lancontrol table, sets, chain, and base rules
// exist. If they exist, they are left untouched. If missing, they are created.
// This is idempotent and safe to run on every startup.
func (fw *Firewall) VerifyOrCreate() error {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    // 1. Verify/Create Table
    out, err := fw.runNft("list", "tables")
    if err != nil {
        return fmt.Errorf("failed to list tables: %v", err)
    }

    if !strings.Contains(out, "table netdev "+TableName) {
        fw.logger.Infof("Table %s not found. Creating...", TableName)
        if _, err := fw.runNft("add", "table", "netdev", TableName); err != nil {
            return fmt.Errorf("create table: %v", err)
        }
    }

    // 2. Verify/Create Sets
    if _, err := fw.runNft("list", "set", "netdev", TableName, BlockedSetName); err != nil {
        if _, err := fw.runNft("add", "set", "netdev", TableName, BlockedSetName, "{ type ether_addr; }"); err != nil {
            return fmt.Errorf("create blocked_macs set: %v", err)
        }
    }

    if _, err := fw.runNft("list", "set", "netdev", TableName, OverrideSetName); err != nil {
        if _, err := fw.runNft("add", "set", "netdev", TableName, OverrideSetName, "{ type ether_addr; }"); err != nil {
            return fmt.Errorf("create override_allow set: %v", err)
        }
    }

    // 3. Verify/Create Chain
    chainDef := fmt.Sprintf("{ type filter hook ingress device \"%s\" priority -200; policy accept; }", fw.iface)
    if _, err := fw.runNft("list", "chain", "netdev", TableName, ChainName); err != nil {
        fw.logger.Infof("Chain %s not found. Creating...", ChainName)
        if _, err := fw.runNft("add", "chain", "netdev", TableName, ChainName, chainDef); err != nil {
            return fmt.Errorf("create ingress chain: %v", err)
        }
    }

    // 4. Verify/Create Rules
    out, _ = fw.runNft("list", "chain", "netdev", TableName, ChainName)

    if !strings.Contains(out, "@override_allow accept") {
        if _, err := fw.runNft("add", "rule", "netdev", TableName, ChainName, "ether", "saddr", "@override_allow", "accept"); err != nil {
            return fmt.Errorf("add override rule: %v", err)
        }
    }

    if !strings.Contains(out, "@blocked_macs drop") {
        if _, err := fw.runNft("add", "rule", "netdev", TableName, ChainName, "ether", "saddr", "@blocked_macs", "drop"); err != nil {
            return fmt.Errorf("add block rule: %v", err)
        }
    }

    // The 'accept' rule is technically redundant due to policy accept, 
    // but we add it to strictly match the spec's logic diagram.
    if !strings.Contains(out, "accept") {
        if _, err := fw.runNft("add", "rule", "netdev", TableName, ChainName, "accept"); err != nil {
            return fmt.Errorf("add accept rule: %v", err)
        }
    }

    return nil
}
