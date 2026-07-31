// Package firewall manages the application's dedicated nftables table.
// It uses the google/nftables library for pure-Go netlink communication.
//
// CRITICAL: This package ONLY interacts with `table netdev lancontrol`.
// It never touches inet filter, inet nat, VPN rules, routing, or NAT.
package firewall

import (
    "fmt"
    "net"
    "strings"
    "sync"

    "github.com/google/nftables"
    "github.com/google/nftables/expr"
    "golang.org/x/sys/unix"
)

const (
    TableName      = "lancontrol"
    TableFamily    = nftables.TableFamilyNetdev
    ChainName      = "ingress"
    BlockedSetName = "blocked_macs"
    OverrideSetName = "override_allow"

    // UserData marker ensures we only manage our own rules
    UserDataMarker = "lias_managed"
)

// Firewall wraps the nftables connection and provides concurrency-safe
// access to our specific table, sets, and chain.
type Firewall struct {
    conn      *nftables.Conn
    iface     string
    table     *nftables.Table
    chain     *nftables.Chain
    blockedSet  *nftables.Set
    overrideSet *nftables.Set
    mu        sync.Mutex
    logger    Logger
}

// Logger interface for firewall package
type Logger interface {
    Infof(format string, args ...interface{})
    Errorf(format string, args ...interface{})
    Warnf(format string, args ...interface{})
    Debugf(format string, args ...interface{})
}

// New initializes a new nftables connection for the given interface.
func New(iface string, logger Logger) (*Firewall, error) {
    if iface == "" {
        return nil, fmt.Errorf("interface name cannot be empty")
    }

    fw := &Firewall{
        conn:   nftables.New(),
        iface:  iface,
        logger: logger,
    }

    // Define our dedicated table (netdev family)
    fw.table = &nftables.Table{
        Family: TableFamily,
        Name:   TableName,
    }

    // Define the ingress chain attached to the interface
    fw.chain = &nftables.Chain{
        Name:     ChainName,
        Table:    fw.table,
        Type:     nftables.ChainTypeFilter,
        Hooknum:  nftables.ChainHookIngress,
        Priority: nftables.ChainPriorityFilter, // -200
        Device:   fw.iface,
    }

    // Define the blocked_macs set
    fw.blockedSet = &nftables.Set{
        Name:   BlockedSetName,
        Table:  fw.table,
        KeyType: nftables.TypeEtherAddr,
    }

    // Define the override_allow set
    fw.overrideSet = &nftables.Set{
        Name:   OverrideSetName,
        Table:  fw.table,
        KeyType: nftables.TypeEtherAddr,
    }

    return fw, nil
}

// VerifyOrCreate ensures the lancontrol table, sets, chain, and base rules
// exist. If they exist, they are left untouched. If missing, they are created.
// This is idempotent and safe to run on every startup.
func (fw *Firewall) VerifyOrCreate() error {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    // 1. Verify/Create Table
    tables, err := fw.conn.ListTables()
    if err != nil {
        return fmt.Errorf("list tables: %w", err)
    }
    
    tableExists := false
    for _, t := range tables {
        if t.Name == TableName && t.Family == TableFamily {
            tableExists = true
            fw.table = t // adopt existing table reference
            // Ensure our internal structs point to the real table
            fw.chain.Table = t
            fw.blockedSet.Table = t
            fw.overrideSet.Table = t
            break
        }
    }
    
    if !tableExists {
        fw.logger.Infof("Table %s not found. Creating...", TableName)
        fw.conn.AddTable(fw.table)
        if err := fw.conn.Flush(); err != nil {
            return fmt.Errorf("create table: %w", err)
        }
    }

    // 2. Verify/Create Sets
    sets, err := fw.conn.GetSets(fw.table)
    if err != nil {
        return fmt.Errorf("get sets: %w", err)
    }

    blockedExists := false
    overrideExists := false
    for _, s := range sets {
        if s.Name == BlockedSetName {
            blockedExists = true
            fw.blockedSet = s
        }
        if s.Name == OverrideSetName {
            overrideExists = true
            fw.overrideSet = s
        }
    }

    if !blockedExists {
        fw.conn.AddSet(fw.blockedSet, nil)
    }
    if !overrideExists {
        fw.conn.AddSet(fw.overrideSet, nil)
    }
    
    if !blockedExists || !overrideExists {
        if err := fw.conn.Flush(); err != nil {
            return fmt.Errorf("create sets: %w", err)
        }
    }

    // 3. Verify/Create Chain
    chains, err := fw.conn.ListChains(fw.table)
    if err != nil {
        return fmt.Errorf("list chains: %w", err)
    }

    chainExists := false
    for _, c := range chains {
        if c.Name == ChainName {
            chainExists = true
            fw.chain = c
            break
        }
    }

    if !chainExists {
        fw.logger.Infof("Chain %s not found. Creating...", ChainName)
        fw.conn.AddChain(fw.chain)
        if err := fw.conn.Flush(); err != nil {
            return fmt.Errorf("create chain: %w", err)
        }
    }

    // 4. Verify/Create Rules
    // We mark our rules with UserData to avoid touching manually added rules
    rules, err := fw.conn.GetRules(fw.table, fw.chain)
    if err != nil {
        return fmt.Errorf("get rules: %w", err)
    }

    hasOverrideRule := false
    hasBlockRule := false
    hasAcceptRule := false

    for _, r := range rules {
        if string(r.UserData) == UserDataMarker {
            // We only care about the presence of our managed rules.
            // A robust implementation could verify the expressions match.
            if len(r.Exprs) > 0 {
                // Heuristic: if it has a lookup and accept, it's override. 
                // If lookup and drop, it's block. If just accept, it's default.
                if hasVerdict(r, expr.VerdictAccept) && hasLookup(r) {
                    hasOverrideRule = true
                } else if hasVerdict(r, expr.VerdictDrop) && hasLookup(r) {
                    hasBlockRule = true
                } else if hasVerdict(r, expr.VerdictAccept) && !hasLookup(r) {
                    hasAcceptRule = true
                }
            }
        }
    }

    rulesToAdd := false
    if !hasOverrideRule {
        fw.addOverrideRule()
        rulesToAdd = true
    }
    if !hasBlockRule {
        fw.addBlockRule()
        rulesToAdd = true
    }
    if !hasAcceptRule {
        fw.addAcceptRule()
        rulesToAdd = true
    }

    if rulesToAdd {
        fw.logger.Infof("Base rules missing. Adding managed rules...")
        if err := fw.conn.Flush(); err != nil {
            return fmt.Errorf("add rules: %w", err)
        }
    }

    return nil
}

// Helper to check if a rule contains a specific verdict
func hasVerdict(rule *nftables.Rule, kind uint32) bool {
    for _, e := range rule.Exprs {
        if v, ok := e.(*expr.Verdict); ok {
            if v.Kind == kind {
                return true
            }
        }
    }
    return false
}

// Helper to check if a rule contains a set lookup
func hasLookup(rule *nftables.Rule) bool {
    for _, e := range rule.Exprs {
        if _, ok := e.(*expr.Lookup); ok {
            return true
        }
    }
    return false
}

func (fw *Firewall) addOverrideRule() {
    fw.conn.AddRule(&nftables.Rule{
        Table:    fw.table,
        Chain:    fw.chain,
        UserData: []byte(UserDataMarker),
        Exprs: []expr.Any{
            // Load ether saddr into register 1
            &expr.Payload{
                OperationType: expr.PayloadLoad,
                DestRegister:  1,
                Base:          expr.PayloadBaseLLHeader,
                Offset:        6, // Source MAC starts at byte 6 in Ethernet header
                Len:           6,
            },
            // Check if it's in override_allow set
            &expr.Lookup{
                SourceRegister: 1,
                SetName:        OverrideSetName,
                SetID:          fw.overrideSet.ID,
            },
            // If matched, accept
            &expr.Verdict{
                Kind: expr.VerdictAccept,
            },
        },
    })
}

func (fw *Firewall) addBlockRule() {
    fw.conn.AddRule(&nftables.Rule{
        Table:    fw.table,
        Chain:    fw.chain,
        UserData: []byte(UserDataMarker),
        Exprs: []expr.Any{
            &expr.Payload{
                OperationType: expr.PayloadLoad,
                DestRegister:  1,
                Base:          expr.PayloadBaseLLHeader,
                Offset:        6,
                Len:           6,
            },
            &expr.Lookup{
                SourceRegister: 1,
                SetName:        BlockedSetName,
                SetID:          fw.blockedSet.ID,
            },
            &expr.Verdict{
                Kind: expr.VerdictDrop,
            },
        },
    })
}

func (fw *Firewall) addAcceptRule() {
    fw.conn.AddRule(&nftables.Rule{
        Table:    fw.table,
        Chain:    fw.chain,
        UserData: []byte(UserDataMarker),
        Exprs: []expr.Any{
            &expr.Verdict{
                Kind: expr.VerdictAccept,
            },
        },
    })
}

// parseMAC converts a string MAC to the 6-byte array required by nftables.
func parseMAC(mac string) ([6]byte, error) {
    var macBytes [6]byte
    hw, err := net.ParseMAC(strings.ToLower(mac))
    if err != nil {
        return macBytes, err
    }
    if len(hw) != 6 {
        return macBytes, fmt.Errorf("invalid mac length")
    }
    copy(macBytes[:], hw)
    return macBytes, nil
}

// unused import prevention if unix is needed later for constants
var _ = unix.NLMSG_DONE
