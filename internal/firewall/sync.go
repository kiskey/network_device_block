package firewall

import (
    "fmt"
    "regexp"
    "strings"
)

var macRegex = regexp.MustCompile(`([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)

// getCurrentMACs fetches the elements of an nftables set as a map.
func (fw *Firewall) getCurrentMACs(setName string) (map[string]struct{}, error) {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    out, err := fw.runNft("list", "set", "netdev", TableName, setName)
    if err != nil {
        return make(map[string]struct{}), nil
    }

    macs := make(map[string]struct{})
    matches := macRegex.FindAllString(out, -1)
    for _, m := range matches {
        macs[strings.ToLower(m)] = struct{}{}
    }
    return macs, nil
}

// GetBlockedMACs retrieves the current MAC addresses in the blocked_macs set.
func (fw *Firewall) GetBlockedMACs() (map[string]struct{}, error) {
    return fw.getCurrentMACs(BlockedSetName)
}

// GetOverrideMACs retrieves the current MAC addresses in the override_allow set.
func (fw *Firewall) GetOverrideMACs() (map[string]struct{}, error) {
    return fw.getCurrentMACs(OverrideSetName)
}

// syncSet takes the desired list of MACs, diffs it against the current nftables
// set, and applies only the additions and deletions.
// v4.0.2: Filters multicast MACs and self-heals if the table is deleted externally.
func (fw *Firewall) syncSet(setName string, desired []string) error {
    current, err := fw.getCurrentMACs(setName)
    if err != nil {
        return err
    }

    desiredMap := make(map[string]struct{})
    var toAdd []string
    var toDelete []string

    for _, macStr := range desired {
        macStr = strings.ToLower(macStr)
        
        // v4.0.2: Filter out broadcast and multicast MACs
        if macStr == "ff:ff:ff:ff:ff:ff" || macStr == "00:00:00:00:00:00" {
            continue
        }
        if strings.HasPrefix(macStr, "01:00:5e") || strings.HasPrefix(macStr, "33:33") {
            continue // IPv4/IPv6 multicast MACs
        }
        
        if !macRegex.MatchString(macStr) {
            fw.logger.Warnf("Skipping invalid MAC format %s", macStr)
            continue
        }
        
        desiredMap[macStr] = struct{}{}
        if _, exists := current[macStr]; !exists {
            toAdd = append(toAdd, macStr)
        }
    }

    for macStr := range current {
        // Clean up any multicast MACs that might have gotten stuck previously
        if strings.HasPrefix(macStr, "01:00:5e") || strings.HasPrefix(macStr, "33:33") {
            toDelete = append(toDelete, macStr)
            continue
        }
        
        if _, exists := desiredMap[macStr]; !exists {
            toDelete = append(toDelete, macStr)
        }
    }

    fw.mu.Lock()
    defer fw.mu.Unlock()

    if len(toAdd) > 0 {
        elems := strings.Join(toAdd, ", ")
        _, err := fw.runNft("add", "element", "netdev", TableName, setName, "{ "+elems+" }")
        
        // v4.0.2 Self-Healing: If sing-box flushed the ruleset, rebuild and retry
        if err != nil && strings.Contains(err.Error(), "No such file or directory") {
            fw.mu.Unlock()
            fw.logger.Warnf("nftables set %s missing. Rebuilding table...", setName)
            rebuildErr := fw.VerifyOrCreate()
            fw.mu.Lock()
            if rebuildErr != nil {
                return fmt.Errorf("rebuild nftables: %v", rebuildErr)
            }
            // Retry adding the elements
            _, err = fw.runNft("add", "element", "netdev", TableName, setName, "{ "+elems+" }")
        }
        
        if err != nil {
            return fmt.Errorf("add elements to %s: %v", setName, err)
        }
        fw.logger.Debugf("Added %d MACs to %s", len(toAdd), setName)
    }

    if len(toDelete) > 0 {
        elems := strings.Join(toDelete, ", ")
        if _, err := fw.runNft("delete", "element", "netdev", TableName, setName, "{ "+elems+" }"); err != nil {
            return fmt.Errorf("delete elements from %s: %v", setName, err)
        }
        fw.logger.Debugf("Removed %d MACs from %s", len(toDelete), setName)
    }

    return nil
}

// SyncBlockedMACs syncs the blocked_macs set.
func (fw *Firewall) SyncBlockedMACs(desired []string) error {
    return fw.syncSet(BlockedSetName, desired)
}

// SyncOverrideMACs syncs the override_allow set.
func (fw *Firewall) SyncOverrideMACs(desired []string) error {
    return fw.syncSet(OverrideSetName, desired)
}
