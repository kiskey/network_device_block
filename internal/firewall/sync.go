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
        // If the set doesn't exist or is empty, return empty map
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
// It NEVER flushes or recreates the set.
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
        if _, exists := desiredMap[macStr]; !exists {
            toDelete = append(toDelete, macStr)
        }
    }

    fw.mu.Lock()
    defer fw.mu.Unlock()

    if len(toAdd) > 0 {
        elems := strings.Join(toAdd, ", ")
        if _, err := fw.runNft("add", "element", "netdev", TableName, setName, "{ "+elems+" }"); err != nil {
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
