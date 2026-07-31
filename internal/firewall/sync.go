package firewall

import (
    "fmt"
)

// GetBlockedMACs retrieves the current MAC addresses in the blocked_macs set.
func (fw *Firewall) GetBlockedMACs() (map[string]struct{}, error) {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    elements, err := fw.conn.GetSetElements(fw.blockedSet)
    if err != nil {
        return nil, fmt.Errorf("get blocked elements: %w", err)
    }

    macs := make(map[string]struct{})
    for _, elem := range elements {
        if len(elem.Key) == 6 {
            mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                elem.Key[0], elem.Key[1], elem.Key[2],
                elem.Key[3], elem.Key[4], elem.Key[5])
            macs[mac] = struct{}{}
        }
    }
    return macs, nil
}

// GetOverrideMACs retrieves the current MAC addresses in the override_allow set.
func (fw *Firewall) GetOverrideMACs() (map[string]struct{}, error) {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    elements, err := fw.conn.GetSetElements(fw.overrideSet)
    if err != nil {
        return nil, fmt.Errorf("get override elements: %w", err)
    }

    macs := make(map[string]struct{})
    for _, elem := range elements {
        if len(elem.Key) == 6 {
            mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                elem.Key[0], elem.Key[1], elem.Key[2],
                elem.Key[3], elem.Key[4], elem.Key[5])
            macs[mac] = struct{}{}
        }
    }
    return macs, nil
}

// SyncBlockedMACs takes the desired list of MACs to block, diffs it against
// the current nftables set, and applies only the additions and deletions.
// It NEVER flushes or recreates the set.
func (fw *Firewall) SyncBlockedMACs(desired []string) error {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    current, err := fw.getCurrentMACs(fw.blockedSet)
    if err != nil {
        return err
    }

    desiredMap := make(map[string]struct{})
    var toAdd []*nftables.SetElement
    var toDelete []*nftables.SetElement

    for _, macStr := range desired {
        macStr = strings.ToLower(macStr)
        desiredMap[macStr] = struct{}{}
        if _, exists := current[macStr]; !exists {
            macBytes, err := parseMAC(macStr)
            if err != nil {
                fw.logger.Warnf("Skipping invalid MAC %s: %v", macStr, err)
                continue
            }
            toAdd = append(toAdd, &nftables.SetElement{
                Key: macBytes[:],
            })
        }
    }

    for macStr, elem := range current {
        if _, exists := desiredMap[macStr]; !exists {
            toDelete = append(toDelete, elem)
        }
    }

    if len(toAdd) > 0 {
        if err := fw.conn.SetAddElements(fw.blockedSet, toAdd); err != nil {
            return fmt.Errorf("add blocked elements: %w", err)
        }
        fw.logger.Debugf("Adding %d MACs to blocked set", len(toAdd))
    }

    if len(toDelete) > 0 {
        if err := fw.conn.SetDeleteElements(fw.blockedSet, toDelete); err != nil {
            return fmt.Errorf("delete blocked elements: %w", err)
        }
        fw.logger.Debugf("Removing %d MACs from blocked set", len(toDelete))
    }

    if len(toAdd) > 0 || len(toDelete) > 0 {
        if err := fw.conn.Flush(); err != nil {
            return fmt.Errorf("flush blocked changes: %w", err)
        }
    }

    return nil
}

// SyncOverrideMACs takes the desired list of MACs to allow, diffs it against
// the current nftables set, and applies only the additions and deletions.
func (fw *Firewall) SyncOverrideMACs(desired []string) error {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    current, err := fw.getCurrentMACs(fw.overrideSet)
    if err != nil {
        return err
    }

    desiredMap := make(map[string]struct{})
    var toAdd []*nftables.SetElement
    var toDelete []*nftables.SetElement

    for _, macStr := range desired {
        macStr = strings.ToLower(macStr)
        desiredMap[macStr] = struct{}{}
        if _, exists := current[macStr]; !exists {
            macBytes, err := parseMAC(macStr)
            if err != nil {
                fw.logger.Warnf("Skipping invalid MAC %s: %v", macStr, err)
                continue
            }
            toAdd = append(toAdd, &nftables.SetElement{
                Key: macBytes[:],
            })
        }
    }

    for macStr, elem := range current {
        if _, exists := desiredMap[macStr]; !exists {
            toDelete = append(toDelete, elem)
        }
    }

    if len(toAdd) > 0 {
        if err := fw.conn.SetAddElements(fw.overrideSet, toAdd); err != nil {
            return fmt.Errorf("add override elements: %w", err)
        }
        fw.logger.Debugf("Adding %d MACs to override set", len(toAdd))
    }

    if len(toDelete) > 0 {
        if err := fw.conn.SetDeleteElements(fw.overrideSet, toDelete); err != nil {
            return fmt.Errorf("delete override elements: %w", err)
        }
        fw.logger.Debugf("Removing %d MACs from override set", len(toDelete))
    }

    if len(toAdd) > 0 || len(toDelete) > 0 {
        if err := fw.conn.Flush(); err != nil {
            return fmt.Errorf("flush override changes: %w", err)
        }
    }

    return nil
}

// getCurrentMACs is an internal helper to fetch set elements as a map
// of MAC string to SetElement pointers.
func (fw *Firewall) getCurrentMACs(set *nftables.Set) (map[string]*nftables.SetElement, error) {
    elements, err := fw.conn.GetSetElements(set)
    if err != nil {
        return nil, fmt.Errorf("get elements for set %s: %w", set.Name, err)
    }

    macs := make(map[string]*nftables.SetElement)
    for _, elem := range elements {
        if len(elem.Key) == 6 {
            mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                elem.Key[0], elem.Key[1], elem.Key[2],
                elem.Key[3], elem.Key[4], elem.Key[5])
            macs[mac] = elem
        }
    }
    return macs, nil
}

// Ensure strings is used
var _ = fmt.Sprintf
