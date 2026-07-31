// Package discovery is responsible for identifying devices on the LAN.
// It merges multiple sources (ARP/Netlink, DHCP leases) into a canonical
// device record. The primary key is ALWAYS the MAC address; IP addresses
// are informational only.
package discovery

import (
    "context"
    "fmt"
    "sync"
    "time"

    "lias/internal/database"
    "lias/internal/logging"
)

// DeviceInfo represents a raw device discovered by a Provider.
type DeviceInfo struct {
    MAC      string
    IP       string
    Hostname string
}

// Provider is an interface for discovery sources (ARP, DHCP, mDNS, etc.)
type Provider interface {
    Discover() ([]DeviceInfo, error)
    Name() string
}

// Discovery manages the periodic scanning and merging of LAN devices.
type Discovery struct {
    db           *database.DB
    iface        string
    dhcpPath     string
    ouiPath      string
    threshold    time.Duration
    logger       *logging.Logger
    providers    []Provider
    vendorLookup *VendorLookup // Provided in Batch 6
}

// New initializes the Discovery manager.
func New(db *database.DB, iface, dhcpPath, ouiPath string, threshold time.Duration, logger *logging.Logger) *Discovery {
    d := &Discovery{
        db:        db,
        iface:     iface,
        dhcpPath:  dhcpPath,
        ouiPath:   ouiPath,
        threshold: threshold,
        logger:    logger,
    }

    // Initialize vendor lookup (graceful fallback if file missing)
    d.vendorLookup = NewVendorLookup(ouiPath, logger)

    // Register discovery providers
    // We fetch ARP and DHCP in this batch. mDNS and rDNS will hook in here.
    d.providers = []Provider{
        NewARPProvider(iface, logger),
        NewDHCPProvider(dhcpPath, logger),
    }

    return d
}

// Run starts the periodic discovery loop.
func (d *Discovery) Run(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    // Run once immediately at startup
    d.discoverOnce()

    for {
        select {
        case <-ctx.Done():
            d.logger.Infof("Discovery stopped.")
            return
        case <-ticker.C:
            d.discoverOnce()
        }
    }
}

// discoverOnce queries all providers, merges the results by MAC address,
// and updates the database. It also marks stale devices as offline.
func (d *Discovery) discoverOnce() {
    startTime := time.Now()
    merged := make(map[string]DeviceInfo)
    var mu sync.Mutex

    var wg sync.WaitGroup

    for _, p := range d.providers {
        wg.Add(1)
        go func(provider Provider) {
            defer wg.Done()
            devices, err := provider.Discover()
            if err != nil {
                d.logger.Warnf("%s discovery failed: %v", provider.Name(), err)
                return
            }

            mu.Lock()
            for _, dev := range devices {
                mac := database.NormalizeMAC(dev.MAC)
                if mac == "" {
                    continue
                }

                existing, exists := merged[mac]
                if !exists {
                    merged[mac] = DeviceInfo{
                        MAC:      mac,
                        IP:       dev.IP,
                        Hostname: dev.Hostname,
                    }
                } else {
                    // Merge: prefer non-empty values
                    if existing.IP == "" && dev.IP != "" {
                        existing.IP = dev.IP
                    }
                    if existing.Hostname == "" && dev.Hostname != "" {
                        existing.Hostname = dev.Hostname
                    }
                    merged[mac] = existing
                }
            }
            mu.Unlock()
        }(p)
    }

    // Wait for all discovery providers to finish
    wg.Wait()

    // Upsert all discovered devices
    for mac, info := range merged {
        vendor := d.vendorLookup.Lookup(mac)
        
        // In a full implementation, we'd hook mDNS and rDNS here if Hostname was empty.
        hostname := info.Hostname
        if hostname == "" {
            hostname = "Unknown Device"
        }

        if err := d.db.UpsertDevice(mac, hostname, vendor, info.IP, true); err != nil {
            d.logger.Errorf("Failed upserting device %s: %v", mac, err)
        }
    }

    // Mark devices not seen recently as offline
    cutoff := time.Now().Add(-d.threshold).Unix()
    if _, err := d.db.MarkStaleDevicesOffline(cutoff); err != nil {
        d.logger.Errorf("Failed marking stale devices offline: %v", err)
    }

    d.logger.Debugf("Discovery cycle completed in %s. %d active devices.", time.Since(startTime), len(merged))
}

// VendorLookup stub to be fully implemented in Batch 6 (vendor.go)
// Included here so the code compiles immediately.
type VendorLookup struct {
    ouiMap map[string]string
}

func NewVendorLookup(path string, logger *logging.Logger) *VendorLookup {
    // Real implementation loads the OUI file into ouiMap.
    // For now, returning an empty map to allow compilation before Batch 6.
    return &VendorLookup{ouiMap: make(map[string]string)}
}

func (vl *VendorLookup) Lookup(mac string) string {
    if len(mac) >= 8 {
        prefix := mac[:8] // "aa:bb:cc"
        if vendor, ok := vl.ouiMap[prefix]; ok {
            return vendor
        }
    }
    return ""
}

// unused import prevention
var _ = fmt.Sprintf
