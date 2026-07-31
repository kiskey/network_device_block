// Package discovery is responsible for identifying devices on the LAN.
// It merges multiple sources (ARP/Netlink, DHCP leases, rDNS) into a canonical
// device record. The primary key is ALWAYS the MAC address.
package discovery

import (
    "context"
    "sync"
    "time"

    "lias/internal/database"
    "lias/internal/dns"
    "lias/internal/logging"
    "lias/internal/vendor"
)

// DeviceInfo represents a raw device discovered by a Provider.
type DeviceInfo struct {
    MAC      string
    IP       string
    Hostname string
}

// Provider is an interface for discovery sources (ARP, DHCP, etc.)
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
    vendorLookup *vendor.Lookup
    dnsResolver  *dns.Resolver
}

// New initializes the Discovery manager.
func New(db *database.DB, iface, dhcpPath, ouiPath string, threshold time.Duration, logger *logging.Logger) *Discovery {
    d := &Discovery{
        db:           db,
        iface:        iface,
        dhcpPath:     dhcpPath,
        ouiPath:      ouiPath,
        threshold:    threshold,
        logger:       logger,
        vendorLookup: vendor.New(ouiPath),
        dnsResolver:  dns.New(),
    }

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

    wg.Wait()

    // Upsert all discovered devices
    for mac, info := range merged {
        vendorName := d.vendorLookup.Lookup(mac)
        
        // 1. Try to use hostname from DHCP
        hostname := info.Hostname
        
        // 2. If empty, try Reverse DNS (which also checks OS hosts/mDNS)
        if hostname == "" && info.IP != "" {
            hostname = d.dnsResolver.LookupAddr(info.IP)
        }
        
        // 3. If still empty, use Vendor name
        if hostname == "" && vendorName != "" {
            hostname = vendorName + " Device"
        }
        
        // 4. Fallback to IP
        if hostname == "" && info.IP != "" {
            hostname = "Device " + info.IP
        }
        
        // 5. Absolute fallback
        if hostname == "" {
            hostname = "Unknown Device"
        }

        if err := d.db.UpsertDevice(mac, hostname, vendorName, info.IP, true); err != nil {
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
