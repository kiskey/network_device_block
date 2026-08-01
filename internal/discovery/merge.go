// Package discovery (merge.go) contains the Merge Engine.
// v3.1.0: Updated to handle IP-only observations by cross-referencing
// them with MACs discovered by Netlink/Nmap.
package discovery

import (
    "strings"

    "lias/internal/database"
)

// Observation represents a raw piece of data discovered by a Provider.
type Observation struct {
    MAC        string
    IP         string
    Hostname   string
    Vendor     string
    OS         string
    Services   string
    SourceName string
    Confidence int
}

// MergeEngine combines observations into database.DeviceObservation objects.
type MergeEngine struct{}

// NewMergeEngine creates a new MergeEngine.
func NewMergeEngine() *MergeEngine {
    return &MergeEngine{}
}

// Merge takes a slice of observations and merges them by MAC address.
func (m *MergeEngine) Merge(observations []Observation) map[string]database.DeviceObservation {
    merged := make(map[string]database.DeviceObservation)
    sourcesMap := make(map[string]map[string]bool) // mac -> source -> true
    maxConfidence := make(map[string]int)

    // 1. Build an IP -> MAC lookup table from high-confidence MAC sources (Netlink, Nmap, DHCP)
    ipToMAC := make(map[string]string)
    for _, obs := range observations {
        if obs.MAC != "" && obs.IP != "" {
            // Prioritize Nmap/Netlink MACs
            if _, exists := ipToMAC[obs.IP]; !exists || obs.SourceName == "nmap" || obs.SourceName == "netlink" {
                ipToMAC[obs.IP] = database.NormalizeMAC(obs.MAC)
            }
        }
    }

    // 2. Merge all observations
    for _, obs := range observations {
        mac := database.NormalizeMAC(obs.MAC)
        
        // If this observation doesn't have a MAC, try to find it via IP
        if mac == "" && obs.IP != "" {
            mac = ipToMAC[obs.IP]
        }

        // If we still don't have a MAC, we can't track it in our DB (ignore it)
        if mac == "" {
            continue
        }

        if sourcesMap[mac] == nil {
            sourcesMap[mac] = make(map[string]bool)
        }
        sourcesMap[mac][obs.SourceName] = true

        dev, exists := merged[mac]
        if !exists {
            dev = database.DeviceObservation{
                MAC:        mac,
                CurrentIP:  obs.IP,
                Hostname:   obs.Hostname,
                Vendor:     obs.Vendor,
                OS:         obs.OS,
                Services:   obs.Services,
                Confidence: obs.Confidence,
            }
        } else {
            // IP: Update if changed
            if obs.IP != "" {
                dev.CurrentIP = obs.IP
            }

            // Hostname: Only overwrite if new confidence is >= existing confidence
            if obs.Hostname != "" && obs.Confidence >= maxConfidence[mac] {
                dev.Hostname = obs.Hostname
            }

            // Vendor/OS: Overwrite if not empty (Nmap usually wins here)
            if obs.Vendor != "" {
                dev.Vendor = obs.Vendor
            }
            if obs.OS != "" {
                dev.OS = obs.OS
            }
            
            // Services: Append unique services
            if obs.Services != "" {
                if dev.Services == "" {
                    dev.Services = obs.Services
                } else if !strings.Contains(dev.Services, obs.Services) {
                    dev.Services = dev.Services + "," + obs.Services
                }
            }

            // Update max confidence
            if obs.Confidence > maxConfidence[mac] {
                maxConfidence[mac] = obs.Confidence
                dev.Confidence = obs.Confidence
            }
        }

        // Build comma-separated sources string
        var srcs []string
        for s := range sourcesMap[mac] {
            srcs = append(srcs, s)
        }
        dev.DiscoverySources = strings.Join(srcs, ",")

        merged[mac] = dev
    }

    return merged
}
