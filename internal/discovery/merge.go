// Package discovery (merge.go) contains the Merge Engine.
// It takes observations from multiple providers and combines them
// into a single canonical device record, strictly adhering to
// source priority and confidence scoring.
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
    Services   string // JSON string or comma-separated list
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
// It returns a map of MAC -> DeviceObservation ready for database upsert.
func (m *MergeEngine) Merge(observations []Observation) map[string]database.DeviceObservation {
    merged := make(map[string]database.DeviceObservation)
    sourcesMap := make(map[string]map[string]bool) // mac -> source -> true

    // Helper to track max confidence per MAC
    maxConfidence := make(map[string]int)

    for _, obs := range observations {
        mac := database.NormalizeMAC(obs.MAC)
        if mac == "" {
            continue
        }

        // Track sources
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

            // Vendor/OS/Services: Overwrite if not empty (Nmap usually wins here if run)
            if obs.Vendor != "" {
                dev.Vendor = obs.Vendor
            }
            if obs.OS != "" {
                dev.OS = obs.OS
            }
            if obs.Services != "" {
                // Simple append for services if from different sources, or overwrite if Nmap
                if obs.SourceName == "nmap" {
                    dev.Services = obs.Services
                } else if dev.Services == "" {
                    dev.Services = obs.Services
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
