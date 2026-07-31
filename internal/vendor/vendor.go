// Package vendor provides offline IEEE OUI (Organizationally Unique Identifier)
// lookups. It parses a standard oui.txt file (e.g., from standup.io or IEEE)
// and stores the 3-byte prefix to vendor name mapping in memory.
package vendor

import (
    "bufio"
    "os"
    "strings"
    "sync"
)

// Lookup provides thread-safe in-memory OUI vendor lookups.
type Lookup struct {
    ouiMap map[string]string
    mu     sync.RWMutex
}

// New initializes the Lookup struct and loads the OUI database from the given path.
// If the file cannot be read, it gracefully falls back to an empty map.
func New(path string) *Lookup {
    l := &Lookup{
        ouiMap: make(map[string]string),
    }
    l.load(path)
    return l
}

// load reads the OUI file line by line.
// Expected format: "AA-BB-CC   (hex)		Vendor Name Inc"
func (l *Lookup) load(path string) {
    file, err := os.Open(path)
    if err != nil {
        // Silently fail; vendor resolution is a nice-to-have, not critical
        return
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        // Look for lines containing "(hex)"
        if !strings.Contains(line, "(hex)") {
            continue
        }

        // Split by "(hex)"
        parts := strings.SplitN(line, "(hex)", 2)
        if len(parts) != 2 {
            continue
        }

        prefix := strings.TrimSpace(parts[0])
        vendor := strings.TrimSpace(parts[1])

        // Normalize prefix to lowercase colons (e.g., aa:bb:cc)
        prefix = strings.ToLower(prefix)
        prefix = strings.ReplaceAll(prefix, "-", ":")

        if len(prefix) == 8 && prefix[2] == ':' && prefix[5] == ':' {
            l.ouiMap[prefix] = vendor
        }
    }
}

// Lookup resolves a MAC address to a vendor name.
// Returns an empty string if the vendor is unknown.
func (l *Lookup) Lookup(mac string) string {
    if len(mac) < 8 {
        return ""
    }

    // Extract first 3 bytes (aa:bb:cc)
    prefix := mac[:8]
    prefix = strings.ToLower(prefix)
    prefix = strings.ReplaceAll(prefix, "-", ":")

    l.mu.RLock()
    defer l.mu.RUnlock()

    return l.ouiMap[prefix]
}
