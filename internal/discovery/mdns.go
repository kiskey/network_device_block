// Package discovery (mdns.go) implements a pure-Go mDNS (Multicast DNS) provider.
// v3.1.1: Completely rewritten DNS parser to properly extract hostnames and services.
package discovery

import (
    "encoding/binary"
    "fmt"
    "net"
    "strings"
    "time"

    "lias/internal/logging"
)

// MDNSProvider discovers devices via multicast DNS.
type MDNSProvider struct {
    logger *logging.Logger
}

// NewMDNSProvider creates a new MDNSProvider.
func NewMDNSProvider(logger *logging.Logger) *MDNSProvider {
    return &MDNSProvider{logger: logger}
}

// Name returns the provider name.
func (p *MDNSProvider) Name() string {
    return "mdns"
}

// Discover sends an mDNS query and listens for responses.
func (p *MDNSProvider) Discover() ([]Observation, error) {
    multicastAddr := "224.0.0.251:5353"
    
    // Standard query for all services (_services._dns-sd._udp.local)
    query := []byte{
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Flags (Standard Query)
        0x00, 0x01, // Questions (1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer, Authority, Additional RRs
        0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
        0x07, '_', 'd', 'n', 's', '-', 's', 'd',
        0x04, '_', 'u', 'd', 'p',
        0x05, 'l', 'o', 'c', 'a', 'l',
        0x00, // Null terminator
        0x00, 0x0c, // Type PTR
        0x00, 0x01, // Class IN
    }

    // Try to bind to port 5353. This is required to receive standard mDNS responses.
    conn, err := net.ListenPacket("udp4", ":5353")
    if err != nil {
        // Fallback to ephemeral port (might miss some responses, but safer)
        p.logger.Debugf("mDNS: Could not bind to :5353 (%v). Falling back to ephemeral port.", err)
        conn, err = net.ListenPacket("udp4", ":0")
        if err != nil {
            return nil, fmt.Errorf("mDNS listen failed: %w", err)
        }
    }
    defer conn.Close()

    addr, err := net.ResolveUDPAddr("udp4", multicastAddr)
    if err != nil {
        return nil, err
    }

    _, err = conn.WriteTo(query, addr)
    if err != nil {
        return nil, fmt.Errorf("mDNS write failed: %w", err)
    }

    conn.SetReadDeadline(time.Now().Add(3 * time.Second))

    var observations []Observation
    buf := make([]byte, 65536)

    for {
        n, remoteAddr, err := conn.ReadFrom(buf)
        if err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                break // Timeout reached, stop listening
            }
            break // Other error, stop listening
        }

        // Parse the mDNS packet properly
        names := parseMDNSPacket(buf[:n])
        
        var hostname, service string
        for _, name := range names {
            lowerName := strings.ToLower(name)
            // If it's a service type (e.g., _airplay._tcp.local)
            if strings.HasPrefix(lowerName, "_") {
                if service == "" {
                    service = name
                }
            } else if strings.HasSuffix(lowerName, ".local") {
                // It's a hostname
                if hostname == "" {
                    hostname = strings.TrimSuffix(name, ".local")
                }
            }
        }

        // We need at least a hostname or service to care about this packet
        if hostname != "" || service != "" {
            servicesStr := "mdns"
            if service != "" {
                servicesStr = "mdns:" + service
            }

            observations = append(observations, Observation{
                IP:         remoteAddr.(*net.UDPAddr).IP.String(),
                Hostname:   hostname,
                SourceName: p.Name(),
                Confidence: 95, // mDNS hostnames are very reliable
                Services:   servicesStr,
            })
        }
    }

    p.logger.Debugf("mDNS discovered %d responses", len(observations))
    return observations, nil
}

// parseMDNSPacket extracts all DNS names from the Answer and Additional RR sections.
func parseMDNSPacket(data []byte) []string {
    var names []string
    if len(data) < 12 {
        return names
    }

    ancount := int(binary.BigEndian.Uint16(data[6:8]))
    arcount := int(binary.BigEndian.Uint16(data[10:12]))
    totalAnswers := ancount + arcount

    if totalAnswers == 0 {
        return names
    }

    // Skip header (12 bytes) and questions
    ptr := 12
    qdcount := int(binary.BigEndian.Uint16(data[4:6]))
    for q := 0; q < qdcount; q++ {
        _, next := parseDNSName(data, ptr)
        ptr = next + 4 // Type + Class
        if ptr >= len(data) {
            return names
        }
    }

    // Parse Answer and Additional sections
    for a := 0; a < totalAnswers; a++ {
        name, next := parseDNSName(data, ptr)
        if name != "" {
            names = append(names, name)
        }
        
        // Skip Type (2), Class (2), TTL (4)
        ptr = next + 8
        if ptr+2 > len(data) {
            break
        }
        
        // Read RDLENGTH
        rdlength := int(binary.BigEndian.Uint16(data[ptr:ptr+2]))
        ptr += 2
        
        // If it's a PTR record, the RDATA contains another DNS name we can parse
        // Type PTR = 0x000C
        if ptr+2 <= len(data) {
            recType := binary.BigEndian.Uint16(data[next:next+2])
            if recType == 0x000C {
                ptrName, _ := parseDNSName(data, ptr)
                if ptrName != "" {
                    names = append(names, ptrName)
                }
            }
        }
        
        // Skip RDATA
        ptr += rdlength
        if ptr >= len(data) {
            break
        }
    }

    return names
}

// parseDNSName parses a DNS name starting at the given offset, handling compression pointers.
// Returns the name and the offset of the byte immediately following the name.
func parseDNSName(data []byte, offset int) (string, int) {
    var labels []string
    ptr := offset
    jumped := false
    finalOffset := 0

    for {
        if ptr >= len(data) {
            break
        }
        l := int(data[ptr])
        
        if l == 0 {
            ptr++ // Skip null terminator
            if !jumped {
                finalOffset = ptr
            }
            break
        }
        
        if l&0xC0 == 0xC0 {
            // Compression pointer
            if ptr+1 >= len(data) {
                break
            }
            newOffset := ((l & 0x3F) << 8) | int(data[ptr+1])
            if !jumped {
                finalOffset = ptr + 2
            }
            ptr = newOffset
            jumped = true
            continue
        }
        
        // Normal label
        if ptr+1+l > len(data) {
            break
        }
        
        labels = append(labels, string(data[ptr+1:ptr+1+l]))
        ptr += 1 + l
    }

    if len(labels) == 0 {
        return "", finalOffset
    }
    
    return strings.Join(labels, "."), finalOffset
}
