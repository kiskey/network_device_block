// Package discovery (mdns.go) implements a pure-Go mDNS (Multicast DNS) provider.
// It queries the local network for devices broadcasting services (Apple, IoT, Printers).
package discovery

import (
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
    // mDNS multicast address for IPv4
    multicastAddr := "224.0.0.251:5353"
    
    // Standard query for all services (_services._dns-sd._udp.local)
    // This is a raw DNS packet formatted to ask for service enumerations.
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

    // Listen for responses
    // We bind to 0.0.0.0:5353. Note: If avahi-daemon is running, this might fail to bind.
    // If it fails, we fall back to just sending and listening on an ephemeral port (less reliable for multicast).
    conn, err := net.ListenPacket("udp4", ":5353")
    if err != nil {
        // Fallback: send from ephemeral port (we might not get multicast responses, but it's safe)
        p.logger.Debugf("mDNS: Could not bind to :5353 (is avahi running?). Falling back.")
        conn, err = net.ListenPacket("udp4", ":0")
        if err != nil {
            return nil, fmt.Errorf("mDNS listen failed: %w", err)
        }
    }
    defer conn.Close()

    // Send the query to the multicast address
    addr, err := net.ResolveUDPAddr("udp4", multicastAddr)
    if err != nil {
        return nil, err
    }

    _, err = conn.WriteTo(query, addr)
    if err != nil {
        return nil, fmt.Errorf("mDNS write failed: %w", err)
    }

    // Set a deadline for listening (2 seconds is usually enough for LAN devices to chatter)
    conn.SetReadDeadline(time.Now().Add(2 * time.Second))

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

        // We need the MAC address. Since we are listening on UDP, we only have the IP.
        // We rely on the Merge Engine to combine this IP with the MAC from Netlink/ARP.
        // However, to help the merge engine, we can extract the Hostname from the mDNS packet.
        
        // Very basic raw parsing: look for the .local hostname in the payload
        payload := buf[:n]
        hostname := extractMDNSHostname(payload)
        
        if hostname != "" {
            observations = append(observations, Observation{
                IP:         remoteAddr.(*net.UDPAddr).IP.String(),
                Hostname:   hostname,
                SourceName: p.Name(),
                Confidence: 95, // mDNS hostnames are very reliable
                Services:   "mdns", // Mark that it supports mDNS for device type inference
            })
        }
    }

    return observations, nil
}

// extractMDNSHostname scans the raw DNS packet for a string ending in .local
func extractMDNSHostname(data []byte) string {
    str := string(data)
    idx := strings.Index(str, ".local")
    if idx == -1 {
        return ""
    }
    
    // Walk backwards from .local to find the start of the name
    start := idx
    for start > 0 {
        // DNS labels are preceded by their length. Stop if we hit a non-printable char or length byte.
        if data[start-1] < 32 || data[start-1] > 126 {
            break
        }
        start--
    }
    
    name := str[start:idx]
    if len(name) > 0 {
        return name + ".local"
    }
    return ""
}
