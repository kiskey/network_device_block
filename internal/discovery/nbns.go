// Package discovery (nbns.go) implements a pure-Go NetBIOS Name Service (NBNS) provider.
// It discovers Windows PCs and older NAS devices by sending a Name Query.
package discovery

import (
    "encoding/binary"
    "fmt"
    "net"
    "time"

    "lias/internal/logging"
)

// NBNSProvider discovers devices via NetBIOS.
type NBNSProvider struct {
    logger *logging.Logger
}

// NewNBNSProvider creates a new NBNSProvider.
func NewNBNSProvider(logger *logging.Logger) *NBNSProvider {
    return &NBNSProvider{logger: logger}
}

// Name returns the provider name.
func (p *NBNSProvider) Name() string {
    return "nbns"
}

// Discover sends a NetBIOS Name Query to the broadcast address and listens for responses.
func (p *NBNSProvider) Discover() ([]Observation, error) {
    // NetBIOS Name Service uses UDP port 137
    broadcastAddr := "255.255.255.255:137"
    
    // A NetBIOS Name Service query for "*<00>" (Wildcard name)
    // This asks for the name of the machine responding.
    query := []byte{
        0x00, 0x00, // Transaction ID
        0x00, 0x10, // Flags (Broadcast, Query)
        0x00, 0x01, // Questions (1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer, Authority, Additional RRs
        0x20, // Length of name (32)
        // Encoded "*\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" using NetBIOS encoding
        0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
        0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
        0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
        0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
        0x00, // Null terminator
        0x00, 0x20, // Type NB (NetBIOS)
        0x00, 0x01, // Class IN
    }

    // We need to listen on UDP 137 to receive replies.
    // Note: Binding to port 137 might require root privileges or conflict with Samba.
    conn, err := net.ListenPacket("udp4", ":137")
    if err != nil {
        // Fallback to ephemeral port (might miss responses if firewall blocks it)
        conn, err = net.ListenPacket("udp4", ":0")
        if err != nil {
            return nil, fmt.Errorf("nbns listen failed: %w", err)
        }
    }
    defer conn.Close()

    addr, err := net.ResolveUDPAddr("udp4", broadcastAddr)
    if err != nil {
        return nil, err
    }

    _, err = conn.WriteTo(query, addr)
    if err != nil {
        // Some systems block broadcast writes on ephemeral ports
        p.logger.Debugf("NBNS broadcast write failed: %v", err)
        return nil, nil
    }

    conn.SetReadDeadline(time.Now().Add(2 * time.Second))

    var observations []Observation
    buf := make([]byte, 65536)

    for {
        n, remoteAddr, err := conn.ReadFrom(buf)
        if err != nil {
            if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
                break
            }
            break
        }

        // Parse the NetBIOS response
        // A valid response should have the same Transaction ID and contain the name.
        if n > 56 {
            // The name is usually at offset 56, and is 15 characters long.
            nameBytes := buf[56 : 56+15]
            name := string(nameBytes)
            
            // Trim trailing spaces
            name = fmt.Sprintf("%-15s", name)
            name = name[:15]
            
            if name != "" && name != "               " {
                observations = append(observations, Observation{
                    IP:         remoteAddr.(*net.UDPAddr).IP.String(),
                    Hostname:   name,
                    SourceName: p.Name(),
                    Confidence: 90, // High confidence for Windows names
                    Services:   "nbns",
                })
            }
        }
    }

    return observations, nil
}
