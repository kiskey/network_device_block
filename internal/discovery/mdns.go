// Package discovery (mdns.go) implements a pure-Go mDNS (Multicast DNS) provider.
// v3.2.0: Robust socket binding (SO_REUSEPORT) and proper Multicast Group joining.
package discovery

import (
    "context"
    "encoding/binary"
    "fmt"
    "net"
    "strings"
    "syscall"
    "time"

    "lias/internal/logging"
    "golang.org/x/net/ipv4"
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
    
    query := []byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
        0x07, '_', 'd', 'n', 's', '-', 's', 'd',
        0x04, '_', 'u', 'd', 'p',
        0x05, 'l', 'o', 'c', 'a', 'l',
        0x00, 0x00, 0x0c, 0x00, 0x01,
    }

    // Use ListenConfig to set SO_REUSEADDR and SO_REUSEPORT.
    // This allows us to bind to port 5353 even if avahi-daemon is running.
    lc := net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            var sockOptErr error
            err := c.Control(func(fd uintptr) {
                sockOptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
                if sockOptErr != nil {
                    return
                }
                // SO_REUSEPORT (15 on Linux)
                sockOptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
            })
            if err != nil {
                return err
            }
            return sockOptErr
        },
    }
    
    conn, err := lc.ListenPacket(context.Background(), "udp4", ":5353")
    if err != nil {
        p.logger.Warnf("mDNS: Could not bind to :5353 (%v). Falling back to ephemeral port.", err)
        conn, err = lc.ListenPacket(context.Background(), "udp4", ":0")
        if err != nil {
            return nil, fmt.Errorf("mDNS listen failed: %w", err)
        }
    }
    defer conn.Close()

    // Join the multicast group to ensure we receive responses
    pConn := ipv4.NewPacketConn(conn)
    ifaces, _ := net.Interfaces()
    for _, iface := range ifaces {
        pConn.JoinGroup(&iface, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)})
    }

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
                break
            }
            break
        }

        names := parseMDNSPacket(buf[:n])
        
        var hostname, service string
        for _, name := range names {
            lowerName := strings.ToLower(name)
            if strings.HasPrefix(lowerName, "_") {
                if service == "" {
                    service = name
                }
            } else if strings.HasSuffix(lowerName, ".local") {
                if hostname == "" {
                    // Extract instance name (e.g., "Johns-iPhone" from "Johns-iPhone._airplay._tcp.local")
                    parts := strings.SplitN(name, "._", 2)
                    hostname = parts[0]
                }
            }
        }

        if hostname != "" || service != "" {
            servicesStr := "mdns"
            if service != "" {
                servicesStr = "mdns:" + service
            }

            observations = append(observations, Observation{
                IP:         remoteAddr.(*net.UDPAddr).IP.String(),
                Hostname:   hostname,
                SourceName: p.Name(),
                Confidence: 95,
                Services:   servicesStr,
            })
        }
    }

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

    ptr := 12
    qdcount := int(binary.BigEndian.Uint16(data[4:6]))
    for q := 0; q < qdcount; q++ {
        _, next := parseDNSName(data, ptr)
        ptr = next + 4
        if ptr >= len(data) {
            return names
        }
    }

    for a := 0; a < totalAnswers; a++ {
        name, next := parseDNSName(data, ptr)
        if name != "" {
            names = append(names, name)
        }
        
        ptr = next + 8
        if ptr+2 > len(data) {
            break
        }
        
        rdlength := int(binary.BigEndian.Uint16(data[ptr:ptr+2]))
        ptr += 2
        
        if ptr+2 <= len(data) {
            recType := binary.BigEndian.Uint16(data[next:next+2])
            if recType == 0x000C {
                ptrName, _ := parseDNSName(data, ptr)
                if ptrName != "" {
                    names = append(names, ptrName)
                }
            }
        }
        
        ptr += rdlength
        if ptr >= len(data) {
            break
        }
    }

    return names
}

// parseDNSName parses a DNS name starting at the given offset, handling compression pointers.
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
            ptr++
            if !jumped {
                finalOffset = ptr
            }
            break
        }
        
        if l&0xC0 == 0xC0 {
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
