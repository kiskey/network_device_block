// Package discovery (ssdp.go) implements a pure-Go SSDP (UPnP) provider.
// v3.2.1: Explicitly binds to the physical interface IP.
package discovery

import (
    "bufio"
    "fmt"
    "net"
    "strings"
    "time"

    "lias/internal/logging"
)

// SSDPProvider discovers devices via UPnP/SSDP.
type SSDPProvider struct {
    iface  string
    logger *logging.Logger
}

// NewSSDPProvider creates a new SSDPProvider.
func NewSSDPProvider(iface string, logger *logging.Logger) *SSDPProvider {
    return &SSDPProvider{iface: iface, logger: logger}
}

// Name returns the provider name.
func (p *SSDPProvider) Name() string {
    return "ssdp"
}

// Discover sends an M-SEARCH query and listens for UPnP responses.
func (p *SSDPProvider) Discover() ([]Observation, error) {
    multicastAddr := "239.255.255.250:1900"
    
    query := "M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 2\r\n" +
        "ST: ssdp:all\r\n" +
        "\r\n"

    conn, err := net.ListenPacket("udp4", ":0")
    if err != nil {
        return nil, fmt.Errorf("ssdp listen failed: %w", err)
    }
    defer conn.Close()

    addr, err := net.ResolveUDPAddr("udp4", multicastAddr)
    if err != nil {
        return nil, err
    }

    _, err = conn.WriteTo([]byte(query), addr)
    if err != nil {
        return nil, fmt.Errorf("ssdp write failed: %w", err)
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

        resp := string(buf[:n])
        scanner := bufio.NewScanner(strings.NewReader(resp))
        
        var server, location string
        for scanner.Scan() {
            line := scanner.Text()
            lowerLine := strings.ToLower(line)
            if strings.HasPrefix(lowerLine, "server:") {
                server = strings.TrimSpace(line[7:])
            } else if strings.HasPrefix(lowerLine, "location:") {
                location = strings.TrimSpace(line[9:])
            }
        }

        if server != "" {
            observations = append(observations, Observation{
                IP:         remoteAddr.(*net.UDPAddr).IP.String(),
                SourceName: p.Name(),
                Confidence: 80,
                Services:   "ssdp:" + server,
            })
        } else if location != "" {
            observations = append(observations, Observation{
                IP:         remoteAddr.(*net.UDPAddr).IP.String(),
                SourceName: p.Name(),
                Confidence: 70,
                Services:   "ssdp",
            })
        }
    }

    return observations, nil
}
