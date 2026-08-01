// Package discovery (nbns.go) implements a pure-Go NetBIOS Name Service (NBNS) provider.
// v3.2.0: Fixed broadcast socket permissions using SO_BROADCAST.
package discovery

import (
    "context"
    "fmt"
    "net"
    "syscall"
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
    broadcastAddr := "255.255.255.255:137"
    
    query := []byte{
        0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
        0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
        0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x00, 0x00, 0x20,
        0x00, 0x01,
    }

    // Must use SO_BROADCAST to send to 255.255.255.255
    lc := net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            var sockOptErr error
            err := c.Control(func(fd uintptr) {
                sockOptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
            })
            if err != nil {
                return err
            }
            return sockOptErr
        },
    }
    
    conn, err := lc.ListenPacket(context.Background(), "udp4", ":0")
    if err != nil {
        return nil, fmt.Errorf("nbns listen failed: %w", err)
    }
    defer conn.Close()

    addr, err := net.ResolveUDPAddr("udp4", broadcastAddr)
    if err != nil {
        return nil, err
    }

    _, err = conn.WriteTo(query, addr)
    if err != nil {
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

        if n > 56 {
            nameBytes := buf[56 : 56+15]
            name := string(nameBytes)
            name = fmt.Sprintf("%-15s", name)
            name = name[:15]
            
            if name != "" && name != "               " {
                observations = append(observations, Observation{
                    IP:         remoteAddr.(*net.UDPAddr).IP.String(),
                    Hostname:   name,
                    SourceName: p.Name(),
                    Confidence: 90,
                    Services:   "nbns",
                })
            }
        }
    }

    return observations, nil
}
