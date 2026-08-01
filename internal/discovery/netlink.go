// Package discovery (netlink.go) implements the NetlinkProvider.
// It reads the kernel neighbor table for real-time, low-overhead device presence.
package discovery

import (
    "fmt"
    "net"

    "lias/internal/logging"

    "github.com/vishvananda/netlink"
)

// NetlinkProvider uses the netlink library to read the kernel neighbor table.
type NetlinkProvider struct {
    iface  string
    logger *logging.Logger
}

// NewNetlinkProvider creates a new NetlinkProvider.
func NewNetlinkProvider(iface string, logger *logging.Logger) *NetlinkProvider {
    return &NetlinkProvider{iface: iface, logger: logger}
}

// Name returns the provider name.
func (p *NetlinkProvider) Name() string {
    return "netlink"
}

// Discover reads the neighbor table and extracts MAC/IP pairs.
func (p *NetlinkProvider) Discover() ([]Observation, error) {
    iface, err := net.InterfaceByName(p.iface)
    if err != nil {
        return nil, fmt.Errorf("get interface %s: %w", p.iface, err)
    }

    neighs, err := netlink.NeighList(iface.Index, netlink.FAMILY_V4)
    if err != nil {
        return nil, fmt.Errorf("list neighbors: %w", err)
    }

    var obs []Observation
    for _, n := range neighs {
        if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 || n.IP == nil {
            continue
        }

        mac := n.HardwareAddr.String()
        ip := n.IP.String()

        obs = append(obs, Observation{
            MAC:        mac,
            IP:         ip,
            Hostname:   "", // Netlink doesn't provide hostnames
            SourceName: p.Name(),
            Confidence: 80, // High confidence for presence, low for metadata
        })
    }

    return obs, nil
}
