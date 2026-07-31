package discovery

import (
    "fmt"
    "net"
    "strings"

    "lias/internal/logging"

    "github.com/vishvananda/netlink"
)

// ARPProvider uses the netlink library to read the kernel neighbor table.
type ARPProvider struct {
    iface  string
    logger *logging.Logger
}

// NewARPProvider creates a new ARP discovery source.
func NewARPProvider(iface string, logger *logging.Logger) *ARPProvider {
    return &ARPProvider{iface: iface, logger: logger}
}

// Name returns the provider name.
func (p *ARPProvider) Name() string {
    return "ARP/Netlink"
}

// Discover reads the neighbor table and extracts MAC/IP pairs.
func (p *ARPProvider) Discover() ([]DeviceInfo, error) {
    // Get the interface index to filter neighbors
    iface, err := net.InterfaceByName(p.iface)
    if err != nil {
        return nil, fmt.Errorf("get interface %s: %w", p.iface, err)
    }

    // Fetch neighbors for the specific interface
    neighs, err := netlink.NeighList(iface.Index, netlink.FAMILY_V4)
    if err != nil {
        return nil, fmt.Errorf("list neighbors: %w", err)
    }

    var devices []DeviceInfo
    for _, n := range neighs {
        // Skip entries without a MAC address (e.g. incomplete entries)
        if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 {
            continue
        }

        mac := n.HardwareAddr.String()
        ip := ""
        if n.IP != nil {
            ip = n.IP.String()
        }

        // State 2 = REACHABLE, 4 = DELAY, 8 = PROBE, 16 = STALE
        // We include any entry that has a MAC, but true "online" status is
        // ultimately determined by the LastSeen timestamp in the DB.
        if mac != "" && ip != "" {
            devices = append(devices, DeviceInfo{
                MAC:      mac,
                IP:       ip,
                Hostname: "", // ARP doesn't provide hostnames
            })
        }
    }

    p.logger.Debugf("ARP found %d neighbors", len(devices))
    return devices, nil
}

// unused import prevention
var _ = strings.TrimSpace
