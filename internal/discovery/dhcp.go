package discovery

import (
    "bufio"
    "fmt"
    "os"
    "regexp"
    "strings"

    "lias/internal/logging"
)

// DHCPProvider parses the dhcpd.leases file to find hostnames and IPs.
type DHCPProvider struct {
    path   string
    logger *logging.Logger
}

// NewDHCPProvider creates a new DHCP leases discovery source.
func NewDHCPProvider(path string, logger *logging.Logger) *DHCPProvider {
    return &DHCPProvider{path: path, logger: logger}
}

// Name returns the provider name.
func (p *DHCPProvider) Name() string {
    return "DHCP Leases"
}

// Discover parses the leases file. It gracefully handles missing files.
func (p *DHCPProvider) Discover() ([]DeviceInfo, error) {
    file, err := os.Open(p.path)
    if err != nil {
        // Not fatal, just means no DHCP data available
        p.logger.Debugf("DHCP leases file %s not accessible: %v", p.path, err)
        return nil, nil
    }
    defer file.Close()

    var devices []DeviceInfo
    var currentIP string
    var currentMAC string
    var currentHostname string

    // Regex to match "hardware ethernet aa:bb:cc:dd:ee:ff;"
    macRegex := regexp.MustCompile(`hardware ethernet\s+([0-9a-fA-F:]+);`)
    // Regex to match "client-hostname "name";"
    hostRegex := regexp.MustCompile(`client-hostname\s+"([^"]+)";`)

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())

        if strings.HasPrefix(line, "lease") {
            // New lease block starts
            parts := strings.Fields(line)
            if len(parts) >= 2 {
                currentIP = strings.TrimSuffix(parts[1], "{")
                currentIP = strings.TrimSpace(currentIP)
            }
            currentMAC = ""
            currentHostname = ""
        } else if strings.HasPrefix(line, "hardware ethernet") {
            matches := macRegex.FindStringSubmatch(line)
            if len(matches) == 2 {
                currentMAC = matches[1]
            }
        } else if strings.HasPrefix(line, "client-hostname") {
            matches := hostRegex.FindStringSubmatch(line)
            if len(matches) == 2 {
                currentHostname = matches[1]
            }
        } else if line == "}" {
            // End of lease block
            if currentMAC != "" {
                devices = append(devices, DeviceInfo{
                    MAC:      currentMAC,
                    IP:       currentIP,
                    Hostname: currentHostname,
                })
            }
            currentIP = ""
            currentMAC = ""
            currentHostname = ""
        }
    }

    if err := scanner.Err(); err != nil {
        return nil, fmt.Errorf("scan leases file: %w", err)
    }

    p.logger.Debugf("DHCP found %d leases", len(devices))
    return devices, nil
}
