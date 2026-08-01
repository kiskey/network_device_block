package discovery

import (
    "bufio"
    "fmt"
    "os"
    "regexp"
    "strings"

    "lias/internal/logging"
)

// DHCPProvider parses dhcpd.leases or dnsmasq.leases to find hostnames.
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
    return "dhcp"
}

// Discover parses the leases file. It gracefully handles missing files.
func (p *DHCPProvider) Discover() ([]Observation, error) {
    if p.path == "" {
        return nil, nil
    }

    file, err := os.Open(p.path)
    if err != nil {
        return nil, nil // Not fatal, just means no DHCP data available
    }
    defer file.Close()

    var obs []Observation
    
    // Try to detect format (ISC dhcpd vs dnsmasq)
    scanner := bufio.NewScanner(file)
    firstLine := ""
    if scanner.Scan() {
        firstLine = scanner.Text()
    }

    // Rewind
    _, _ = file.Seek(0, 0)
    scanner = bufio.NewScanner(file)

    if strings.HasPrefix(firstLine, "lease") {
        // ISC dhcpd format
        obs = p.parseISC(scanner)
    } else {
        // Assume dnsmasq format (MAC IP Hostname ClientID)
        obs = p.parseDnsmasq(scanner)
    }

    return obs, nil
}

func (p *DHCPProvider) parseISC(scanner *bufio.Scanner) []Observation {
    var obs []Observation
    var currentIP, currentMAC, currentHostname string

    macRegex := regexp.MustCompile(`hardware ethernet\s+([0-9a-fA-F:]+);`)
    hostRegex := regexp.MustCompile(`client-hostname\s+"([^"]+)";`)

    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())

        if strings.HasPrefix(line, "lease") {
            parts := strings.Fields(line)
            if len(parts) >= 2 {
                currentIP = strings.TrimSuffix(parts[1], "{")
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
            if currentMAC != "" {
                obs = append(obs, Observation{
                    MAC:        currentMAC,
                    IP:         currentIP,
                    Hostname:   currentHostname,
                    SourceName: p.Name(),
                    Confidence: 90, // High confidence for hostname
                })
            }
            currentIP = ""
            currentMAC = ""
            currentHostname = ""
        }
    }
    return obs
}

func (p *DHCPProvider) parseDnsmasq(scanner *bufio.Scanner) []Observation {
    var obs []Observation
    
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }
        
        parts := strings.Fields(line)
        if len(parts) >= 3 {
            mac := parts[0]
            ip := parts[1]
            hostname := parts[2]
            
            // Basic MAC validation
            if _, err := net.ParseMAC(mac); err == nil {
                obs = append(obs, Observation{
                    MAC:        mac,
                    IP:         ip,
                    Hostname:   hostname,
                    SourceName: p.Name(),
                    Confidence: 90,
                })
            }
        }
    }
    return obs
}

// unused import prevention
import (
    "net"
)
