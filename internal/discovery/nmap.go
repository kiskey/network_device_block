// Package discovery (nmap.go) implements the NmapProvider.
// It executes nmap and parses the XML output for rich device metadata.
package discovery

import (
    "encoding/xml"
    "fmt"
    "os/exec"
    "strings"

    "lias/internal/database"
    "lias/internal/logging"
)

// NmapProvider runs nmap to discover devices and enrich metadata.
type NmapProvider struct {
    db     *database.DB
    logger *logging.Logger
}

// NewNmapProvider creates a new NmapProvider.
func NewNmapProvider(db *database.DB, logger *logging.Logger) *NmapProvider {
    return &NmapProvider{db: db, logger: logger}
}

// Name returns the provider name.
func (p *NmapProvider) Name() string {
    return "nmap"
}

// NmapXML represents the relevant parts of the nmap XML output.
type NmapXML struct {
    Hosts []NmapHost `xml:"host"`
}

type NmapHost struct {
    Status   NmapStatus   `xml:"status"`
    Addresses []NmapAddress `xml:"address"`
    Hostnames NmapHostnames `xml:"hostnames"`
    OS       NmapOS       `xml:"os"`
    Ports    NmapPorts    `xml:"ports"`
}

type NmapStatus struct {
    State string `xml:"state,attr"`
}

type NmapAddress struct {
    Addr     string `xml:"addr,attr"`
    AddrType string `xml:"addrtype,attr"`
    Vendor   string `xml:"vendor,attr"`
}

type NmapHostnames struct {
    Hostname []NmapHostname `xml:"hostname"`
}

type NmapHostname struct {
    Name string `xml:"name,attr"`
    Type string `xml:"type,attr"`
}

type NmapOS struct {
    OSMatch []NmapOSMatch `xml:"osmatch"`
}

type NmapOSMatch struct {
    Name     string `xml:"name,attr"`
    Accuracy string `xml:"accuracy,attr"`
}

type NmapPorts struct {
    Port []NmapPort `xml:"port"`
}

type NmapPort struct {
    PortID string `xml:"portid,attr"`
    Proto  string `xml:"protocol,attr"`
    State  struct {
        State string `xml:"state,attr"`
    } `xml:"state"`
    Service struct {
        Name string `xml:"name,attr"`
    } `xml:"service"`
}

// Discover executes the nmap command and parses the results.
func (p *NmapProvider) Discover() ([]Observation, error) {
    enabled, _ := p.db.GetBoolSetting("nmap_enabled", true)
    if !enabled {
        return nil, nil
    }

    subnet, _ := p.db.GetSetting("nmap_subnet")
    if subnet == "" {
        subnet = "192.168.1.0/24"
    }

    // Check if nmap is installed
    if _, err := exec.LookPath("nmap"); err != nil {
        p.logger.Warnf("Nmap binary not found in PATH. Skipping active discovery.")
        return nil, nil
    }

    // Execute nmap: -sn (ping scan), -PR (ARP scan), -PE (ICMP echo), -oX - (XML to stdout)
    cmd := exec.Command("nmap", "-sn", "-PR", "-PE", "-oX", "-", subnet)
    var out strings.Builder
    cmd.Stdout = &out
    
    if err := cmd.Run(); err != nil {
        return nil, fmt.Errorf("nmap execution failed: %w", err)
    }

    var nmapData NmapXML
    if err := xml.Unmarshal([]byte(out.String()), &nmapData); err != nil {
        return nil, fmt.Errorf("parse nmap xml: %w", err)
    }

    var observations []Observation

    for _, host := range nmapData.Hosts {
        if host.Status.State != "up" {
            continue
        }

        var mac, ip, vendor, hostname, osName string
        var services []string

        for _, addr := range host.Addresses {
            if addr.AddrType == "mac" {
                mac = addr.Addr
                vendor = addr.Vendor
            } else if addr.AddrType == "ipv4" {
                ip = addr.Addr
            }
        }

        // If we only found an IP but no MAC, we can't reliably track it in our DB
        if mac == "" {
            continue
        }

        if len(host.Hostnames.Hostname) > 0 {
            hostname = host.Hostnames.Hostname[0].Name
        }

        if len(host.OS.OSMatch) > 0 {
            osName = host.OS.OSMatch[0].Name
        }

        for _, port := range host.Ports.Port {
            if port.State.State == "open" {
                services = append(services, fmt.Sprintf("%s/%s", port.PortID, port.Service.Name))
            }
        }

        observations = append(observations, Observation{
            MAC:        mac,
            IP:         ip,
            Hostname:   hostname,
            Vendor:     vendor,
            OS:         osName,
            Services:   strings.Join(services, ","),
            SourceName: p.Name(),
            Confidence: 100, // Nmap is the highest confidence source
        })
    }

    p.logger.Debugf("Nmap discovered %d up hosts with MACs", len(observations))
    return observations, nil
}
