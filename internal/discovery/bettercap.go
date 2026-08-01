// Package discovery (bettercap.go) implements a provider that queries
// a local Bettercap REST API instance for rich, passive device metadata.
package discovery

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "lias/internal/logging"
)

// BettercapProvider queries a Bettercap API endpoint.
type BettercapProvider struct {
    apiURL string
    logger *logging.Logger
    client *http.Client
}

// NewBettercapProvider creates a new BettercapProvider.
func NewBettercapProvider(logger *logging.Logger) *BettercapProvider {
    return &BettercapProvider{
        apiURL: "http://127.0.0.1:8081/api/session/", // Default Bettercap API endpoint
        logger: logger,
        client: &http.Client{Timeout: 5 * time.Second},
    }
}

// Name returns the provider name.
func (p *BettercapProvider) Name() string {
    return "bettercap"
}

// BettercapSession represents the JSON structure returned by Bettercap's API.
type BettercapSession struct {
    Session struct {
        Hosts []BettercapHost `json:"hosts"`
    } `json:"session"`
}

// BettercapHost represents a single device discovered by Bettercap.
type BettercapHost struct {
    IP       string `json:"ip"`
    MAC      string `json:"mac"`
    Vendor   string `json:"vendor"`
    Hostname string `json:"hostname"`
    Meta     struct {
        MdnsName  string `json:"mdns.name"`
        MdnsQuery string `json:"mdns.query"`
    } `json:"meta"`
}

// Discover queries the Bettercap API and maps the results to Observations.
func (p *BettercapProvider) Discover() ([]Observation, error) {
    resp, err := p.client.Get(p.apiURL)
    if err != nil {
        // Fail silently if Bettercap is not running
        return nil, nil 
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("bettercap api returned status %d", resp.StatusCode)
    }

    var session BettercapSession
    if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
        return nil, fmt.Errorf("parse bettercap json: %w", err)
    }

    var observations []Observation
    
    for _, host := range session.Session.Hosts {
        if host.MAC == "" {
            continue
        }

        // Prefer mDNS name if available, otherwise use standard hostname
        hostname := host.Hostname
        if host.Meta.MdnsName != "" {
            hostname = host.Meta.MdnsName
        }

        // Build a services string from mDNS queries
        services := ""
        if host.Meta.MdnsQuery != "" {
            services = "mdns:" + host.Meta.MdnsQuery
        }

        observations = append(observations, Observation{
            MAC:        host.MAC,
            IP:         host.IP,
            Hostname:   hostname,
            Vendor:     host.Vendor,
            Services:   services,
            SourceName: p.Name(),
            Confidence: 98, // Bettercap's passive sniffing is extremely reliable
        })
    }

    p.logger.Debugf("Bettercap discovered %d hosts", len(observations))
    return observations, nil
}
