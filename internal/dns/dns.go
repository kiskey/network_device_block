// Package dns provides reverse DNS (rDNS) resolution capabilities.
// It is used by the discovery layer to resolve hostnames for IP addresses
// found in the ARP table when DHCP or mDNS do not provide a hostname.
package dns

import (
    "context"
    "net"
    "strings"
    "time"
)

// Resolver wraps the standard Go resolver with a short timeout.
type Resolver struct {
    timeout time.Duration
}

// New creates a new DNS resolver with a 1-second timeout.
func New() *Resolver {
    return &Resolver{
        timeout: 1 * time.Second,
    }
}

// LookupAddr performs a reverse DNS lookup for the given IP address.
// Returns the hostname without a trailing dot, or an empty string if
// the lookup fails or times out.
func (r *Resolver) LookupAddr(ip string) string {
    if ip == "" {
        return ""
    }

    ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
    defer cancel()

    names, err := net.DefaultResolver.LookupAddr(ctx, ip)
    if err != nil || len(names) == 0 {
        return ""
    }

    // Strip the trailing dot added by standard DNS responses
    return strings.TrimSuffix(names[0], ".")
}
