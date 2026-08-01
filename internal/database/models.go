// Package database (models.go) defines the core data structures.
// v4.0.0: Adds IsInfrastructure flag for the "Never Block" zone.
package database

// Device represents a discovered LAN device.
type Device struct {
    MAC          string  `json:"mac"`
    Hostname     string  `json:"hostname"`
    FriendlyName string  `json:"friendly_name"`
    Vendor       string  `json:"vendor"`
    CurrentIP    string  `json:"current_ip"`
    Online       bool    `json:"online"`
    FirstSeen    int64   `json:"first_seen"`
    LastSeen     int64   `json:"last_seen"`
    Paused       bool    `json:"paused"`
    Policy       *Policy `json:"policy,omitempty"`

    // v4.0.0: Immutable Infrastructure flag
    IsInfrastructure bool `json:"is_infrastructure"`

    // v3.0.0 Device Intelligence Fields
    DeviceType       string `json:"device_type"`
    Manufacturer     string `json:"manufacturer"`
    OS               string `json:"os"`
    Services         string `json:"services"`
    DiscoverySources string `json:"discovery_sources"`
    Confidence       int    `json:"confidence"`
}

// Policy represents either the global policy (MAC is empty) or a device override.
type Policy struct {
    ID        int64  `json:"id"`
    MAC       string `json:"mac"`
    Mode      string `json:"mode"`
    Enabled   bool   `json:"enabled"`
    CreatedAt int64  `json:"created_at"`
    UpdatedAt int64  `json:"updated_at"`
}

// Schedule represents a time range for a specific day of the week.
type Schedule struct {
    ID         int64  `json:"id"`
    PolicyID   int64  `json:"policy_id"`
    DayOfWeek  int    `json:"day_of_week"`
    StartTime  string `json:"start_time"`
    EndTime    string `json:"end_time"`
    Enabled    bool   `json:"enabled"`
    CreatedAt  int64  `json:"created_at"`
    UpdatedAt  int64  `json:"updated_at"`
}

// LogEntry represents an audit log record.
type LogEntry struct {
    ID        int64  `json:"id"`
    Timestamp int64  `json:"timestamp"`
    Category  string `json:"category"`
    Message   string `json:"message"`
    MAC       string `json:"mac"`
    Details   string `json:"details"`
}

// Setting represents a key-value configuration pair.
type Setting struct {
    Key       string `json:"key"`
    Value     string `json:"value"`
    UpdatedAt int64  `json:"updated_at"`
}

func boolToInt(b bool) int {
    if b {
        return 1
    }
    return 0
}
