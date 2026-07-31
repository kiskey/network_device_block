// Package database (models.go) defines the core data structures used
// throughout the application. These structs map directly to the SQLite
// database tables and are serialized to JSON for the API.
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
    Paused       bool    `json:"paused"` // v2.0.0: Temporary instant-block state
    Policy       *Policy `json:"policy,omitempty"`
}

// Policy represents either the global policy (MAC is empty) or a device override.
type Policy struct {
    ID        int64  `json:"id"`
    MAC       string `json:"mac"` // empty string for global policy
    Mode      string `json:"mode"`
    Enabled   bool   `json:"enabled"` // v2.0.0: For global, means "Global takes precedence". For device, means "Override is active".
    CreatedAt int64  `json:"created_at"`
    UpdatedAt int64  `json:"updated_at"`
}

// Schedule represents a time range for a specific day of the week.
type Schedule struct {
    ID         int64  `json:"id"`
    PolicyID   int64  `json:"policy_id"`
    DayOfWeek  int    `json:"day_of_week"` // 0=Sunday ... 6=Saturday
    StartTime  string `json:"start_time"`  // "HH:MM"
    EndTime    string `json:"end_time"`    // "HH:MM"
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

// Helper function to convert bool to int for SQLite
func boolToInt(b bool) int {
    if b {
        return 1
    }
    return 0
}
