package api

import (
    "encoding/json"
    "net/http"

    "lias/internal/database"
)

// handleGetDevices processes GET /api/devices
func (s *Server) handleGetDevices(w http.ResponseWriter, r *http.Request) {
    devices, err := s.db.GetAllDevices()
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to fetch devices")
        return
    }
    writeJSON(w, http.StatusOK, devices)
}

// handleGetDevice processes GET /api/devices/{mac}
func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    device, err := s.db.GetDevice(mac)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Database error")
        return
    }
    if device == nil {
        writeError(w, http.StatusNotFound, "Device not found")
        return
    }

    // Attach current effective policy to the device payload for UI convenience
    policy, _ := s.db.GetEffectivePolicy(mac)
    if policy != nil {
        device.Policy = policy
    }

    writeJSON(w, http.StatusOK, device)
}

// handleUpdateDevice processes PUT /api/devices/{mac}
// Currently only supports updating the friendly_name.
func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    var payload struct {
        FriendlyName string `json:"friendly_name"`
    }
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        writeError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    if err := s.db.SetDeviceFriendlyName(mac, payload.FriendlyName); err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to update device")
        return
    }

    s.db.InsertLog(database.LogCategoryManualToggle, "Updated device friendly name", mac, payload.FriendlyName)
    
    device, _ := s.db.GetDevice(mac)
    writeJSON(w, http.StatusOK, device)
}

// handleDeleteDevice processes DELETE /api/devices/{mac}
func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    if err := s.db.DeleteDevice(mac); err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to delete device")
        return
    }

    s.applyPoliciesImmediately()
    s.db.InsertLog(database.LogCategoryManualToggle, "Deleted device and policy", mac, "")

    writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleToggleDevice processes POST /api/devices/{mac}/toggle
// Provides an instant internet on/off switch. 
// If currently allowed (or unknown), it blocks. If currently blocked, it allows.
func (s *Server) handleToggleDevice(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    // Check if device exists, if not, create a stub record so it can be blocked later
    dev, _ := s.db.GetDevice(mac)
    if dev == nil {
        // Upsert with empty data just to register the MAC for the toggle
        s.db.UpsertDevice(mac, "Unknown Device", "", "", false)
    }

    effPolicy, err := s.db.GetEffectivePolicy(mac)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to get effective policy")
        return
    }

    var newMode string
    if effPolicy.Mode == database.ModeBlockAlways {
        newMode = database.ModeAllowAlways
    } else {
        newMode = database.ModeBlockAlways
    }

    // Apply as an override
    if err := s.db.SetDevicePolicy(mac, newMode, true); err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to set policy")
        return
    }

    s.applyPoliciesImmediately()
    
    action := "Internet disabled"
    if newMode == database.ModeAllowAlways {
        action = "Internet enabled"
    }
    s.db.InsertLog(database.LogCategoryManualToggle, action, mac, "")

    writeJSON(w, http.StatusOK, map[string]string{"status": "toggled", "new_mode": newMode})
}
