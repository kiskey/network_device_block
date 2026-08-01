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

    // Attach policy to each device for UI convenience
    for i := range devices {
        p, _ := s.db.GetEffectivePolicy(devices[i].MAC)
        devices[i].Policy = p
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

    policy, _ := s.db.GetEffectivePolicy(mac)
    device.Policy = policy

    writeJSON(w, http.StatusOK, device)
}

// handleUpdateDevice processes PUT /api/devices/{mac}
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
func (s *Server) handleToggleDevice(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    dev, _ := s.db.GetDevice(mac)
    if dev == nil {
        obs := database.DeviceObservation{
            MAC:        mac,
            Hostname:   "Unknown Device",
            Confidence: 0,
        }
        if err := s.db.UpsertDevice(obs); err != nil {
            writeError(w, http.StatusInternalServerError, "Failed to create device")
            return
        }
        dev, _ = s.db.GetDevice(mac)
    }

    // Prevent pausing infrastructure devices
    if dev.IsInfrastructure {
        writeError(w, http.StatusBadRequest, "Cannot pause an infrastructure device")
        return
    }

    newPaused := !dev.Paused
    if err := s.db.SetDevicePaused(mac, newPaused); err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to toggle pause state")
        return
    }

    s.applyPoliciesImmediately()

    action := "Internet resumed"
    if newPaused {
        action = "Internet paused"
    }
    s.db.InsertLog(database.LogCategoryManualToggle, action, mac, "")

    writeJSON(w, http.StatusOK, map[string]bool{"paused": newPaused})
}

// v4.0.0: handleToggleInfrastructure processes POST /api/devices/{mac}/infrastructure
func (s *Server) handleToggleInfrastructure(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    var payload struct {
        Enabled bool `json:"enabled"`
    }
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        // If body is empty, just toggle the existing state
        dev, _ := s.db.GetDevice(mac)
        if dev == nil {
            writeError(w, http.StatusNotFound, "Device not found")
            return
        }
        payload.Enabled = !dev.IsInfrastructure
    }

    if err := s.db.SetDeviceInfrastructure(mac, payload.Enabled); err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to update infrastructure status")
        return
    }

    // If we just made it infrastructure, ensure it's not left in a paused state
    if payload.Enabled {
        _ = s.db.SetDevicePaused(mac, false)
    }

    s.applyPoliciesImmediately()

    action := "Removed from Infrastructure (Never Block) zone"
    if payload.Enabled {
        action = "Added to Infrastructure (Never Block) zone"
    }
    s.db.InsertLog(database.LogCategoryPolicyChanged, action, mac, "")

    writeJSON(w, http.StatusOK, map[string]bool{"is_infrastructure": payload.Enabled})
}
