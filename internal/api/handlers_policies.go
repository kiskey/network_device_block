package api

import (
    "encoding/json"
    "net/http"

    "lias/internal/database"
)

// handleGetPolicies processes GET /api/policies
func (s *Server) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
    policies, err := s.db.GetAllPolicies()
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to fetch policies")
        return
    }
    writeJSON(w, http.StatusOK, policies)
}

// handleGetGlobalPolicy processes GET /api/policies/global
func (s *Server) handleGetGlobalPolicy(w http.ResponseWriter, r *http.Request) {
    p, err := s.db.GetGlobalPolicy()
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to fetch global policy")
        return
    }
    writeJSON(w, http.StatusOK, p)
}

// handleUpdateGlobalPolicy processes PUT /api/policies/global
func (s *Server) handleUpdateGlobalPolicy(w http.ResponseWriter, r *http.Request) {
    var p database.Policy
    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
        writeError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    if err := s.db.SetGlobalPolicy(p.Mode, p.Enabled); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    s.applyPoliciesImmediately()
    s.db.InsertLog(database.LogCategoryPolicyChanged, "Updated global policy", "", p.Mode)

    updated, _ := s.db.GetGlobalPolicy()
    writeJSON(w, http.StatusOK, updated)
}

// handleGetDevicePolicy processes GET /api/policies/{mac}
func (s *Server) handleGetDevicePolicy(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    p, err := s.db.GetDevicePolicy(mac)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to fetch device policy")
        return
    }
    
    if p == nil {
        // Return the global policy if no override exists, so frontend knows the effective state
        p, _ = s.db.GetGlobalPolicy()
        p.MAC = mac // Indicate which device this applies to
    }

    writeJSON(w, http.StatusOK, p)
}

// handleUpdateDevicePolicy processes PUT /api/policies/{mac}
func (s *Server) handleUpdateDevicePolicy(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    var p database.Policy
    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
        writeError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    if err := s.db.SetDevicePolicy(mac, p.Mode, p.Enabled); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    s.applyPoliciesImmediately()
    s.db.InsertLog(database.LogCategoryPolicyChanged, "Updated device policy", mac, p.Mode)

    updated, _ := s.db.GetDevicePolicy(mac)
    writeJSON(w, http.StatusOK, updated)
}

// handleDeleteDevicePolicy processes DELETE /api/policies/{mac}
// Reverts the device to inheriting the global policy.
func (s *Server) handleDeleteDevicePolicy(w http.ResponseWriter, r *http.Request) {
    mac := normalizeMAC(r.PathValue("mac"))
    if mac == "" {
        writeError(w, http.StatusBadRequest, "Invalid MAC address")
        return
    }

    if err := s.db.DeleteDevicePolicy(mac); err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to delete device policy")
        return
    }

    // Also clean up any schedules associated with the old override policy
    // (The DB ON DELETE CASCADE handles this if the policy row is deleted,
    // but DeleteDevicePolicy only deletes by MAC. We should ensure cleanup.)
    // Note: The database layer's DeleteDevicePolicy deletes by MAC, so CASCADE works.

    s.applyPoliciesImmediately()
    s.db.InsertLog(database.LogCategoryPolicyChanged, "Removed device override, reverting to global", mac, "")

    writeJSON(w, http.StatusOK, map[string]string{"status": "reverted_to_global"})
}
