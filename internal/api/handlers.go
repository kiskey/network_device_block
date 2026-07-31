package api

import (
    "net/http"
    "strconv"
    "time"

    "lias/internal/policy"
)

// handleGetLogs processes GET /api/logs?limit=100&mac=xx:xx
func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
    limitStr := r.URL.Query().Get("limit")
    limit := 100
    if limitStr != "" {
        if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
            limit = n
        }
    }
    
    mac := r.URL.Query().Get("mac")
    if mac != "" {
        mac = normalizeMAC(mac)
    }

    logs, err := s.db.GetLogs(limit, mac)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to fetch logs")
        return
    }
    writeJSON(w, http.StatusOK, logs)
}

// applyPoliciesImmediately is a helper called by mutation handlers to
// force the firewall sets to sync right away, providing instant feedback
// to the user without waiting for the 60-second scheduler tick.
func (s *Server) applyPoliciesImmediately() {
    desired, err := policy.ComputeDesiredState(s.db, time.Now())
    if err != nil {
        s.logger.Errorf("Immediate policy computation failed: %v", err)
        return
    }
    
    if err := s.fw.SyncBlockedMACs(desired.BlockMACs); err != nil {
        s.logger.Errorf("Immediate blocked sync failed: %v", err)
    }
    if err := s.fw.SyncOverrideMACs(desired.OverrideMACs); err != nil {
        s.logger.Errorf("Immediate override sync failed: %v", err)
    }
}

// normalizeMAC is a local helper to ensure MACs from URL paths are formatted correctly.
func normalizeMAC(mac string) string {
    // Reuse the database normalization logic to keep it DRY
    // In a real scenario, we might import a shared util package, 
    // but database.NormalizeMAC is exported and perfectly fine to use here.
    return database.NormalizeMAC(mac)
}

// unused import prevention if we remove database later
import (
    "lias/internal/database"
)
