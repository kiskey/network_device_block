package api

import (
    "encoding/json"
    "net/http"
    "strconv"

    "lias/internal/database"
)

// handleGetGlobalSchedules processes GET /api/schedules/global
func (s *Server) handleGetGlobalSchedules(w http.ResponseWriter, r *http.Request) {
    global, err := s.db.GetGlobalPolicy()
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to get global policy")
        return
    }

    schedules, err := s.db.GetSchedulesByPolicy(global.ID)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to fetch schedules")
        return
    }
    writeJSON(w, http.StatusOK, schedules)
}

// handleAddGlobalSchedule processes POST /api/schedules/global
func (s *Server) handleAddGlobalSchedule(w http.ResponseWriter, r *http.Request) {
    var sched database.Schedule
    if err := json.NewDecoder(r.Body).Decode(&sched); err != nil {
        writeError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    global, err := s.db.GetGlobalPolicy()
    if err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to get global policy")
        return
    }

    sched.PolicyID = global.ID
    id, err := s.db.AddSchedule(sched.PolicyID, sched.DayOfWeek, sched.StartTime, sched.EndTime, sched.Enabled)
    if err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    s.applyPoliciesImmediately()
    s.db.InsertLog(database.LogCategoryScheduleApplied, "Added global schedule", "", "")

    sched.ID = id
    writeJSON(w, http.StatusCreated, sched)
}

// handleUpdateSchedule processes PUT /api/schedules/{id}
func (s *Server) handleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
    idStr := r.PathValue("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        writeError(w, http.StatusBadRequest, "Invalid schedule ID")
        return
    }

    var sched database.Schedule
    if err := json.NewDecoder(r.Body).Decode(&sched); err != nil {
        writeError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    if err := s.db.UpdateSchedule(id, sched.DayOfWeek, sched.StartTime, sched.EndTime, sched.Enabled); err != nil {
        writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    s.applyPoliciesImmediately()
    s.db.InsertLog(database.LogCategoryScheduleApplied, "Updated schedule", "", "")

    sched.ID = id
    writeJSON(w, http.StatusOK, sched)
}

// handleDeleteSchedule processes DELETE /api/schedules/{id}
func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
    idStr := r.PathValue("id")
    id, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        writeError(w, http.StatusBadRequest, "Invalid schedule ID")
        return
    }

    if err := s.db.DeleteSchedule(id); err != nil {
        writeError(w, http.StatusInternalServerError, "Failed to delete schedule")
        return
    }

    s.applyPoliciesImmediately()
    s.db.InsertLog(database.LogCategoryScheduleRemoved, "Deleted schedule", "", "")

    writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
