// Package api implements the HTTP/HTTPS web server, REST API endpoints,
// and serves the embedded web UI.
package api

import (
    "context"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "net/http"
    "time"

    "lias/internal/database"
    "lias/internal/firewall"
    "lias/internal/logging"
    "lias/internal/ui"
)

// ServerConfig holds configuration for the API server.
type ServerConfig struct {
    ListenAddr   string
    HTTPSEnabled bool
    HTTPSCert    string
    HTTPSKey     string
}

// Server represents the API and Web UI server.
type Server struct {
    db          *database.DB
    fw          *firewall.Firewall
    cfg         ServerConfig
    logger      *logging.Logger
    mux         *http.ServeMux
    httpServer  *http.Server
    auth        *Auth
}

// NewServer initializes the API server and registers all routes.
func NewServer(db *database.DB, fw *firewall.Firewall, cfg ServerConfig, logger *logging.Logger) *Server {
    s := &Server{
        db:     db,
        fw:     fw,
        cfg:    cfg,
        logger: logger,
        mux:    http.NewServeMux(),
    }

    s.auth = NewAuth(db, logger)
    
    if secret, _ := db.GetSetting("session_secret"); secret == "" {
        newSecret := generateRandomString(32)
        _ = db.SetSetting("session_secret", newSecret)
    }

    s.registerRoutes()
    return s
}

// registerRoutes maps URLs to handler functions.
func (s *Server) registerRoutes() {
    // Auth routes
    s.mux.HandleFunc("POST /api/login", s.handleLogin)
    s.mux.Handle("POST /api/logout", s.authMiddleware(s.handleLogout))
    s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)

    // API routes
    api := http.NewServeMux()
    
    // Dashboard
    api.HandleFunc("GET /api/dashboard", s.handleGetDashboard)
    
    // Devices
    api.HandleFunc("GET /api/devices", s.handleGetDevices)
    api.HandleFunc("GET /api/devices/{mac}", s.handleGetDevice)
    api.HandleFunc("PUT /api/devices/{mac}", s.handleUpdateDevice)
    api.HandleFunc("DELETE /api/devices/{mac}", s.handleDeleteDevice)
    api.HandleFunc("POST /api/devices/{mac}/toggle", s.handleToggleDevice)
    
    // v4.0.0: Infrastructure Tagging Route
    api.HandleFunc("POST /api/devices/{mac}/infrastructure", s.handleToggleInfrastructure)
    
    // Policies
    api.HandleFunc("GET /api/policies", s.handleGetPolicies)
    api.HandleFunc("GET /api/policies/global", s.handleGetGlobalPolicy)
    api.HandleFunc("PUT /api/policies/global", s.handleUpdateGlobalPolicy)
    api.HandleFunc("GET /api/policies/{mac}", s.handleGetDevicePolicy)
    api.HandleFunc("PUT /api/policies/{mac}", s.handleUpdateDevicePolicy)
    api.HandleFunc("DELETE /api/policies/{mac}", s.handleDeleteDevicePolicy)
    
    // Schedules
    api.HandleFunc("GET /api/schedules/global", s.handleGetGlobalSchedules)
    api.HandleFunc("POST /api/schedules/global", s.handleAddGlobalSchedule)
    api.HandleFunc("GET /api/policies/{mac}/schedules", s.handleGetDeviceSchedules)
    api.HandleFunc("POST /api/policies/{mac}/schedules", s.handleAddDeviceSchedule)
    api.HandleFunc("PUT /api/schedules/{id}", s.handleUpdateSchedule)
    api.HandleFunc("DELETE /api/schedules/{id}", s.handleDeleteSchedule)
    
    // Logs
    api.HandleFunc("GET /api/logs", s.handleGetLogs)

    // Wrap API routes with Auth and CSRF middleware
    s.mux.Handle("/api/", s.csrfMiddleware(s.authMiddleware(api.ServeHTTP)))

    // Serve embedded UI
    s.mux.Handle("/", ui.Handler())
}

// Start begins listening for HTTP/HTTPS requests.
func (s *Server) Start() error {
    s.httpServer = &http.Server{
        Addr:         s.cfg.ListenAddr,
        Handler:      s.mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    if s.cfg.HTTPSEnabled {
        s.logger.Infof("Starting HTTPS server on %s", s.cfg.ListenAddr)
        return s.httpServer.ListenAndServeTLS(s.cfg.HTTPSCert, s.cfg.HTTPSKey)
    }
    
    s.logger.Infof("Starting HTTP server on %s", s.cfg.ListenAddr)
    return s.httpServer.ListenAndServe()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
    if s.httpServer != nil {
        return s.httpServer.Shutdown(ctx)
    }
    return nil
}

// Helper functions
func generateRandomString(length int) string {
    b := make([]byte, length)
    _, _ = rand.Read(b)
    return base64.StdEncoding.EncodeToString(b)
}

func computeHMAC(data string, secret string) string {
    h := hmac.New(sha256.New, []byte(secret))
    h.Write([]byte(data))
    return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func writeJSON(w http.ResponseWriter, code int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    if payload != nil {
        json.NewEncoder(w).Encode(payload)
    }
}

func writeError(w http.ResponseWriter, code int, msg string) {
    writeJSON(w, code, map[string]string{"error": msg})
}
