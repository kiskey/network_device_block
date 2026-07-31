package api

import (
    "database/sql"
    "net/http"
    "strings"
    "time"

    "lias/internal/database"
    "lias/internal/logging"
    "golang.org/x/crypto/bcrypt"
)

const (
    SessionCookieName = "lias_session"
    SessionDuration   = 24 * time.Hour
)

// Auth manages user credentials and session validation.
type Auth struct {
    db     *database.DB
    logger *logging.Logger
}

// NewAuth creates a new Auth manager.
func NewAuth(db *database.DB, logger *logging.Logger) *Auth {
    return &Auth{db: db, logger: logger}
}

// IsAuthEnabled checks if password authentication is required.
func (a *Auth) IsAuthEnabled() bool {
    val, _ := a.db.GetSetting("auth_enabled")
    return val != "false" // Enabled by default
}

// VerifyPassword checks the provided plaintext password against the stored hash.
func (a *Auth) VerifyPassword(password string) bool {
    hash, err := a.db.GetSetting("auth_password_hash")
    if err != nil {
        a.logger.Errorf("Failed to get password hash: %v", err)
        return false
    }
    
    // If no password is set, consider it first-run setup (allow access to set password)
    if hash == "" {
        return true
    }

    err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// SetPassword updates the password hash in the database.
func (a *Auth) SetPassword(password string) error {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }
    return a.db.SetSetting("auth_password_hash", string(hash))
}

// CreateSession generates a signed session token and sets the cookie.
// Format: base64(username|expiresAt)|hmac
func (a *Auth) CreateSession(w http.ResponseWriter, username string) {
    expiresAt := time.Now().Add(SessionDuration).Unix()
    data := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%d", username, expiresAt)))
    
    secret, _ := a.db.GetSetting("session_secret")
    if secret == "" {
        secret = generateRandomString(32)
        _ = a.db.SetSetting("session_secret", secret)
    }

    mac := computeHMAC(data, secret)
    token := data + "." + mac

    http.SetCookie(w, &http.Cookie{
        Name:     SessionCookieName,
        Value:    token,
        Path:     "/",
        HttpOnly: true,
        Secure:   false, // Set to true if HTTPS is enforced
        SameSite: http.SameSiteStrictMode,
        Expires:  time.Unix(expiresAt, 0),
    })
}

// ValidateSession checks the request for a valid session cookie.
func (a *Auth) ValidateSession(r *http.Request) bool {
    if !a.IsAuthEnabled() {
        return true
    }

    cookie, err := r.Cookie(SessionCookieName)
    if err != nil {
        return false
    }

    parts := strings.SplitN(cookie.Value, ".", 2)
    if len(parts) != 2 {
        return false
    }

    data := parts[0]
    mac := parts[1]

    secret, _ := a.db.GetSetting("session_secret")
    if secret == "" {
        return false
    }

    expectedMac := computeHMAC(data, secret)
    if !hmac.Equal([]byte(mac), []byte(expectedMac)) {
        return false
    }

    decoded, err := base64.StdEncoding.DecodeString(data)
    if err != nil {
        return false
    }

    strData := string(decoded)
    strParts := strings.SplitN(strData, "|", 2)
    if len(strParts) != 2 {
        return false
    }

    expiresAt, err := strconv.ParseInt(strParts[1], 10, 64)
    if err != nil {
        return false
    }

    if time.Now().Unix() > expiresAt {
        return false
    }

    return true
}

// ClearSession expires the session cookie.
func (a *Auth) ClearSession(w http.ResponseWriter) {
    http.SetCookie(w, &http.Cookie{
        Name:     SessionCookieName,
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        MaxAge:   -1,
    })
}

// handleLogin processes POST /api/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Password string `json:"password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
        writeError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    // If no password is set, this is the first run. Set the password.
    hash, _ := s.db.GetSetting("auth_password_hash")
    if hash == "" {
        if len(creds.Password) < 6 {
            writeError(w, http.StatusBadRequest, "Password must be at least 6 characters")
            return
        }
        if err := s.auth.SetPassword(creds.Password); err != nil {
            writeError(w, http.StatusInternalServerError, "Failed to set password")
            return
        }
        s.auth.CreateSession(w, "admin")
        writeJSON(w, http.StatusOK, map[string]string{"status": "password_set"})
        return
    }

    if !s.auth.VerifyPassword(creds.Password) {
        s.db.InsertLog(database.LogCategoryAuth, "Failed login attempt", "", "")
        writeError(w, http.StatusUnauthorized, "Invalid password")
        return
    }

    s.auth.CreateSession(w, "admin")
    s.db.InsertLog(database.LogCategoryAuth, "Successful login", "", "")
    writeJSON(w, http.StatusOK, map[string]string{"status": "logged_in"})
}

// handleLogout processes POST /api/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
    s.auth.ClearSession(w)
    writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// handleAuthStatus processes GET /api/auth/status
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
    hash, _ := s.db.GetSetting("auth_password_hash")
    
    status := map[string]interface{}{
        "auth_enabled": s.auth.IsAuthEnabled(),
        "password_set": hash != "",
        "authenticated": s.auth.ValidateSession(r),
    }
    writeJSON(w, http.StatusOK, status)
}

// unused imports
import (
    "encoding/json"
    "fmt"
    "strconv"
)
var _ = sql.ErrNoRows
