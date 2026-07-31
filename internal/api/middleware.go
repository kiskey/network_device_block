package api

import (
    "crypto/hmac"
    "net/http"
)

// authMiddleware ensures the user is authenticated before proceeding.
func (s *Server) authMiddleware(next http.HandlerFunc) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !s.auth.IsAuthEnabled() {
            next(w, r)
            return
        }

        if !s.auth.ValidateSession(r) {
            writeError(w, http.StatusUnauthorized, "Unauthorized")
            return
        }
        next(w, r)
    })
}

// authMiddlewareHandler is a version that accepts an http.Handler for wrapping routers.
func (s *Server) authMiddlewareHandler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !s.auth.IsAuthEnabled() {
            next.ServeHTTP(w, r)
            return
        }

        if !s.auth.ValidateSession(r) {
            writeError(w, http.StatusUnauthorized, "Unauthorized")
            return
        }
        next.ServeHTTP(w, r)
    })
}

// csrfMiddleware ensures that unsafe HTTP methods (POST, PUT, DELETE, PATCH)
// include a valid CSRF token in the header that matches the CSRF cookie.
// This uses the Double Submit Cookie pattern.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Safe methods bypass CSRF check
        if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
            next.ServeHTTP(w, r)
            return
        }

        // If auth is completely disabled (first run setup), we might need to allow
        // the initial POST /api/login without CSRF, since we can't set the cookie beforehand.
        if r.URL.Path == "/api/login" {
            next.ServeHTTP(w, r)
            return
        }

        cookie, err := r.Cookie("csrf_token")
        if err != nil || cookie.Value == "" {
            writeError(w, http.StatusForbidden, "Missing CSRF cookie")
            return
        }

        headerToken := r.Header.Get("X-CSRF-Token")
        if headerToken == "" {
            writeError(w, http.StatusForbidden, "Missing CSRF header")
            return
        }

        // Constant time comparison to prevent timing attacks
        if !hmac.Equal([]byte(cookie.Value), []byte(headerToken)) {
            writeError(w, http.StatusForbidden, "CSRF token mismatch")
            return
        }

        next.ServeHTTP(w, r)
    })
}

// setCSRFCookie is a helper that can be called on successful auth to provide
// the frontend with the CSRF token to use in subsequent requests.
func (s *Server) setCSRFCookie(w http.ResponseWriter) {
    token := generateRandomString(32)
    http.SetCookie(w, &http.Cookie{
        Name:     "csrf_token",
        Value:    token,
        Path:     "/",
        HttpOnly: false, // Must be readable by JavaScript
        Secure:   false,
        SameSite: http.SameSiteStrictMode,
    })
}
