// Package ui embeds the web frontend files (HTML, CSS, JS) into the Go binary
// using go:embed. This ensures the application remains a single statically
// linked binary with no external file dependencies.
package ui

import (
    "embed"
    "io/fs"
    "net/http"
    "strings"
)

//go:embed all:web
var webFS embed.FS

// Handler returns an http.Handler that serves the embedded web UI.
// It implements a fallback to index.html for Single Page Application (SPA)
// routing, though the current UI uses a simple vanilla JS approach.
func Handler() http.Handler {
    // Subdir to strip the "web/" prefix from the embedded paths
    subFS, err := fs.Sub(webFS, "web")
    if err != nil {
        panic(err)
    }

    fileServer := http.FileServer(http.FS(subFS))

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        path := strings.TrimPrefix(r.URL.Path, "/")
        
        // If the path has an extension, try to serve the static file directly.
        // If it doesn't exist, return 404.
        if strings.Contains(path, ".") {
            if _, err := fs.Stat(subFS, path); err != nil {
                http.NotFound(w, r)
                return
            }
        }

        // For all other paths (routes), serve index.html
        if path == "" || !strings.Contains(path, ".") {
            r.URL.Path = "/"
        }

        fileServer.ServeHTTP(w, r)
    })
}
