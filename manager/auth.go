package manager

import (
	"net/http"
	"os"
	"strings"

	"aegisedge/logger"
)

// APIKeyAuth returns middleware that gates all management API requests
// behind a Bearer token. If AEGISEDGE_API_KEY is not set, the middleware
// is a transparent passthrough (backward compatible).
func APIKeyAuth(next http.Handler) http.Handler {
	apiKey := os.Getenv("AEGISEDGE_API_KEY")
	if apiKey == "" {
		return next // No auth configured — run open
	}

	logger.Info("Management API authentication enabled (Bearer token)")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		if auth == "" {
			http.Error(w, `{"error": "Authorization header required"}`, http.StatusUnauthorized)
			return
		}

		// Expect "Bearer <key>"
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] != apiKey {
			logger.Warn("Management API: invalid auth attempt", "remote_addr", r.RemoteAddr)
			http.Error(w, `{"error": "Invalid API key"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
