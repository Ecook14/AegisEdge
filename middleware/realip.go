package middleware

import (
	"net"
	"net/http"
	"strings"

	"aegisedge/util"
)

// RealIP middleware resolves the true client IP from trusted proxy headers.
// Priority: CF-Connecting-IP → X-Real-IP → X-Forwarded-For → RemoteAddr.
//
// The watcher's trusted list is read atomically on every request — no restart
// required when CSF/iptables/cPHulk lists change.
func RealIP(watcher *util.ProxyWatcher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r, watcher)
			next.ServeHTTP(w, util.SetRealIP(r, ip))
		})
	}
}

// GetRealIP is a convenience wrapper for use within the middleware package.
func GetRealIP(r *http.Request) string {
	return util.GetRealIP(r)
}

func extractIP(r *http.Request, watcher *util.ProxyWatcher) string {
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Only honour forwarded headers when the immediate connection is from
	// a trusted proxy in the live CSF/iptables/cPHulk whitelist.
	if watcher == nil || !watcher.IsTrusted(remoteHost) {
		return remoteHost
	}

	// 1. Cloudflare — single authoritative header, no parsing ambiguity.
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		if ip := net.ParseIP(strings.TrimSpace(cf)); ip != nil {
			return ip.String()
		}
	}

	// 2. Standard nginx / AWS ALB
	if real := r.Header.Get("X-Real-IP"); real != "" {
		if ip := net.ParseIP(strings.TrimSpace(real)); ip != nil {
			return ip.String()
		}
	}

	// 3. X-Forwarded-For — leftmost value is the original client.
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
			return ip.String()
		}
	}

	return remoteHost
}
