package filter

import (
	"bytes"
	"io"
	"net/http"
	"regexp"

	"aegisedge/logger"
)

var (
	// Expanded SQLi: looking for tautologies, comments, and dangerous keywords
	sqliRegex = regexp.MustCompile(`(?i)(union.*select|insert.*into|drop.*table|delete.*from|update.*set|' or '1'='1|--|/\*|;.*--|exec\(|sp_executesql|information_schema|sysdatabases|waitfor delay)`)
	
	// Expanded XSS: looking for event handlers, javascript pseudo-protocol, and script tags
	xssRegex = regexp.MustCompile(`(?i)(<script|alert\(|onerror=|onload=|onmouseover=|javascript:|eval\(|unescape\(|String\.fromCharCode|<iframe|document\.(cookie|location)|window\.(location|open)|src=.*javascript:)`)
	
	// Command Injection: looking for shell operators and dangerous commands
	cmdInjRegex = regexp.MustCompile(`(?i)(;|\||&&|>|<|\x60|\$\(.*\)|python|perl|bash|sh|cmd|powershell|curl|wget|nc -e|/bin/sh|/bin/bash)`)
	
	// Path Traversal and Sensitive File Access
	traversal = regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/windows/system32|boot\.ini|windows/win\.ini|/var/www/html/.*\.env)`)
)

func WAFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Scan Query Parameters and Path
		query := r.URL.RawQuery
		path := r.URL.Path

		// 2. Scan Body (POST/PUT only, capped at 4KB to prevent memory exhaustion)
		var bodySample string
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			buf := make([]byte, 4096)
			n, _ := io.ReadFull(r.Body, buf)
			if n > 0 {
				bodySample = string(buf[:n])
				// Restore body so proxy can still read it
				r.Body = struct {
					io.Reader
					io.Closer
				}{
					Reader: io.MultiReader(bytes.NewReader(buf[:n]), r.Body),
					Closer: r.Body,
				}
			}
		}

		// Combined check
		payloads := []string{query, path, bodySample}

		for _, p := range payloads {
			if p == "" {
				continue
			}

			if sqliRegex.MatchString(p) {
				logger.Warn("Blocked SQLi attempt", "remote_addr", r.RemoteAddr, "payload", p)
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "sqli").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}

			if xssRegex.MatchString(p) {
				logger.Warn("Blocked XSS attempt", "remote_addr", r.RemoteAddr, "payload", p)
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "xss").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}

			if cmdInjRegex.MatchString(p) {
				logger.Warn("Blocked Command Injection attempt", "remote_addr", r.RemoteAddr, "payload", p)
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "cmd_injection").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}

			if traversal.MatchString(p) {
				logger.Warn("Blocked path traversal attempt", "remote_addr", r.RemoteAddr, "payload", p)
				if MetricsEnabled() {
					BlockedRequests.WithLabelValues("L7", "traversal").Inc()
				}
				http.Error(w, "Malicious request detected", http.StatusBadRequest)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
