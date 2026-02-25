// Package util provides shared helpers used across filter and middleware packages.
// It must NOT import aegisedge/filter or aegisedge/middleware to avoid import cycles.
package util

import (
	//"context"
	"net"
	"net/http"
)

// SetRealIP stores a resolved IP into the request headers to avoid context allocations.
func SetRealIP(r *http.Request, ip string) *http.Request {
	r.Header.Set("X-Aegis-Real-IP", ip)
	return r
}

// GetRealIP retrieves the resolved client IP from the request headers.
func GetRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Aegis-Real-IP"); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
