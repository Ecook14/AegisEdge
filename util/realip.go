// Package util provides shared helpers used across filter and middleware packages.
// It must NOT import aegisedge/filter or aegisedge/middleware to avoid import cycles.
package util

import (
	"context"
	"net"
	"net/http"
)

// ctxKey is an unexported type for context keys scoped to this package.
type ctxKey string

// RealIPKey is the context key under which the resolved client IP is stored.
const RealIPKey ctxKey = "real_ip"

// SetRealIP stores a resolved IP into the request context.
// Called by the RealIP middleware in the middleware package.
func SetRealIP(r *http.Request, ip string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), RealIPKey, ip))
}

// GetRealIP retrieves the resolved client IP from the request context.
// Falls back to r.RemoteAddr (with port stripped) if not present.
func GetRealIP(r *http.Request) string {
	if ip, ok := r.Context().Value(RealIPKey).(string); ok && ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
