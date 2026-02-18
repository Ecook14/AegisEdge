package filter

import (
	"net"
	"net/http"
	"strings"

	"aegisedge/logger"
)

type GeoIPFilter struct {
	BlockedRanges []*net.IPNet
}

func NewGeoIPFilter(blocked []string) *GeoIPFilter {
	var ranges []*net.IPNet
	for _, b := range blocked {
		// Handle both single IPs and CIDR ranges
		if !strings.Contains(b, "/") {
			if strings.Count(b, ".") == 3 {
				b += "/32"
			} else if strings.Count(b, ":") >= 2 {
				b += "/128"
			}
		}
		
		_, ipnet, err := net.ParseCIDR(b)
		if err == nil {
			ranges = append(ranges, ipnet)
		} else {
			logger.Error("Failed to parse blocked range", "range", b, "err", err)
		}
	}
	return &GeoIPFilter{BlockedRanges: ranges}
}

func (f *GeoIPFilter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		
		if f.isBlockedRegion(ip) {
			logger.Warn("Blocked request from unauthorized region", "remote_addr", host)
			BlockedRequests.WithLabelValues("L7", "geoip").Inc()
			http.Error(w, "Access Denied: Region Restricted", http.StatusForbidden)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (f *GeoIPFilter) isBlockedRegion(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, block := range f.BlockedRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
