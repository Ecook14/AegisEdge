package filter

import (
	"net"
	"net/http"

	"aegisedge/logger"
	"github.com/oschwald/geoip2-golang"
)

type GeoIPFilter struct {
	db *geoip2.Reader
	blockedCountries map[string]bool
}

func NewGeoIPFilter(dbPath string, blockedCountries []string) *GeoIPFilter {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		logger.Warn("GeoIP filter bypassed: Database file not found", "path", dbPath, "tip", "Download GeoLite2-Country.mmdb from MaxMind to enable country blocking")
	}

	bc := make(map[string]bool)
	for _, c := range blockedCountries {
		bc[c] = true
	}

	return &GeoIPFilter{
		db: db,
		blockedCountries: bc,
	}
}

func (f *GeoIPFilter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		
		if f.db != nil && ip != nil {
			record, err := f.db.Country(ip)
			if err == nil {
				if f.blockedCountries[record.Country.IsoCode] {
					logger.Warn("Blocked request from unauthorized country", "remote_addr", host, "country", record.Country.IsoCode)
					BlockedRequests.WithLabelValues("L7", "geoip").Inc()
					http.Error(w, "Access Denied: Country Restricted", http.StatusForbidden)
					return
				}
			}
		}
		
		next.ServeHTTP(w, r)
	})
}
