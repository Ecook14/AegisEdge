package filter

import (
	"net"
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"
)

// AnomalyDetector tracks request patterns to identify stealthy attacks.
type AnomalyDetector struct {
	HeavyURLs      map[string]bool
	IPStats        map[string]*IPTrafficStats
	Threshold      int
	mu             sync.Mutex
}

type IPTrafficStats struct {
	URLCounts    map[string]int
	LastSeen     time.Time
}

func NewAnomalyDetector(heavyURLs []string, threshold int) *AnomalyDetector {
	heavyMap := make(map[string]bool)
	for _, url := range heavyURLs {
		heavyMap[url] = true
	}
	return &AnomalyDetector{
		HeavyURLs: heavyMap,
		IPStats:   make(map[string]*IPTrafficStats),
		Threshold: threshold,
	}
}

func (d *AnomalyDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		path := r.URL.Path

		d.mu.Lock()
		stats, ok := d.IPStats[host]
		if !ok {
			stats = &IPTrafficStats{
				URLCounts: make(map[string]int),
				LastSeen:  time.Now(),
			}
			d.IPStats[host] = stats
		}
		
		stats.URLCounts[path]++
		stats.LastSeen = time.Now()
		
		// Anomaly Detection Logic
		if d.HeavyURLs[path] && stats.URLCounts[path] > d.Threshold {
			logger.Warn("Anomaly detected: High frequency on heavy URL", 
				"remote_addr", host, "path", path, "count", stats.URLCounts[path])
			
			// If it's too high, we don't just rate limit, we tarpit or block
			BlockedRequests.WithLabelValues("L7", "anomaly_heavy_url").Inc()
			http.Error(w, "Anomalous traffic detected", http.StatusTooManyRequests)
			d.mu.Unlock()
			return
		}
		
		// Detecting "No Entropy" behavior (hammering exactly one resource)
		if len(stats.URLCounts) == 1 && stats.URLCounts[path] > d.Threshold*2 {
			logger.Warn("Anomaly detected: Zero-entropy behavior", "remote_addr", host)
			BlockedRequests.WithLabelValues("L7", "low_entropy").Inc()
			http.Error(w, "Access Denied: Non-human pattern", http.StatusForbidden)
			d.mu.Unlock()
			return
		}
		
		d.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}
