package filter

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"aegisedge/logger"
	"aegisedge/store"
)

// AnomalyDetector tracks request patterns to identify stealthy attacks.
type AnomalyDetector struct {
	HeavyURLs map[string]bool
	Threshold int
	store     store.Storer
}

func NewAnomalyDetector(heavyURLs []string, threshold int, s store.Storer) *AnomalyDetector {
	heavyMap := make(map[string]bool)
	for _, url := range heavyURLs {
		heavyMap[url] = true
	}
	return &AnomalyDetector{
		HeavyURLs: heavyMap,
		Threshold: threshold,
		store:     s,
	}
}

func (d *AnomalyDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		path := r.URL.Path

		// Unified Anomaly Detection
		key := fmt.Sprintf("anomaly:stats:%s:%s", host, path)
		count, err := d.store.Increment(key, 10*time.Minute)
		if err == nil {
			if d.HeavyURLs[path] && int(count) > d.Threshold {
				logger.Warn("Anomaly detected: High frequency on heavy URL",
					"remote_addr", host, "path", path, "count", count)
				BlockedRequests.WithLabelValues("L7", "anomaly_heavy_url").Inc()
				http.Error(w, "Anomalous traffic detected", http.StatusTooManyRequests)
				return
			}

			// Entropy Analysis: Detects behavior where a client repeatedly accesses a single resource,
			// which is characteristic of certain automated tools.
			entropyKey := "anomaly:entropy:" + host
			entropyCount, _ := d.store.Increment(entropyKey, 1*time.Minute)
			if int(entropyCount) > d.Threshold*3 {
				logger.Warn("Anomaly detected: Behavioral lock-on", "remote_addr", host)
				BlockedRequests.WithLabelValues("L7", "low_entropy").Inc()
				http.Error(w, "Access Denied: Anomalous behavioral pattern", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
