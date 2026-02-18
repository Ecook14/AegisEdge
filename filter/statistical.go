package filter

import (
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"
)

// StatisticalAnomalyDetector tracks overall request volume to detect spikes.
type StatisticalAnomalyDetector struct {
	mu           sync.RWMutex
	MovingAvg    float64
	WindowSize   int
	RequestCount int
	LastReset    time.Time
	Enabled      bool
}

func NewStatisticalAnomalyDetector(windowSeconds int) *StatisticalAnomalyDetector {
	return &StatisticalAnomalyDetector{
		WindowSize: windowSeconds,
		LastReset:  time.Now(),
		Enabled:    true,
	}
}

func (d *StatisticalAnomalyDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		d.mu.Lock()
		d.RequestCount++
		
		// Every window, update the moving average
		if time.Since(d.LastReset).Seconds() >= float64(d.WindowSize) {
			currentRPS := float64(d.RequestCount) / float64(d.WindowSize)
			
			// Simple Alpha-weighted moving average (0.1 for slow adaptation)
			if d.MovingAvg == 0 {
				d.MovingAvg = currentRPS
			} else {
				d.MovingAvg = (0.9 * d.MovingAvg) + (0.1 * currentRPS)
			}
			
			d.RequestCount = 0
			d.LastReset = time.Now()
			logger.Info("Statistical baseline updated", "rps_avg", d.MovingAvg)
		}

		// Check if current burst is anomalous (e.g. 5x the baseline)
		// This is a simplified demo of a "Pulse" check
		if d.MovingAvg > 5 && float64(d.RequestCount) > d.MovingAvg*10 {
			logger.Warn("Statistical Anomaly: Global traffic pulse detected", 
				"avg", d.MovingAvg, "current_burst", d.RequestCount)
			BlockedRequests.WithLabelValues("L7", "stat_anomaly").Inc()
			// We don't block everything, we might trigger "Challenge Mode" for all
		}
		
		d.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (d *StatisticalAnomalyDetector) SetEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Enabled = enabled
}
