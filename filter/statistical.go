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
			
			// Exponential Moving Average (EMA) for RPS tracking.
			if d.MovingAvg == 0 {
				d.MovingAvg = currentRPS
			} else {
				d.MovingAvg = (0.9 * d.MovingAvg) + (0.1 * currentRPS)
			}
			
			d.RequestCount = 0
			d.LastReset = time.Now()
			logger.Info("Statistical RPS baseline updated", "rps_avg", d.MovingAvg)
		}

		// Baseline comparison logic. 
		// If current burst significantly exceeds the moving average, it indicates a volumetric anomaly.
		if d.MovingAvg > 5 && float64(d.RequestCount) > d.MovingAvg*10 {
			logger.Warn("Statistical Anomaly: Volumetric traffic peak detected", 
				"avg", d.MovingAvg, "current_burst", d.RequestCount)
			BlockedRequests.WithLabelValues("L7", "stat_anomaly").Inc()
			// Further action: Trigger defensive posture (e.g., CAPTCHA challenge for all traffic).
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
