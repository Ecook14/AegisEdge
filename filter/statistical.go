package filter

import (
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"
)

// StatisticalAnomalyDetector tracks overall request volume to detect volumetric spikes.
// When a burst exceeds 10× the established EMA baseline, it enters "attack mode"
// and the IsUnderAttack() flag gates the challenge middleware in main.go.
type StatisticalAnomalyDetector struct {
	mu           sync.RWMutex
	MovingAvg    float64
	WindowSize   int
	RequestCount int
	LastReset    time.Time
	Enabled      bool
	underAttack  bool
	attackClears int // consecutive calm windows needed to clear attack mode
}

func NewStatisticalAnomalyDetector(windowSeconds int) *StatisticalAnomalyDetector {
	return &StatisticalAnomalyDetector{
		WindowSize: windowSeconds,
		LastReset:  time.Now(),
		Enabled:    true,
	}
}

// IsUnderAttack is safe for concurrent reads and is checked by main.go
// to force-enable the browser challenge for all incoming traffic.
func (d *StatisticalAnomalyDetector) IsUnderAttack() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.underAttack
}

func (d *StatisticalAnomalyDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		d.mu.Lock()
		d.RequestCount++

		if time.Since(d.LastReset).Seconds() >= float64(d.WindowSize) {
			currentRPS := float64(d.RequestCount) / float64(d.WindowSize)

			// Exponential Moving Average (α=0.1 for smooth baseline)
			if d.MovingAvg == 0 {
				d.MovingAvg = currentRPS
			} else {
				d.MovingAvg = (0.9 * d.MovingAvg) + (0.1 * currentRPS)
			}

			// Volumetric anomaly: burst > 10× the established baseline (baseline > 5 RPS to avoid cold-start false positives)
			if d.MovingAvg > 5 && currentRPS > d.MovingAvg*10 {
				if !d.underAttack {
					logger.Warn("⚠️  VOLUMETRIC ATTACK DETECTED — forcing challenge mode for all traffic",
						"baseline_rps", d.MovingAvg, "burst_rps", currentRPS)
					BlockedRequests.WithLabelValues("L7", "stat_anomaly").Inc()
				}
				d.underAttack = true
				d.attackClears = 0
			} else if d.underAttack {
				// Require 3 consecutive calm windows before lifting attack mode
				d.attackClears++
				if d.attackClears >= 3 {
					d.underAttack = false
					d.attackClears = 0
					logger.Info("✅  Traffic normalized — lifting forced challenge mode", "baseline_rps", d.MovingAvg)
				}
			}

			d.RequestCount = 0
			d.LastReset = time.Now()
			logger.Info("Statistical RPS baseline updated", "rps_avg", d.MovingAvg, "under_attack", d.underAttack)
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
