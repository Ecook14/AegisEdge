package filter

import (
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"
	"aegisedge/notifier"
)

// StatisticalAnomalyDetector tracks overall request volume to detect volumetric spikes.
// When a burst exceeds 10× the established EMA baseline, it enters "attack mode"
// and the IsUnderAttack() flag gates the challenge middleware in main.go.
type StatisticalAnomalyDetector struct {
	mu           sync.RWMutex
	MeanRPS      float64
	VarianceRPS  float64
	WindowSize   int
	RequestCount int
	LastReset    time.Time
	Enabled      bool
	underAttack  bool
	attackClears int
}

func NewStatisticalAnomalyDetector(windowSeconds int) *StatisticalAnomalyDetector {
	return &StatisticalAnomalyDetector{
		WindowSize: windowSeconds,
		LastReset:  time.Now(),
		Enabled:    true,
	}
}

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

			// Welford's Algorithm for online mean and variance (α=0.1 EMA approximation)
			if d.MeanRPS == 0 {
				d.MeanRPS = currentRPS
			} else {
				delta := currentRPS - d.MeanRPS
				d.MeanRPS += 0.1 * delta
				// Update variance with EMA logic
				d.VarianceRPS = (0.9 * d.VarianceRPS) + (0.1 * delta * (currentRPS - d.MeanRPS))
			}

			// Compute true standard deviation from the tracked variance.
			// VarianceRPS is maintained via an EMA-weighted Welford approximation.
			// We use a floor of 1.0 to avoid zero variance on dormant/static sites.
			stdDev := math.Sqrt(d.VarianceRPS)
			if stdDev < 1.0 {
				stdDev = 1.0
			}

			// Z-Score Detection: trigger when currentRPS > Mean + 3*Sigma.
			// Hard floor of 10 RPS prevents false-positives on traffic-less sites.
			threshold := d.MeanRPS + (3 * stdDev)
			if threshold < 10 {
				threshold = 10
			}

			if currentRPS > threshold {
				if !d.underAttack {
					logger.Warn("⚠️  STATISTICAL ANOMALY DETECTED (Z-Score) — forcing global challenge mode",
						"rps", currentRPS, "mean", d.MeanRPS, "threshold", threshold)
					notifier.SendAlert(fmt.Sprintf("VOLUMETRIC ATTACK DETECTED: RPS hit %.2f (3-Sigma Threshold: %.2f)", currentRPS, threshold), "CRITICAL")
					BlockedRequests.WithLabelValues("L7", "stat_anomaly").Inc()
				}
				d.underAttack = true
				d.attackClears = 0
			} else if d.underAttack {
				d.attackClears++
				if d.attackClears >= 3 {
					d.underAttack = false
					d.attackClears = 0
					logger.Info("✅  Traffic normalized — lifting forced challenge mode", "mean_rps", d.MeanRPS)
				}
			}

			d.RequestCount = 0
			d.LastReset = time.Now()
			logger.Info("Baseline updated", "mean", d.MeanRPS, "under_attack", d.underAttack)
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
