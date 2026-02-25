package filter

import (
	"sync/atomic"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricsEnabled atomic.Bool

	BlockedRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisedge_blocked_requests_total",
			Help: "The total number of requests blocked by AegisEdge",
		},
		[]string{"layer", "reason"},
	)

	ActiveConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisedge_active_connections",
			Help: "The number of currently active proxied connections",
		},
	)

	RequestLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "aegisedge_request_duration_seconds",
			Help: "Time taken to process and proxy the request",
		},
		[]string{"method", "path"},
	)
)

func SetMetricsEnabled(v bool) {
	metricsEnabled.Store(v)
}

func MetricsEnabled() bool {
	return metricsEnabled.Load()
}
