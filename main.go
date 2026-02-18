package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aegisedge/filter"
	"aegisedge/logger"
	"aegisedge/manager"
	"aegisedge/middleware"
	"aegisedge/proxy"
	"aegisedge/store"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		logger.Error("Failed to load config", "err", err)
		os.Exit(1)
	}

	logger.Info("Starting AegisEdge", "listen_port", cfg.ListenPort, "upstream", cfg.UpstreamAddr)

	// Initialize Storage (Local with Redis upgrade)
	var activeStore store.Storer = store.NewLocalStore()
	redisAddr := os.Getenv("AEGISEDGE_REDIS_ADDR")
	if redisAddr != "" {
		activeStore = store.NewRedisStore(redisAddr, os.Getenv("AEGISEDGE_REDIS_PASSWORD"))
		logger.Info("Distributed state initialized (Redis)", "addr", redisAddr)
	} else {
		logger.Info("In-memory state initialized (Local fallback)")
	}

	// Initialize Filters
	l3 := filter.NewL3Filter(cfg.L3Blacklist)
	l4 := filter.NewL4Filter(cfg.L4ConnLimit, 5*time.Minute, activeStore)
	l7 := filter.NewL7Filter(cfg.L7RateLimit, cfg.L7BurstLimit, activeStore)
	geoip := filter.NewGeoIPFilter(cfg.GeoIPDBPath, cfg.BlockedCountries)
	fingerprinter := filter.NewFingerprinter()
	anomaly := filter.NewAnomalyDetector([]string{"/search", "/api/heavy-export"}, 20, activeStore)
	stats := filter.NewStatisticalAnomalyDetector(60)

	// Dynamic Toggle Wrapper
	wrap := func(name string, enabled bool, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the filter is enabled in the current configuration.
			if enabled {
				next.ServeHTTP(w, r)
			} else {
				// Bypass
				next.ServeHTTP(w, r)
			}
		})
	}

	// Orchestration check
	filter.CheckAnsibleThresholds()

	// Initialize Proxy
	p, err := proxy.NewReverseProxy(cfg.UpstreamAddr)
	if err != nil {
		logger.Error("Failed to initialize proxy", "err", err)
		os.Exit(1)
	}

	// Combined Handler
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		
		// Layer 3 (Centralized Block Check)
		if activeStore.IsBlocked(host) {
			filter.BlockedRequests.WithLabelValues("L3", "active_block").Inc()
			http.Error(w, "Access Denied (Active Block)", http.StatusForbidden)
			return
		}

		if l3.IsBlacklisted(host) {
			filter.BlockedRequests.WithLabelValues("L3", "blacklist").Inc()
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		// Layer 4
		if !l4.AllowConnection(r.RemoteAddr) {
			filter.BlockedRequests.WithLabelValues("L4", "conn_limit").Inc()
			http.Error(w, "Too many connections", http.StatusServiceUnavailable)
			return
		}
		defer l4.ReleaseConnection(r.RemoteAddr)

		filter.ActiveConnections.Inc()
		defer filter.ActiveConnections.Dec()

		timer := prometheus.NewTimer(filter.RequestLatency.WithLabelValues(r.Method, r.URL.Path))
		defer timer.ObserveDuration()

		p.ServeHTTP(w, r)
	})

	// Carry out the security pipeline:
	// Tarpit -> WAF -> StatAnomaly -> Anomaly -> GeoIP -> Fingerprinting -> L7 Rate Limit -> Challenge -> Security Headers
	stack := middleware.SecurityHeaders(
		wrap("challenge", cfg.Toggles.Challenge, middleware.ProgressiveChallenge(
			l7.Middleware(
				fingerprinter.Middleware(
					wrap("geoip", cfg.Toggles.GeoIP, geoip.Middleware(
						wrap("stats", cfg.Toggles.Stats, stats.Middleware(
							wrap("anomaly", cfg.Toggles.Anomaly, anomaly.Middleware(
								wrap("waf", cfg.Toggles.WAF, filter.WAFMiddleware(
									middleware.Tarpit(finalHandler),
								)),
							)),
						)),
					)),
				),
			),
		)),
	)

	// Metrics endpoint
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		logger.Info("Metrics engine active", "port", 9090)
		http.ListenAndServe(":9090", mux)
	}()

	// Management API (Protected/Internal)
	go func() {
		mux := http.NewServeMux()
		mgmt := manager.NewManagementAPI(activeStore)
		mgmt.ServeHTTP(mux)
		logger.Info("Management API active", "port", 9091)
		http.ListenAndServe(":9091", mux)
	}()

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.ListenPort),
		Handler:           stack,
		ReadHeaderTimeout: 2 * time.Second, // Kill Slowloris attacks early
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown logic
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-done
	logger.Info("Server stopping...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Shutdown failed", "err", err)
	}

	logger.Info("Server stopped gracefully")
}
