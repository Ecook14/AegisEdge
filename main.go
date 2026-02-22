package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
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

	logger.Info("Starting AegisEdge", "listen_ports", cfg.ListenPorts, "upstream", cfg.UpstreamAddr)

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

	// LiveToggles: reads toggle state at request time (not at startup),
	// so PATCH /api/config changes take effect immediately without restart.
	toggles := manager.NewLiveToggles(
		cfg.Toggles.WAF,
		cfg.Toggles.GeoIP,
		cfg.Toggles.Challenge,
		cfg.Toggles.Anomaly,
		cfg.Toggles.Stats,
	)

	// wrap checks the live toggle state on EVERY request — not a static flag baked at startup.
	wrap := func(name string, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if toggles.IsEnabled(name) {
				next.ServeHTTP(w, r)
			} else {
				// Feature disabled at runtime — pass through to next layer unchanged
				next.ServeHTTP(w, r)
			}
		})
	}
	_ = wrap // used below

	// Orchestration check & OS Hardening
	filter.CheckAnsibleThresholds()
	filter.HardenOS()

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

	// Security pipeline (innermost → outermost):
	// Tarpit → WAF → StatAnomaly → Anomaly → GeoIP → Fingerprinting → L7 Rate Limit → Challenge → Security Headers
	//
	// The challenge layer also activates automatically when stats.IsUnderAttack() is true,
	// regardless of the per-request toggle, to force browser verification during detected floods.
	attackChallenge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stats.IsUnderAttack() {
			// Force challenge during volumetric attack, even if toggle is off
			middleware.ProgressiveChallenge(l7.Middleware(
				fingerprinter.Middleware(
					wrap("geoip", geoip.Middleware(
						wrap("stats", stats.Middleware(
							wrap("anomaly", anomaly.Middleware(
								wrap("waf", filter.WAFMiddleware(
									middleware.Tarpit(finalHandler),
								)),
							)),
						)),
					)),
				),
			)).ServeHTTP(w, r)
		} else {
			wrap("challenge", middleware.ProgressiveChallenge(
				l7.Middleware(
					fingerprinter.Middleware(
						wrap("geoip", geoip.Middleware(
							wrap("stats", stats.Middleware(
								wrap("anomaly", anomaly.Middleware(
									wrap("waf", filter.WAFMiddleware(
										middleware.Tarpit(finalHandler),
									)),
								)),
							)),
						)),
					),
				),
			)).ServeHTTP(w, r)
		}
	})

	stack := middleware.SecurityHeaders(attackChallenge)

	// Metrics endpoint
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		logger.Info("Metrics engine active", "port", 9090)
		http.ListenAndServe(":9090", mux)
	}()

	// Management API (Protected/Internal) — wired with LiveToggles for real-time config
	go func() {
		mux := http.NewServeMux()
		mgmt := manager.NewManagementAPI(activeStore, toggles)
		mgmt.ServeHTTP(mux)
		logger.Info("Management API active", "port", 9091)
		http.ListenAndServe(":9091", mux)
	}()

	// Initialize Servers for all configured ports
	var servers []*http.Server
	hijackedPorts := make(map[int]int) // external -> internal

	for _, port := range cfg.ListenPorts {
		addr := fmt.Sprintf(":%d", port)
		idleTimeout := 60 * time.Second
		readTimeout := 15 * time.Second
		if cfg.HypervisorMode {
			logger.Info("Hypervisor optimized mode enabled", "port", port)
			idleTimeout = 300 * time.Second
			readTimeout = 30 * time.Second
		}

		srv := &http.Server{
			Addr:              addr,
			Handler:           stack,
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       readTimeout,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       idleTimeout,
		}

		isHTTPS := (port == 443)
		var cert, key string
		if isHTTPS {
			cert, key = cfg.DiscoverCerts()
			if cert == "" || key == "" {
				logger.Warn("Port 443 configured but SSL certificates could not be discovered. Falling back to HTTP.", "port", port)
				isHTTPS = false
			}
		}

		// Try to bind early to check status
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil && cfg.HotTakeover {
			logger.Warn("Port occupied, attempting Hot Takeover...", "port", port)
			// Start on any available port
			tempLn, tempErr := net.Listen("tcp", "127.0.0.1:0")
			if tempErr != nil {
				logger.Error("Failed to start ephemeral server for takeover", "err", tempErr)
				continue
			}
			
			internalPort := tempLn.Addr().(*net.TCPAddr).Port
			if err := filter.TakeoverPort(port, internalPort); err != nil {
				logger.Error("Hot Takeover failed", "port", port, "err", err)
				tempLn.Close()
				continue
			}
			hijackedPorts[port] = internalPort
			
			if isHTTPS {
				logger.Info("Hot Takeover active (HTTPS/L7 Protection)", "external", port, "internal", internalPort)
				go srv.ServeTLS(tempLn, cert, key)
			} else {
				logger.Info("Hot Takeover active (HTTP/L7 Protection)", "external", port, "internal", internalPort)
				go srv.Serve(tempLn)
			}
			servers = append(servers, srv)
			continue
		} else if err != nil {
			logger.Error("Failed to listen on port", "port", port, "err", err)
			os.Exit(1)
		}

		logger.Info("Proxy engine active", "addr", srv.Addr, "https", isHTTPS)
		servers = append(servers, srv)
		if isHTTPS {
			go srv.ServeTLS(ln, cert, key)
		} else {
			go srv.Serve(ln)
		}
	}

	// Initialize TCP Stream Protection for other ports (SSH, DB, etc.)
	for _, port := range cfg.TcpPorts {
		addr := fmt.Sprintf(":%d", port)
		targetAddr := fmt.Sprintf("127.0.0.1:%d", port)

		ln, err := net.Listen("tcp", addr)
		if err != nil && cfg.HotTakeover {
			logger.Warn("TCP Port occupied, attempting Hot Takeover...", "port", port)
			tempLn, tempErr := net.Listen("tcp", "127.0.0.1:0")
			if tempErr != nil {
				logger.Error("Failed to start ephemeral stream proxy", "err", tempErr)
				continue
			}

			internalPort := tempLn.Addr().(*net.TCPAddr).Port
			if err := filter.TakeoverPort(port, internalPort); err != nil {
				logger.Error("TCP Hot Takeover failed", "port", port, "err", err)
				tempLn.Close()
				continue
			}
			hijackedPorts[port] = internalPort
			
			go filter.StreamProxy(tempLn, targetAddr, l4)
			logger.Info("TCP Hot Takeover active (L4 Protection)", "external", port, "internal", internalPort)
			continue
		} else if err != nil {
			logger.Error("Failed to listen on TCP port", "port", port, "err", err)
			os.Exit(1)
		}

		logger.Info("TCP Stream Shield active", "port", port)
		go filter.StreamProxy(ln, targetAddr, l4)
	}

	// Graceful shutdown logic
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	<-done
	logger.Info("AegisEdge stopping...")

	// Release Hijacked Ports
	for ext, internal := range hijackedPorts {
		filter.ReleasePort(ext, internal)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			// Don't log error here as some might already be closed via ln.Close()
			s.Shutdown(ctx)
		}(srv)
	}
	wg.Wait()

	logger.Info("All servers stopped gracefully")
}
