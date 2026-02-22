package filter

import (
	"net"
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"

	"golang.org/x/time/rate"
)

// ipLimiter holds a token bucket limiter per IP along with the last time it was seen.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// L7Filter enforces per-IP Token Bucket rate limiting using golang.org/x/time/rate.
// Each IP gets its own bucket; stale entries are purged every 5 minutes.
type L7Filter struct {
	rate    rate.Limit
	burst   int
	mu      sync.Mutex
	clients map[string]*ipLimiter
}

func NewL7Filter(r float64, b int, _ interface{}) *L7Filter {
	f := &L7Filter{
		rate:    rate.Limit(r),
		burst:   b,
		clients: make(map[string]*ipLimiter),
	}
	go f.cleanupLoop()
	return f
}

// getLimiter returns the token bucket limiter for a given IP, creating one if needed.
func (f *L7Filter) getLimiter(ip string) *rate.Limiter {
	f.mu.Lock()
	defer f.mu.Unlock()

	entry, exists := f.clients[ip]
	if !exists {
		lim := rate.NewLimiter(f.rate, f.burst)
		f.clients[ip] = &ipLimiter{limiter: lim, lastSeen: time.Now()}
		return lim
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// cleanupLoop removes stale IP limiters every 5 minutes to prevent unbounded memory growth.
func (f *L7Filter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		f.mu.Lock()
		for ip, entry := range f.clients {
			if time.Since(entry.lastSeen) > 10*time.Minute {
				delete(f.clients, ip)
			}
		}
		f.mu.Unlock()
		logger.Info("L7 limiter: stale IP entries purged")
	}
}

func (f *L7Filter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)

		limiter := f.getLimiter(host)
		if !limiter.Allow() {
			logger.Warn("L7 rate limit exceeded (token bucket)", "remote_addr", host,
				"rate", float64(f.rate), "burst", f.burst)
			BlockedRequests.WithLabelValues("L7", "rate_limit").Inc()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Reject headless clients with no User-Agent
		if r.Header.Get("User-Agent") == "" {
			BlockedRequests.WithLabelValues("L7", "no_user_agent").Inc()
			http.Error(w, "Plain bot requests are not allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
