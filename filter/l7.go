package filter

import (
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"
	"aegisedge/util"

	"golang.org/x/time/rate"
)


// L7Filter enforces per-IP Token Bucket rate limiting using golang.org/x/time/rate.
// Each IP gets its own bucket; stale entries are purged every 5 minutes.
type L7Filter struct {
	mu           sync.RWMutex
	limiters     map[string]*rate.Limiter
	lastSeen     map[string]time.Time
	DefaultRate  float64
	DefaultBurst int
	stop         chan struct{}
}

func NewL7Filter(rateLimit float64, burstLimit int, _ interface{}) *L7Filter {
	f := &L7Filter{
		limiters:     make(map[string]*rate.Limiter),
		lastSeen:     make(map[string]time.Time),
		DefaultRate:  rateLimit,
		DefaultBurst: burstLimit,
		stop:         make(chan struct{}),
	}
	go f.cleanupLoop()
	return f
}

func (f *L7Filter) Stop() {
	close(f.stop)
}

// getLimiter returns the token bucket limiter for a given IP, creating one if needed.
func (f *L7Filter) getLimiter(ip string) *rate.Limiter {
	f.mu.Lock()
	defer f.mu.Unlock()

	lim, exists := f.limiters[ip]
	if !exists {
		lim = rate.NewLimiter(rate.Limit(f.DefaultRate), f.DefaultBurst)
		f.limiters[ip] = lim
	}
	f.lastSeen[ip] = time.Now()
	return lim
}

// cleanupLoop removes stale IP limiters every 5 minutes to prevent unbounded memory growth.
func (f *L7Filter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f.mu.Lock()
			for ip, last := range f.lastSeen {
				if time.Since(last) > 10*time.Minute {
					delete(f.limiters, ip)
					delete(f.lastSeen, ip)
				}
			}
			f.mu.Unlock()
			logger.Info("L7 limiter: stale IP entries purged")
		case <-f.stop:
			return
		}
	}
}

func (f *L7Filter) Middleware(next http.Handler, rep *ReputationManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := util.GetRealIP(r)

		multiplier := 1.0

		limiter := f.getLimiter(host)

		// Apply reputation multiplier to the effective rate live.
		// SetLimit and SetBurst are concurrency-safe in golang.org/x/time/rate.
		if rep != nil {
			multiplier = rep.GetMultiplier(host)
			limiter.SetLimit(rate.Limit(f.DefaultRate * multiplier))
			limiter.SetBurst(int(float64(f.DefaultBurst) * multiplier))
		}

		if !limiter.AllowN(time.Now(), 1) {
			logger.Warn("L7 rate limit exceeded (token bucket)", "remote_addr", host,
				"effective_rate", f.DefaultRate*multiplier, "effective_burst", int(float64(f.DefaultBurst)*multiplier))

			if rep != nil {
				rep.Penalize(host)
			}

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
