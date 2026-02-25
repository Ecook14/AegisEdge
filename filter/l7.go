package filter

import (
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"
	"aegisedge/util"

	"golang.org/x/time/rate"
)


const numShards = 64

type limiterEntry struct {
	limiter    *rate.Limiter
	multiplier float64
	lastUpdate time.Time
}

type shard struct {
	mu       sync.RWMutex
	limiters map[string]*limiterEntry
	lastSeen map[string]time.Time
}

// L7Filter enforces per-IP Token Bucket rate limiting with sharded locks for 10k+ RPS scale.
type L7Filter struct {
	shards       [numShards]*shard
	Whitelist    map[string]bool
	DefaultRate  float64
	DefaultBurst int
	stop         chan struct{}
}

func NewL7Filter(rateLimit float64, burstLimit int, whitelist []string) *L7Filter {
	wl := make(map[string]bool)
	for _, ip := range whitelist {
		wl[ip] = true
	}
	f := &L7Filter{
		Whitelist:    wl,
		DefaultRate:  rateLimit,
		DefaultBurst: burstLimit,
		stop:         make(chan struct{}),
	}
	for i := 0; i < numShards; i++ {
		f.shards[i] = &shard{
			limiters: make(map[string]*limiterEntry),
			lastSeen: make(map[string]time.Time),
		}
	}
	go f.cleanupLoop()
	return f
}

func (f *L7Filter) Stop() {
	close(f.stop)
}

func (f *L7Filter) getShard(ip string) *shard {
	// Simple hash for IP to shard
	hash := uint32(0)
	for i := 0; i < len(ip); i++ {
		hash = 31*hash + uint32(ip[i])
	}
	return f.shards[hash%numShards]
}

// getLimiter returns both the limiter and the cached multiplier for an IP.
func (f *L7Filter) getLimiter(ip string, rep *ReputationManager) (*rate.Limiter, float64) {
	s := f.getShard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	entry, exists := s.limiters[ip]
	
	if !exists {
		entry = &limiterEntry{
			limiter:    rate.NewLimiter(rate.Limit(f.DefaultRate), f.DefaultBurst),
			multiplier: 1.0,
			lastUpdate: time.Time{}, // Force immediate update
		}
		s.limiters[ip] = entry
	}
	s.lastSeen[ip] = now

	// Optimization: Only refresh reputation score every 2 seconds to save store cycles
	if rep != nil && now.Sub(entry.lastUpdate) > 2*time.Second {
		entry.multiplier = rep.GetMultiplier(ip)
		entry.lastUpdate = now
		entry.limiter.SetLimit(rate.Limit(f.DefaultRate * entry.multiplier))
		entry.limiter.SetBurst(int(float64(f.DefaultBurst) * entry.multiplier))
	}

	return entry.limiter, entry.multiplier
}

// cleanupLoop removes stale entries from all shards concurrently.
func (f *L7Filter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for i := 0; i < numShards; i++ {
				s := f.shards[i]
				s.mu.Lock()
				for ip, last := range s.lastSeen {
					if time.Since(last) > 10*time.Minute {
						delete(s.limiters, ip)
						delete(s.lastSeen, ip)
					}
				}
				s.mu.Unlock()
			}
			logger.Info("L7 limiter: sharded stale IP entries purged")
		case <-f.stop:
			return
		}
	}
}

func (f *L7Filter) Middleware(next http.Handler, rep *ReputationManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := util.GetRealIP(r)

		// Whitelist takes absolute precedence
		if f.Whitelist[host] {
			next.ServeHTTP(w, r)
			return
		}

		limiter, multiplier := f.getLimiter(host, rep)

		if !limiter.AllowN(time.Now(), 1) {
			logger.Warn("L7 rate limit exceeded", "remote_addr", host, "multiplier", multiplier)

			if rep != nil {
				rep.Penalize(host)
			}

			if MetricsEnabled() {
				BlockedRequests.WithLabelValues("L7", "rate_limit").Inc()
			}
			IncrementL7Blocks()
			
			// Potential "Fast-Path" trigger point for repeat offenders
			TriggerSoftBlock(host) 

			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		if r.Header.Get("User-Agent") == "" {
			if MetricsEnabled() {
				BlockedRequests.WithLabelValues("L7", "no_user_agent").Inc()
			}
			http.Error(w, "Plain bot requests are not allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
