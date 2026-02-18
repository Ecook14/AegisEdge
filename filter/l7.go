package filter

import (
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type L7Filter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	rate     rate.Limit
	burst    int
}

func NewL7Filter(r float64, b int) *L7Filter {
	return &L7Filter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(r),
		burst:    b,
	}
}

func (f *L7Filter) GetLimiter(ip string) *rate.Limiter {
	f.mu.Lock()
	defer f.mu.Unlock()

	limiter, ok := f.limiters[ip]
	if !ok {
		limiter = rate.NewLimiter(f.rate, f.burst)
		f.limiters[ip] = limiter
	}

	return limiter
}

func (f *L7Filter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		limiter := f.GetLimiter(host)
		
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Basic header validation
		if r.Header.Get("User-Agent") == "" {
			http.Error(w, "Plain bot requests are not allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
