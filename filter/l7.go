package filter

import (
	"net"
	"net/http"
	"time"

	"aegisedge/store"

	"golang.org/x/time/rate"
)

type L7Filter struct {
	rate  rate.Limit
	burst int
	store store.Storer
}

func NewL7Filter(r float64, b int, s store.Storer) *L7Filter {
	return &L7Filter{
		rate:  rate.Limit(r),
		burst: b,
		store: s,
	}
}

func (f *L7Filter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		
		// Rate limiting using fixed window on store
		key := "l7:rate:" + host
		count, err := f.store.Increment(key, 1*time.Second)
		if err == nil && int(count) > f.burst {
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
