package middleware

import (
	"net/http"
	"time"

	"aegisedge/filter"
	"aegisedge/logger"
)

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self';")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		
		next.ServeHTTP(w, r)
	})
}

func Tarpit(next http.Handler, rep *filter.ReputationManager) http.Handler {
	const maxTarpitDelay = 5 * time.Second // Hard cap to prevent goroutine starvation

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := GetRealIP(r)

		delay := 0 * time.Second

		// 1. Reputation-based delay: each point of negative trust = 1s delay
		if rep != nil {
			trust := rep.GetTrust(host)
			if trust < 0 {
				delay = time.Duration(-trust) * time.Second
			}
		}

		// 2. Headless/Suspicious Signal: enforce minimum 2s penalty
		if r.Header.Get("User-Agent") == "" {
			if delay < 2*time.Second {
				delay = 2 * time.Second
			}
		}

		// 3. Hard cap — prevents goroutine exhaustion during large floods
		if delay > maxTarpitDelay {
			delay = maxTarpitDelay
		}

		if delay > 0 {
			logger.Warn("Tarpitting suspicious request", "remote_addr", host, "delay", delay)
			time.Sleep(delay)
		}

		next.ServeHTTP(w, r)
	})
}
