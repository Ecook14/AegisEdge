package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"aegisedge/util"
)

const ipShards = 64

type ipCacheShard struct {
	mu    sync.RWMutex
	cache map[string]string
}

var memoizedIPs [ipShards]*ipCacheShard

func init() {
	for i := 0; i < ipShards; i++ {
		memoizedIPs[i] = &ipCacheShard{
			cache: make(map[string]string),
		}
	}
}

func getIpShard(remoteAddr string) *ipCacheShard {
	// Fast FNV-like hash for the remoteAddr string
	hash := uint32(0)
	for i := 0; i < len(remoteAddr); i++ {
		hash = 31*hash + uint32(remoteAddr[i])
	}
	return memoizedIPs[hash%ipShards]
}

// RealIP middleware resolves the true client IP from trusted proxy headers.
// Priority: CF-Connecting-IP → X-Real-IP → X-Forwarded-For → RemoteAddr.
func RealIP(watcher *util.ProxyWatcher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				remoteHost = r.RemoteAddr
			}

			shard := getIpShard(remoteHost)
			shard.mu.RLock()
			cached, ok := shard.cache[remoteHost]
			shard.mu.RUnlock()

			if ok {
				next.ServeHTTP(w, util.SetRealIP(r, cached))
				return
			}

			ip := extractIP(r, watcher, remoteHost)

			// Store in cache
			shard.mu.Lock()
			shard.cache[remoteHost] = ip
			shard.mu.Unlock()

			next.ServeHTTP(w, util.SetRealIP(r, ip))
		})
	}
}

// GetRealIP is a convenience wrapper for use within the middleware package.
func GetRealIP(r *http.Request) string {
	return util.GetRealIP(r)
}

func extractIP(r *http.Request, watcher *util.ProxyWatcher, remoteHost string) string {
	// Only honour forwarded headers when the immediate connection is from
	// a trusted proxy in the live CSF/iptables/cPHulk whitelist.
	if watcher == nil || !watcher.IsTrusted(remoteHost) {
		return remoteHost
	}

	// 1. Cloudflare — single authoritative header, no parsing ambiguity.
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		if ip := net.ParseIP(strings.TrimSpace(cf)); ip != nil {
			return ip.String()
		}
	}

	// 2. Standard nginx / AWS ALB
	if real := r.Header.Get("X-Real-IP"); real != "" {
		if ip := net.ParseIP(strings.TrimSpace(real)); ip != nil {
			return ip.String()
		}
	}

	// 3. X-Forwarded-For — leftmost value is the original client.
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
			return ip.String()
		}
	}

	return remoteHost
}
