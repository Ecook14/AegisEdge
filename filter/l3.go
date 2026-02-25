package filter

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

type L3Filter struct {
	blacklist atomic.Value // stores map[string]bool
	whitelist atomic.Value // stores map[string]bool
	mu        sync.Mutex   // guards updates only
}

func NewL3Filter(ips []string, whitelist []string) *L3Filter {
	bl := make(map[string]bool)
	for _, ip := range ips {
		bl[ip] = true
	}
	wl := make(map[string]bool)
	for _, ip := range whitelist {
		wl[ip] = true
	}

	f := &L3Filter{}
	f.blacklist.Store(bl)
	f.whitelist.Store(wl)
	return f
}

func (f *L3Filter) IsBlacklisted(ip string) bool {
	// Optimization: If the IP string contains a port (standard RemoteAddr), split it.
	// But our RealIP middleware already passes a clean IP.
	if strings.Contains(ip, ":") && !strings.Contains(ip, "]") { // naive but fast check for IP:Port
		host, _, err := net.SplitHostPort(ip)
		if err == nil {
			ip = host
		}
	}

	// Whitelist takes absolute precedence
	wl, _ := f.whitelist.Load().(map[string]bool)
	if wl[ip] {
		return false
	}

	// High-speed "Fast-Path" check (Zero-Lock / Sharded)
	if IsSoftBlocked(ip) {
		return true
	}

	bl, _ := f.blacklist.Load().(map[string]bool)
	return bl[ip]
}

func (f *L3Filter) IsWhitelisted(ip string) bool {
	wl, _ := f.whitelist.Load().(map[string]bool)
	return wl[ip]
}

func (f *L3Filter) AddIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Copy-on-Write: rebuild the map and swap it atomically
	oldMap, _ := f.blacklist.Load().(map[string]bool)
	newMap := make(map[string]bool, len(oldMap)+1)
	for k, v := range oldMap {
		newMap[k] = v
	}
	newMap[ip] = true
	f.blacklist.Store(newMap)
}
