package filter

import (
	"net"
	"time"

	"aegisedge/logger"
	"aegisedge/store"
)

type L4Filter struct {
	MaxConnPerIP int
	IdleTimeout  time.Duration
	Whitelist    map[string]bool
	store        store.Storer
}

func NewL4Filter(maxConn int, idleTimeout time.Duration, s store.Storer, whitelist []string) *L4Filter {
	wl := make(map[string]bool)
	for _, ip := range whitelist {
		wl[ip] = true
	}
	return &L4Filter{
		MaxConnPerIP: maxConn,
		IdleTimeout:  idleTimeout,
		Whitelist:    wl,
		store:        s,
	}
}

func (f *L4Filter) AllowConnection(addr string) bool {
	// Performance Bypass: If limit is 0, skip all tracking and locks
	if f.MaxConnPerIP <= 0 {
		return true
	}

	host, _, _ := net.SplitHostPort(addr)
	
	// Whitelist takes absolute precedence
	if f.Whitelist[host] {
		return true
	}

	key := "l4:conn:" + host

	count, err := f.store.Increment(key, f.IdleTimeout)
	if err != nil {
		logger.Error("L4 store error (fail open)", "err", err, "ip", host)
		return true // Fail open
	}

	if int(count) > f.MaxConnPerIP {
		logger.Warn("L4 connection limit exceeded", "ip", host, "count", count, "limit", f.MaxConnPerIP)
		return false
	}
	return true
}

func (f *L4Filter) ReleaseConnection(addr string) {
	// Performance Bypass: If limit is 0, skip all tracking and locks
	if f.MaxConnPerIP <= 0 {
		return
	}

	host, _, _ := net.SplitHostPort(addr)
	key := "l4:conn:" + host
	
	_, err := f.store.Decrement(key)
	if err != nil {
		logger.Error("L4 store decrement error", "err", err, "ip", host)
	}
}

