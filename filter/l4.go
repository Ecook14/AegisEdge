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
	store        store.Storer
}

func NewL4Filter(maxConn int, idleTimeout time.Duration, s store.Storer) *L4Filter {
	return &L4Filter{
		MaxConnPerIP: maxConn,
		IdleTimeout:  idleTimeout,
		store:        s,
	}
}

func (f *L4Filter) AllowConnection(addr string) bool {
	host, _, _ := net.SplitHostPort(addr)
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
	host, _, _ := net.SplitHostPort(addr)
	key := "l4:conn:" + host
	
	_, err := f.store.Decrement(key)
	if err != nil {
		logger.Error("L4 store decrement error", "err", err, "ip", host)
	}
}

