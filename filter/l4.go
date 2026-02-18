package filter

import (
	"log"
	"net"
	"time"

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
		log.Printf("[L4] Store error: %v", err)
		return true // Fail open
	}

	if int(count) > f.MaxConnPerIP {
		log.Printf("[L4] Blocked IP %s (too many connections: %d)", host, count)
		return false
	}
	return true
}

func (f *L4Filter) ReleaseConnection(addr string) {
	host, _, _ := net.SplitHostPort(addr)
	key := "l4:conn:" + host
	
	_, err := f.store.Decrement(key)
	if err != nil {
		log.Printf("[L4] Store decrement error: %v", err)
	}
}

