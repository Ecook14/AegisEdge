package filter

import (
	//"fmt"
	"net"
	"sync"
)

type L3Filter struct {
	Blacklist map[string]bool
	mu        sync.RWMutex
}

func NewL3Filter(ips []string) *L3Filter {
	bl := make(map[string]bool)
	for _, ip := range ips {
		bl[ip] = true
	}
	return &L3Filter{Blacklist: bl}
}

func (f *L3Filter) IsBlacklisted(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		ip = host
	}
	
	return f.Blacklist[ip]
}

func (f *L3Filter) AddIP(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Blacklist[ip] = true
}
