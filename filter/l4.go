package filter

import (
	"log"
	"net"
	"sync"
	"time"
)

type ConnStats struct {
	Count     int
	LastSeen  time.Time
}

type L4Filter struct {
	MaxConnPerIP int
	IdleTimeout  time.Duration
	connections  map[string]*ConnStats
	mu           sync.Mutex
}

func NewL4Filter(maxConn int, idleTimeout time.Duration) *L4Filter {
	f := &L4Filter{
		MaxConnPerIP: maxConn,
		IdleTimeout:  idleTimeout,
		connections:  make(map[string]*ConnStats),
	}
	
	// Background cleanup of idle connections
	go f.cleanupLoop()
	
	return f
}

func (f *L4Filter) AllowConnection(addr string) bool {
	host, _, _ := net.SplitHostPort(addr)
	
	f.mu.Lock()
	defer f.mu.Unlock()
	
	stats, ok := f.connections[host]
	if !ok {
		stats = &ConnStats{LastSeen: time.Now()}
		f.connections[host] = stats
	}
	
	if stats.Count >= f.MaxConnPerIP {
		log.Printf("[L4] Blocked IP %s (too many connections: %d)", host, stats.Count)
		return false
	}
	
	stats.Count++
	stats.LastSeen = time.Now()
	return true
}

func (f *L4Filter) ReleaseConnection(addr string) {
	host, _, _ := net.SplitHostPort(addr)
	
	f.mu.Lock()
	defer f.mu.Unlock()
	
	if stats, ok := f.connections[host]; ok && stats.Count > 0 {
		stats.Count--
		stats.LastSeen = time.Now()
		if stats.Count == 0 {
			delete(f.connections, host)
		}
	}
}

func (f *L4Filter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		f.mu.Lock()
		for host, stats := range f.connections {
			if time.Since(stats.LastSeen) > f.IdleTimeout {
				log.Printf("[L4] Cleaning up idle connection tracking for %s", host)
				delete(f.connections, host)
			}
		}
		f.mu.Unlock()
	}
}
