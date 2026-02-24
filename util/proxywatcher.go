package util

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyWatcher maintains a live, hot-swappable list of trusted proxy CIDRs.
// It re-discovers from CSF, cPHulk, and iptables on a configurable interval
// and supports on-demand reloads via Reload().
type ProxyWatcher struct {
	nets   atomic.Value  // stores []*net.IPNet — lock-free reads per request
	manual []string      // static entries from env / API calls
	mu     sync.Mutex    // guards manual slice and Reload()
	stop   chan struct{}
}

// NewProxyWatcher creates a watcher, does an immediate load, then refreshes
// on the given interval. Pass interval=0 to disable background refresh.
func NewProxyWatcher(manualList string, interval time.Duration) *ProxyWatcher {
	w := &ProxyWatcher{
		stop: make(chan struct{}),
	}
	// Parse static manual entries once.
	for _, e := range strings.Split(manualList, ",") {
		e = strings.TrimSpace(e)
		if e != "" {
			w.manual = append(w.manual, e)
		}
	}
	w.reload()

	if interval > 0 {
		go w.loop(interval)
	}
	return w
}

// IsTrusted returns true if ip is within any currently trusted network.
// Uses atomic load — zero contention on the hot path.
func (w *ProxyWatcher) IsTrusted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	nets, _ := w.nets.Load().([]*net.IPNet)
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Reload forces an immediate re-read of all sources. Safe to call concurrently.
func (w *ProxyWatcher) Reload() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reload()
}

// AddManual adds a single IP or CIDR to the permanent manual list and reloads.
func (w *ProxyWatcher) AddManual(entry string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.manual = append(w.manual, entry)
	w.reload()
}

// RemoveManual removes an entry from the manual list and reloads.
func (w *ProxyWatcher) RemoveManual(entry string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	updated := w.manual[:0]
	for _, e := range w.manual {
		if e != entry {
			updated = append(updated, e)
		}
	}
	w.manual = updated
	w.reload()
}

// Stop cancels the background refresh goroutine.
func (w *ProxyWatcher) Stop() {
	close(w.stop)
}

// reload (must be called with mu held, or single-threaded at init) rebuilds
// the live net list from all sources and atomically swaps it in.
func (w *ProxyWatcher) reload() {
	entries := make([]string, 0, len(w.manual))
	entries = append(entries, w.manual...)
	entries = append(entries, DiscoverTrustedProxies()...)
	w.nets.Store(parseTrustedList(entries))
}

func (w *ProxyWatcher) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.Reload()
		case <-w.stop:
			return
		}
	}
}

// parseTrustedList converts string entries to []*net.IPNet.
func parseTrustedList(entries []string) []*net.IPNet {
	seen := make(map[string]struct{})
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, seen := seen[entry]; seen {
			continue
		}
		seen[entry] = struct{}{}

		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128"
			} else {
				entry += "/32"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil {
			nets = append(nets, cidr)
		}
	}
	return nets
}
