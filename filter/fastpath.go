package filter

import (
	"sync"
	"time"

	"aegisedge/logger"
)

const (
	fastPathShards = 32
	softBlockTTL   = 60 * time.Second
	violationLimit = 5
	violationTTL   = 10 * time.Second
)

type fpShard struct {
	mu         sync.RWMutex
	softBlocks map[string]time.Time
	violations map[string]int
	lastSeen   map[string]time.Time
}

var fp = [fastPathShards]*fpShard{}

func init() {
	for i := 0; i < fastPathShards; i++ {
		fp[i] = &fpShard{
			softBlocks: make(map[string]time.Time),
			violations: make(map[string]int),
			lastSeen:   make(map[string]time.Time),
		}
	}
	go fastPathCleanup()
}

func getFpShard(ip string) *fpShard {
	hash := uint32(0)
	for i := 0; i < len(ip); i++ {
		hash = 31*hash + uint32(ip[i])
	}
	return fp[hash%fastPathShards]
}

// GetSoftBlocks returns a snapshot of all active Soft Blocks across all shards.
func GetSoftBlocks() map[string]time.Time {
	all := make(map[string]time.Time)
	for i := 0; i < fastPathShards; i++ {
		s := fp[i]
		s.mu.RLock()
		for ip, expiry := range s.softBlocks {
			if time.Now().Before(expiry) {
				all[ip] = expiry
			}
		}
		s.mu.RUnlock()
	}
	return all
}

// IsSoftBlocked checks if an IP is in the high-speed "Hot-Block" path.
func IsSoftBlocked(ip string) bool {
	s := getFpShard(ip)
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiry, exists := s.softBlocks[ip]
	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		return false
	}
	return true
}

// TriggerSoftBlock handles violation accounting and "Soft Block" promotion.
// This is called by filters when a threshold (like L7 Rate Limit) is breached.
func TriggerSoftBlock(ip string) {
	s := getFpShard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	
	// Increment violations
	s.violations[ip]++
	s.lastSeen[ip] = now

	// If threshold reached, promote to Soft Block (Cool Down mode)
	if s.violations[ip] >= violationLimit {
		s.softBlocks[ip] = now.Add(softBlockTTL)
		logger.Warn("IP promoted to Fast-Path Soft Block (Cool Down)", "ip", ip, "duration", softBlockTTL)
		// Reset violations so they don't cumulative infinitely if unblocked later
		delete(s.violations, ip)
	}
}

func fastPathCleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		for i := 0; i < fastPathShards; i++ {
			s := fp[i]
			s.mu.Lock()
			// Cleanup expired soft blocks
			for ip, expiry := range s.softBlocks {
				if now.After(expiry) {
					delete(s.softBlocks, ip)
					logger.Info("IP released from Fast-Path Soft Block (Cool Down finished)", "ip", ip)
				}
			}
			// Cleanup stale violations
			for ip, last := range s.lastSeen {
				if now.Sub(last) > violationTTL {
					delete(s.violations, ip)
					delete(s.lastSeen, ip)
				}
			}
			s.mu.Unlock()
		}
	}
}
