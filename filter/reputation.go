package filter

import (
	"fmt"
	"time"

	"aegisedge/logger"
	"aegisedge/notifier"
	"aegisedge/store"
)

const (
	TrustKeyPrefix = "trust:"
	TrustMax       = 10
	TrustMin       = -10
	TrustReward    = 1
	TrustPenalty   = -2
)

// ReputationManager tracks client trust scores in the persistent store.
type ReputationManager struct {
	store store.Storer
}

func NewReputationManager(s store.Storer) *ReputationManager {
	return &ReputationManager{store: s}
}

// GetTrust returns the current trust score for an IP. Default is 0.
func (m *ReputationManager) GetTrust(ip string) int {
	key := TrustKeyPrefix + ip
	score, err := m.store.Get(key)
	if err != nil {
		return 0
	}
	
	var val int
	fmt.Sscanf(score, "%d", &val)
	return val
}

// Reward increases trust when a client behaves well (e.g., solves a challenge).
func (m *ReputationManager) Reward(ip string) {
	m.adjust(ip, TrustReward)
}

// Penalize decreases trust when a client behaves poorly (e.g., hits rate limits).
func (m *ReputationManager) Penalize(ip string) {
	m.adjust(ip, TrustPenalty)
}

func (m *ReputationManager) adjust(ip string, delta int) {
	current := m.GetTrust(ip)
	newScore := current + delta

	if newScore > TrustMax {
		newScore = TrustMax
	}
	if newScore < TrustMin {
		newScore = TrustMin
	}

	key := TrustKeyPrefix + ip
	// Persist for 24 hours
	m.store.Set(key, fmt.Sprintf("%d", newScore), 24*time.Hour)

	// Warning fires when trust is persistently low but not yet terminal (-5)
	if newScore <= TrustMin/2 && newScore > TrustMin {
		logger.Warn("Low reputation IP detected", "ip", ip, "score", newScore)
		notifier.SendAlert(fmt.Sprintf("Warning: Persistent low reputation for %s (Score: %d)", ip, newScore), "WARNING")
	}

	// Terminal reputation: kernel-level drop at -10
	if newScore <= TrustMin {
		logger.Warn("IP reached terminal reputation — triggering kernel-level drop", "ip", ip)
		if err := BlockIPKernel(ip); err != nil {
			logger.Error("Kernel block failed, falling back to application-layer block", "ip", ip, "err", err)
		}
		notifier.SendAlert(fmt.Sprintf("Kernel-level block issued for %s (Terminal reputation)", ip), "CRITICAL")
	}
}

// GetMultiplier returns a rate limit multiplier based on trust.
// Trust 10 = 2.0x throughput
// Trust 0  = 1.0x throughput
// Trust -10 = 0.5x throughput
func (m *ReputationManager) GetMultiplier(ip string) float64 {
	trust := m.GetTrust(ip)
	if trust >= 0 {
		return 1.0 + (float64(trust) / 10.0)
	}
	// Scale -1 to -10 linearly to 0.9 to 0.5
	return 1.0 + (float64(trust) * 0.05)
}
