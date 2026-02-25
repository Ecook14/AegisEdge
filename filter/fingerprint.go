package filter

import (
	"fmt"
	"hash/fnv"
	"net/http"
	"sync"

	"aegisedge/logger"
)

const fingerprintShards = 64

type fingerprintShard struct {
	mu                  sync.RWMutex
	blockedFingerprints map[string]bool
	fingerprintScores   map[string]int
}

// Fingerprinter identifies clients based on HTTP header signatures.
// It uses a 64-shard lock architecture and FNV-1a hashing for 10k+ RPS efficiency.
type Fingerprinter struct {
	shards     [fingerprintShards]*fingerprintShard
	botScanner *BotScanner
}

func NewFingerprinter() *Fingerprinter {
	f := &Fingerprinter{
		botScanner: NewBotScanner(),
	}
	for i := 0; i < fingerprintShards; i++ {
		f.shards[i] = &fingerprintShard{
			blockedFingerprints: make(map[string]bool),
			fingerprintScores:   make(map[string]int),
		}
	}
	return f
}

func (f *Fingerprinter) getShard(fp string) *fingerprintShard {
	// FNV-1a is extremely fast and effective for short header strings
	h := fnv.New32a()
	h.Write([]byte(fp))
	return f.shards[h.Sum32()%fingerprintShards]
}

const botScoreBlock = 4

func (f *Fingerprinter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp := f.calculateFingerprint(r)
		score := f.scoreRequest(r)

		shard := f.getShard(fp)
		shard.mu.Lock()
		
		shard.fingerprintScores[fp] += score
		accumulated := shard.fingerprintScores[fp]

		if accumulated >= botScoreBlock && !shard.blockedFingerprints[fp] {
			shard.blockedFingerprints[fp] = true
			logger.Warn("Auto-blocked bot fingerprint", "fingerprint", fp,
				"score", accumulated, "remote_addr", r.RemoteAddr,
				"user_agent", r.Header.Get("User-Agent"))
		}

		blocked := shard.blockedFingerprints[fp]
		shard.mu.Unlock()

		if blocked {
			if MetricsEnabled() {
				BlockedRequests.WithLabelValues("L7", "fingerprint").Inc()
			}
			http.Error(w, "Access Denied: Malicious Signature", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// scoreRequest returns a bot-likelihood score for the request (higher = more bot-like).
// A score of 0 = looks human. Scores accumulate per fingerprint over time.
func (f *Fingerprinter) scoreRequest(r *http.Request) int {
	score := 0

	// High-Performance Bot Signature Check
	if f.botScanner.IsBot(r.Header.Get("User-Agent")) {
		score += 3
	}

	// Missing Accept header is a strong bot signal
	if r.Header.Get("Accept") == "" {
		score += 2
	}
	// Missing Accept-Language is unusual for real browsers
	if r.Header.Get("Accept-Language") == "" {
		score += 1
	}
	// Missing Accept-Encoding means no compression support — very rare for browsers
	if r.Header.Get("Accept-Encoding") == "" {
		score += 1
	}
	// Modern browsers always send Sec-Fetch-* headers; absence is a bot signal
	if r.Header.Get("Sec-Fetch-Site") == "" {
		score += 1
	}
	// Connection: keep-alive is sent by all modern browsers
	if r.Header.Get("Connection") == "" {
		score += 1
	}

	return score
}

func (f *Fingerprinter) calculateFingerprint(r *http.Request) string {
	fingerprintHeaders := []string{
		"User-Agent",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
		"Upgrade-Insecure-Requests",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"Sec-Fetch-User",
	}

	h := fnv.New64a()
	for _, header := range fingerprintHeaders {
		val := r.Header.Get(header)
		if val == "" {
			val = "missing"
		}
		h.Write([]byte(header + ":" + val + "|"))
	}

	return fmt.Sprintf("%x", h.Sum64())
}

func (f *Fingerprinter) BlockFingerprint(fp string) {
	shard := f.getShard(fp)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	shard.blockedFingerprints[fp] = true
}
