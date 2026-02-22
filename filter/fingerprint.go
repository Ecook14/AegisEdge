package filter

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"sync"

	"aegisedge/logger"
)

// botScore thresholds
const (
	botScoreBlock = 4 // score >= this means auto-block the fingerprint
)

// Fingerprinter identifies clients based on HTTP header signatures.
// It also auto-scores requests for bot-like behavior and blocks high-scoring fingerprints.
type Fingerprinter struct {
	mu                  sync.RWMutex
	BlockedFingerprints map[string]bool
	// fingerprintScores tracks cumulative bot scores per fingerprint hash
	// to auto-block fingerprints that consistently look like bots.
	fingerprintScores map[string]int
}

func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{
		BlockedFingerprints: make(map[string]bool),
		fingerprintScores:   make(map[string]int),
	}
}

func (f *Fingerprinter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp := f.calculateFingerprint(r)
		score := f.scoreRequest(r)

		f.mu.Lock()
		// Accumulate score for this fingerprint
		f.fingerprintScores[fp] += score
		accumulated := f.fingerprintScores[fp]

		// Auto-block fingerprints with consistently bot-like behavior
		if accumulated >= botScoreBlock && !f.BlockedFingerprints[fp] {
			f.BlockedFingerprints[fp] = true
			logger.Warn("Auto-blocked bot fingerprint", "fingerprint", fp,
				"score", accumulated, "remote_addr", r.RemoteAddr,
				"user_agent", r.Header.Get("User-Agent"))
		}

		blocked := f.BlockedFingerprints[fp]
		f.mu.Unlock()

		if blocked {
			BlockedRequests.WithLabelValues("L7", "fingerprint").Inc()
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

	// Missing Accept header is a strong bot signal — real browsers always send it
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

	var data []byte
	for _, h := range fingerprintHeaders {
		val := r.Header.Get(h)
		if val == "" {
			val = "missing"
		}
		data = append(data, []byte(h+":"+val+"|")...)
	}

	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func (f *Fingerprinter) BlockFingerprint(fp string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.BlockedFingerprints[fp] = true
}
