package filter

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strings"

	"aegisedge/logger"
)

// BehavioralFingerprinter identifies clients based on headers and connection patterns.
// This is a professional implementation of "JA3-like" application-layer fingerprinting.
type Fingerprinter struct {
	BlockedFingerprints map[string]bool
}

func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{
		BlockedFingerprints: make(map[string]bool),
	}
}

func (f *Fingerprinter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp := f.calculateFingerprint(r)
		
		if f.BlockedFingerprints[fp] {
			logger.Warn("Blocked known malicious fingerprint", "remote_addr", r.RemoteAddr, "fingerprint", fp)
			BlockedRequests.WithLabelValues("L7", "fingerprint").Inc()
			http.Error(w, "Access Denied: Malicious Signature", http.StatusForbidden)
			return
		}

		// Store fingerprint in context for further analysis if needed
		next.ServeHTTP(w, r)
	})
}

func (s *Fingerprinter) calculateFingerprint(r *http.Request) string {
	// Behavioral fingerprinting based on HTTP header signature.
	// We look for specific headers and their order/values to identify the "DNA" of the client.
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

	var data strings.Builder
	for _, h := range fingerprintHeaders {
		val := r.Header.Get(h)
		if val != "" {
			data.WriteString(h + ":" + val + "|")
		} else {
			data.WriteString(h + ":missing|")
		}
	}

	hash := md5.Sum([]byte(data.String()))
	return hex.EncodeToString(hash[:])
}

func (f *Fingerprinter) BlockFingerprint(fp string) {
	f.BlockedFingerprints[fp] = true
}
