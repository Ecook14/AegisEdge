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

func (f *Fingerprinter) calculateFingerprint(r *http.Request) string {
	// In a real JA3 implementation, we would inspect the TLS Client Hello.
	// Here we simulate it using a hash of specific semi-static headers.
	headers := []string{
		r.Header.Get("User-Agent"),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Accept-Encoding"),
	}
	data := strings.Join(headers, "|")
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (f *Fingerprinter) BlockFingerprint(fp string) {
	f.BlockedFingerprints[fp] = true
}
