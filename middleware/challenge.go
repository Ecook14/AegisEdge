package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"aegisedge/logger"
)

const (
	ChallengeCookieName = "ae_clearance"
	CookieExpiry      = 3600 // 1 hour
)

var secretKey = []byte(getSecret())

func getSecret() string {
	s := os.Getenv("AEGISEDGE_SECRET")
	if s == "" {
		return "dev-default-secret-key-change-me"
	}
	return s
}

func generateSignature(val string) string {
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(val))
	return hex.EncodeToString(h.Sum(nil))
}

func ProgressiveChallenge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check if user already has a valid clearance cookie
		cookie, err := r.Cookie(ChallengeCookieName)
		if err == nil && verifyCookie(cookie.Value) {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Identify if request should be challenged
		if r.URL.Query().Get("challenge") == "1" {
			logger.Info("Serving JS challenge", "remote_addr", r.RemoteAddr)
			serveChallenge(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func serveChallenge(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusServiceUnavailable)
	
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := generateSignature(ts)
	cookieVal := fmt.Sprintf("%s.%s", ts, sig)

	html := `
	<html>
		<head><title>AegisEdge Protection</title></head>
		<body>
			<h1>Checking your browser...</h1>
			<p>Please wait while we verify you are human.</p>
			<script>
				setTimeout(function() {
					document.cookie = "ae_clearance=` + cookieVal + `; Path=/; Max-Age=3600; SameSite=Lax";
					location.reload();
				}, 2000);
			</script>
		</body>
	</html>`
	fmt.Fprint(w, html)
}

func verifyCookie(val string) bool {
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return false
	}

	tsStr, providedSig := parts[0], parts[1]
	
	// Validate signature
	expectedSig := generateSignature(tsStr)
	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		logger.Warn("Invalid cookie signature detected", "value", val)
		return false
	}

	// Validate expiry
	var ts int64
	fmt.Sscanf(tsStr, "%d", &ts)
	if time.Now().Unix() > ts+CookieExpiry {
		logger.Warn("Expired cookie detected", "timestamp", ts)
		return false
	}

	return true
}
