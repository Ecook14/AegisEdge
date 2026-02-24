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

	"aegisedge/filter"
	"aegisedge/logger"
)

const (
	ChallengeCookieName = "ae_clearance"
	CookieExpiry        = 3600 // 1 hour in seconds
)

var secretKey = []byte(getSecret())

func getSecret() string {
	s := os.Getenv("AEGISEDGE_SECRET")
	if s == "" {
		return "dev-default-secret-key-change-me"
	}
	return s
}

func generateSignature(val, ip string) string {
	h := hmac.New(sha256.New, secretKey)
	// Bind to both the value and the client IP for enterprise-grade security
	h.Write([]byte(val + ":" + ip))
	return hex.EncodeToString(h.Sum(nil))
}

func ProgressiveChallenge(next http.Handler, rep *filter.ReputationManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := GetRealIP(r)

		cookie, err := r.Cookie(ChallengeCookieName)
		if err == nil && verifyCookie(cookie.Value, host) {
			next.ServeHTTP(w, r)
			return
		}

		if token := r.URL.Query().Get("ae_token"); token != "" {
			if verifyCookie(token, host) {
				// Reward the IP for solving the challenge
				if rep != nil {
					rep.Reward(host)
				}
				http.SetCookie(w, &http.Cookie{
					Name:     ChallengeCookieName,
					Value:    token,
					Path:     "/",
					MaxAge:   CookieExpiry,
					SameSite: http.SameSiteStrictMode,
					HttpOnly: true,
					Secure:   true, // Must not be sent over plain HTTP
				})
				// Strip the token from the URL and redirect to the clean path
				target := r.URL.Path
				if r.URL.RawQuery != "" {
					q := r.URL.Query()
					q.Del("ae_token")
					if len(q) > 0 {
						target += "?" + q.Encode()
					}
				}
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
		}

		// 3. All other requests get the JS challenge page.
		logger.Info("Serving JS challenge (no valid clearance)", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
		serveChallenge(w, r, host)
	})
}

func serveChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusServiceUnavailable)

	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := generateSignature(ts, ip)
	token := fmt.Sprintf("%s.%s", ts, sig)

	// The JS sets the token as a query param and reloads so the server can
	// set it as an HttpOnly cookie (JS can't set HttpOnly cookies itself).
	redirectURL := r.URL.Path + "?ae_token=" + token
	if r.URL.RawQuery != "" {
		q := r.URL.Query()
		q.Del("ae_token")
		if encoded := q.Encode(); encoded != "" {
			redirectURL += "&" + encoded
		}
	}

	html := `<!DOCTYPE html>
<html>
  <head>
    <title>AegisEdge — Checking your browser</title>
    <style>
      body { font-family: sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; background:#0d1117; color:#cdd9e5; }
      .box { text-align:center; }
      .spinner { width:40px; height:40px; border:4px solid #30363d; border-top-color:#58a6ff; border-radius:50%; animation:spin 0.8s linear infinite; margin:1rem auto; }
      @keyframes spin { to { transform: rotate(360deg); } }
    </style>
  </head>
  <body>
    <div class="box">
      <div class="spinner"></div>
      <h2>Checking your browser&hellip;</h2>
      <p>AegisEdge Security &mdash; one moment please.</p>
      <script>
        setTimeout(function() {
          window.location.href = "` + redirectURL + `";
        }, 2000);
      </script>
    </div>
  </body>
</html>`
	fmt.Fprint(w, html)
}

func verifyCookie(val, ip string) bool {
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return false
	}

	tsStr, providedSig := parts[0], parts[1]

	// Constant-time HMAC comparison
	expectedSig := generateSignature(tsStr, ip)
	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		logger.Warn("Invalid challenge cookie signature or IP mismatch", "value", val, "client_ip", ip)
		return false
	}

	// Expiry check
	var ts int64
	fmt.Sscanf(tsStr, "%d", &ts)
	if time.Now().Unix() > ts+CookieExpiry {
		logger.Warn("Expired challenge cookie", "timestamp", ts)
		return false
	}

	return true
}
