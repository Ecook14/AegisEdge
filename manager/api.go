package manager

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"aegisedge/logger"
	"aegisedge/store"
	utilpkg "aegisedge/util"
)

// LiveToggles holds the runtime feature flag state, safe for concurrent reads/writes.
type LiveToggles struct {
	mu       sync.RWMutex
	WAF      bool
	GeoIP    bool
	Challenge bool
	Anomaly  bool
	Stats    bool
}

func NewLiveToggles(waf, geoip, challenge, anomaly, stats bool) *LiveToggles {
	return &LiveToggles{
		WAF:      waf,
		GeoIP:    geoip,
		Challenge: challenge,
		Anomaly:  anomaly,
		Stats:    stats,
	}
}

func (t *LiveToggles) IsEnabled(feature string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	switch feature {
	case "waf":
		return t.WAF
	case "geoip":
		return t.GeoIP
	case "challenge":
		return t.Challenge
	case "anomaly":
		return t.Anomaly
	case "stats":
		return t.Stats
	}
	return true
}

func (t *LiveToggles) Set(feature string, enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch feature {
	case "waf":
		t.WAF = enabled
	case "geoip":
		t.GeoIP = enabled
	case "challenge":
		t.Challenge = enabled
	case "anomaly":
		t.Anomaly = enabled
	case "stats":
		t.Stats = enabled
	}
}

func (t *LiveToggles) Snapshot() map[string]bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return map[string]bool{
		"waf":       t.WAF,
		"geoip":     t.GeoIP,
		"challenge": t.Challenge,
		"anomaly":   t.Anomaly,
		"stats":     t.Stats,
	}
}

// ManagementAPI provides runtime control over AegisEdge state.
type ManagementAPI struct {
	Store        store.Storer
	Toggles      *LiveToggles
	ProxyWatcher *utilpkg.ProxyWatcher
}

type BlockRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"` // e.g. "1h", "30m", "permanent"
}

func NewManagementAPI(s store.Storer, toggles *LiveToggles, pw *utilpkg.ProxyWatcher) *ManagementAPI {
	return &ManagementAPI{Store: s, Toggles: toggles, ProxyWatcher: pw}
}

func (api *ManagementAPI) ServeHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", api.handleStatus)
	mux.HandleFunc("/api/block", api.handleBlock)
	mux.HandleFunc("/api/config", api.handleConfig)
	// Trusted proxy management — live, no restart required
	mux.HandleFunc("/api/proxy/reload", api.handleProxyReload)
	mux.HandleFunc("/api/proxy/add", api.handleProxyAdd)
	mux.HandleFunc("/api/proxy/remove", api.handleProxyRemove)
}

func (api *ManagementAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Use PATCH", http.StatusMethodNotAllowed)
		return
	}

	var updates map[string]bool
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	for feature, enabled := range updates {
		api.Toggles.Set(feature, enabled)
		logger.Info("Feature toggle applied live", "feature", feature, "enabled", enabled)
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Toggles applied (live, no restart needed)",
		"toggles":  api.Toggles.Snapshot(),
	})
}

func (api *ManagementAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	blocks, err := api.Store.ListBlocks()
	if err != nil {
		http.Error(w, "Failed to list blocks", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status":        "active",
		"active_blocks": blocks,
		"toggles":       api.Toggles.Snapshot(),
		"timestamp":     time.Now(),
	})
}

func (api *ManagementAPI) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req BlockRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		dur := 24 * time.Hour // Default
		blockType := "temp"
		if req.Duration == "permanent" {
			dur = 10 * 365 * 24 * time.Hour
			blockType = "hard"
		} else if d, err := time.ParseDuration(req.Duration); err == nil {
			dur = d
		}

		api.Store.Block(req.IP, dur, blockType)
		logger.Info("Manual IP block applied", "ip", req.IP, "duration", dur, "type", blockType)
		w.WriteHeader(http.StatusCreated)
		return
	}

	if r.Method == http.MethodDelete {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "IP required", http.StatusBadRequest)
			return
		}
		if err := api.Store.Unblock(ip); err != nil {
			http.Error(w, "Clear failed", http.StatusInternalServerError)
			return
		}
		logger.Info("Manual block clearance", "ip", ip)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleProxyReload forces an immediate re-read of CSF/cPHulk/iptables.
// POST /api/proxy/reload
func (api *ManagementAPI) handleProxyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Use POST", http.StatusMethodNotAllowed)
		return
	}
	if api.ProxyWatcher == nil {
		http.Error(w, "ProxyWatcher not initialised", http.StatusServiceUnavailable)
		return
	}
	api.ProxyWatcher.Reload()
	logger.Info("Trusted proxy list reloaded via API")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

// handleProxyAdd adds a permanent manual IP/CIDR to the trusted list.
// POST /api/proxy/add   body: {"entry": "1.2.3.4"} or {"entry": "10.0.0.0/8"}
func (api *ManagementAPI) handleProxyAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Use POST", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Entry string `json:"entry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Entry == "" {
		http.Error(w, "body must be {\"entry\": \"<ip-or-cidr>\"}", http.StatusBadRequest)
		return
	}
	api.ProxyWatcher.AddManual(body.Entry)
	logger.Info("Trusted proxy entry added via API", "entry", body.Entry)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "added", "entry": body.Entry})
}

// handleProxyRemove removes a manual IP/CIDR from the trusted list.
// DELETE /api/proxy/remove?entry=1.2.3.4
func (api *ManagementAPI) handleProxyRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Use DELETE", http.StatusMethodNotAllowed)
		return
	}
	entry := r.URL.Query().Get("entry")
	if entry == "" {
		http.Error(w, "?entry= required", http.StatusBadRequest)
		return
	}
	api.ProxyWatcher.RemoveManual(entry)
	logger.Info("Trusted proxy entry removed via API", "entry", entry)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "entry": entry})
}

// Ensure utilpkg is used (ProxyWatcher field references it).
var _ *utilpkg.ProxyWatcher
