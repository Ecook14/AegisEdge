package manager

import (
	"encoding/json"
	"net/http"
	//"sync"
	"sync/atomic"
	"time"

	"aegisedge/logger"
	"aegisedge/store"
	"aegisedge/filter"
	utilpkg "aegisedge/util"
)

// LiveToggles holds the runtime feature flag state, lockless for extreme throughput.
type LiveToggles struct {
	WAF       atomic.Bool
	GeoIP     atomic.Bool
	Challenge atomic.Bool
	Anomaly   atomic.Bool
	Stats     atomic.Bool
}

func NewLiveToggles(waf, geoip, challenge, anomaly, stats bool) *LiveToggles {
	t := &LiveToggles{}
	t.WAF.Store(waf)
	t.GeoIP.Store(geoip)
	t.Challenge.Store(challenge)
	t.Anomaly.Store(anomaly)
	t.Stats.Store(stats)
	return t
}

func (t *LiveToggles) IsEnabled(feature string) bool {
	switch feature {
	case "waf":
		return t.WAF.Load()
	case "geoip":
		return t.GeoIP.Load()
	case "challenge":
		return t.Challenge.Load()
	case "anomaly":
		return t.Anomaly.Load()
	case "stats":
		return t.Stats.Load()
	}
	return true
}

func (t *LiveToggles) Set(feature string, enabled bool) {
	switch feature {
	case "waf":
		t.WAF.Store(enabled)
	case "geoip":
		t.GeoIP.Store(enabled)
	case "challenge":
		t.Challenge.Store(enabled)
	case "anomaly":
		t.Anomaly.Store(enabled)
	case "stats":
		t.Stats.Store(enabled)
		filter.SetMetricsEnabled(enabled)
	}
}

func (t *LiveToggles) Snapshot() map[string]bool {
	return map[string]bool{
		"waf":       t.WAF.Load(),
		"geoip":     t.GeoIP.Load(),
		"challenge": t.Challenge.Load(),
		"anomaly":   t.Anomaly.Load(),
		"stats":     t.Stats.Load(),
	}
}

// ManagementAPI provides runtime control over AegisEdge state.
type ManagementAPI struct {
	Store        store.Storer
	Toggles      *LiveToggles
	ProxyWatcher *utilpkg.ProxyWatcher
	RequestCount atomic.Uint64
	StartTime    time.Time
}

type BlockRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"` // e.g. "1h", "30m", "permanent"
}

func NewManagementAPI(s store.Storer, toggles *LiveToggles, pw *utilpkg.ProxyWatcher) *ManagementAPI {
	return &ManagementAPI{
		Store:        s,
		Toggles:      toggles,
		ProxyWatcher: pw,
		StartTime:    time.Now(),
	}
}

func (api *ManagementAPI) TrackRequest() {
	api.RequestCount.Add(1)
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

	totalReqs := api.RequestCount.Load()
	uptimeSeconds := time.Since(api.StartTime).Seconds()
	avgRps := float64(totalReqs) / uptimeSeconds

	json.NewEncoder(w).Encode(map[string]any{
		"status":           "active",
		"uptime_seconds":   int(uptimeSeconds),
		"total_requests":   totalReqs,
		"average_rps":      avgRps,
		"active_blocks":    blocks,
		"fast_path_blocks": filter.GetSoftBlocks(),
		"toggles":          api.Toggles.Snapshot(),
		"timestamp":        time.Now(),
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
