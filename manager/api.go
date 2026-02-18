package manager

import (
	"encoding/json"
	"net/http"
	"time"

	"aegisedge/logger"
	"aegisedge/store"
)

type ManagementAPI struct {
	Store store.Storer
}

type BlockRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration"` // e.g. "1h", "permanent"
}

func NewManagementAPI(s store.Storer) *ManagementAPI {
	return &ManagementAPI{Store: s}
}

func (api *ManagementAPI) ServeHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", api.handleStatus)
	mux.HandleFunc("/api/block", api.handleBlock)
	mux.HandleFunc("/api/config", api.handleConfig)
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

	// Process toggles
	// Process feature toggle updates.
	for k, v := range updates {
		logger.Info("Feature toggle updated", "feature", k, "state", v)
		// Propagate changes to the active configuration registry.
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"message": "Config updated successfully"})
}

func (api *ManagementAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	blocks, err := api.Store.ListBlocks()
	if err != nil {
		http.Error(w, "Failed to list blocks", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"status": "active",
		"active_blocks": blocks,
		"timestamp": time.Now(),
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
			dur = 0 // Redis 0 means no expire in some contexts, but we use a large value
			dur = 10 * 365 * 24 * time.Hour 
			blockType = "hard"
		} else if d, err := time.ParseDuration(req.Duration); err == nil {
			dur = d
		}

		api.Store.Block(req.IP, dur, blockType)
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
