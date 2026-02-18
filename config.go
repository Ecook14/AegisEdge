package main

import (
	"encoding/json"
	"os"
	"fmt"
)

type Config struct {
	ListenPort       int          `json:"listen_port"` // Legacy support
	ListenPorts      []int        `json:"listen_ports"`
	UpstreamAddr     string       `json:"upstream_addr"`
	L3Blacklist      []string     `json:"l3_blacklist"`
	L4ConnLimit      int          `json:"l4_conn_limit"`
	L7RateLimit      float64      `json:"l7_rate_limit"`
	L7BurstLimit     int          `json:"l7_burst_limit"`
	GeoIPDBPath      string       `json:"geoip_db_path"`
	BlockedCountries []string     `json:"blocked_countries"`
	Toggles          FeatureFlags `json:"toggles"`
}

type FeatureFlags struct {
	WAF       bool `json:"waf"`
	GeoIP     bool `json:"geoip"`
	Challenge bool `json:"challenge"`
	Anomaly   bool `json:"anomaly"`
	Stats     bool `json:"stats"`
}

func LoadConfig(path string) (*Config, error) {
	var cfg Config
	
	// Try loading from file first
	file, err := os.Open(path)
	if err == nil {
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&cfg)
		file.Close()
	}

	// Handle port synchronization
	if len(cfg.ListenPorts) == 0 && cfg.ListenPort != 0 {
		cfg.ListenPorts = []int{cfg.ListenPort}
	}

	// Override with ENV variables if present
	if val := os.Getenv("AEGISEDGE_PORT"); val != "" {
		var p int
		fmt.Sscanf(val, "%d", &p)
		cfg.ListenPorts = append(cfg.ListenPorts, p)
	}
	if val := os.Getenv("AEGISEDGE_UPSTREAM"); val != "" {
		cfg.UpstreamAddr = val
	}
	if val := os.Getenv("AEGISEDGE_L4_CONN_LIMIT"); val != "" {
		fmt.Sscanf(val, "%d", &cfg.L4ConnLimit)
	}
	if val := os.Getenv("AEGISEDGE_L7_RATE_LIMIT"); val != "" {
		fmt.Sscanf(val, "%f", &cfg.L7RateLimit)
	}

	// Default values if nothing exists
	if len(cfg.ListenPorts) == 0 {
		cfg.ListenPorts = []int{8080}
	}
	if cfg.UpstreamAddr == "" {
		cfg.UpstreamAddr = "http://localhost:3000"
	}

	// Default Toggles to true
	cfg.Toggles.WAF = true
	cfg.Toggles.GeoIP = true
	cfg.Toggles.Challenge = true
	cfg.Toggles.Anomaly = true
	cfg.Toggles.Stats = true

	return &cfg, nil
}
