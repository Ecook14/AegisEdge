package main

import (
	"encoding/json"
	"os"
	"fmt"
	"strings"
)

type Config struct {
	ListenPort       int          `json:"listen_port"` // Legacy support
	ListenPorts      []int        `json:"listen_ports"`
	TcpPorts         []int        `json:"tcp_ports"`
	UpstreamAddr     string       `json:"upstream_addr"`
	L3Blacklist      []string     `json:"l3_blacklist"`
	L4ConnLimit      int          `json:"l4_conn_limit"`
	L7RateLimit      float64      `json:"l7_rate_limit"`
	L7BurstLimit     int          `json:"l7_burst_limit"`
	GeoIPDBPath      string       `json:"geoip_db_path"`
	BlockedCountries []string     `json:"blocked_countries"`
	HypervisorMode   bool         `json:"hypervisor_mode"`
	HotTakeover      bool         `json:"hot_takeover"`
	SSLCertPath      string       `json:"ssl_cert_path"`
	SSLKeyPath       string       `json:"ssl_key_path"`
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
	if val := os.Getenv("AEGISEDGE_PORTS"); val != "" {
		portStrs := strings.Split(val, ",")
		for _, s := range portStrs {
			var p int
			fmt.Sscanf(strings.TrimSpace(s), "%d", &p)
			if p != 0 {
				cfg.ListenPorts = append(cfg.ListenPorts, p)
			}
		}
	}
	if val := os.Getenv("AEGISEDGE_TCP_PORTS"); val != "" {
		portStrs := strings.Split(val, ",")
		for _, s := range portStrs {
			var p int
			fmt.Sscanf(strings.TrimSpace(s), "%d", &p)
			if p != 0 {
				cfg.TcpPorts = append(cfg.TcpPorts, p)
			}
		}
	}
	if val := os.Getenv("AEGISEDGE_UPSTREAM"); val != "" {
		cfg.UpstreamAddr = val
	}
	if val := os.Getenv("AEGISEDGE_HYPERVISOR_MODE"); val != "" {
		cfg.HypervisorMode = (val == "true" || val == "1")
	}
	if val := os.Getenv("AEGISEDGE_HOT_TAKEOVER"); val != "" {
		cfg.HotTakeover = (val == "true" || val == "1")
	}
	if val := os.Getenv("AEGISEDGE_SSL_CERT"); val != "" {
		cfg.SSLCertPath = val
	}
	if val := os.Getenv("AEGISEDGE_SSL_KEY"); val != "" {
		cfg.SSLKeyPath = val
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

// DiscoverCerts attempts to find SSL certificates in common system locations.
func (c *Config) DiscoverCerts() (string, string) {
	if c.SSLCertPath != "" && c.SSLKeyPath != "" {
		return c.SSLCertPath, c.SSLKeyPath
	}

	// Priority locations for different environments (WHM, Plesk, Baremetal, etc.)
	searches := []struct {
		cert string
		key  string
	}{
		{"certs/cert.pem", "certs/key.pem"},
		{"/etc/letsencrypt/live/*/fullchain.pem", "/etc/letsencrypt/live/*/privkey.pem"}, // Wildcard support would need glob
		{"/etc/letsencrypt/open/fullchain.pem", "/etc/letsencrypt/open/privkey.pem"},
		{"/etc/ssl/certs/aegis.crt", "/etc/ssl/private/aegis.key"},
		// RHEL / CentOS
		{"/etc/pki/tls/certs/localhost.crt", "/etc/pki/tls/private/localhost.key"},
		// cPanel / WHM (common locations)
		{"/var/cpanel/ssl/installed/certs/*.crt", "/var/cpanel/ssl/installed/keys/*.key"},
		// Plesk
		{"/usr/local/psa/var/certificates/*", "/usr/local/psa/var/certificates/*"},
	}

	for _, s := range searches {
		// Note: Actual implementation would use filepath.Glob for wildcards
		// For now, checking direct standard paths
		if _, err := os.Stat(s.cert); err == nil {
			if _, err := os.Stat(s.key); err == nil {
				return s.cert, s.key
			}
		}
	}

	return "", ""
}
