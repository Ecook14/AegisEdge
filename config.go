package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	// 1. Set System Defaults
	cfg := Config{
		UpstreamAddr: "http://localhost:3000",
		ListenPorts:  []int{8080},
		Toggles: FeatureFlags{
			WAF:       true,
			GeoIP:     true,
			Challenge: true,
			Anomaly:   true,
			Stats:     true,
		},
	}
	
	// 2. Load from file (Overrides Defaults)
	file, err := os.Open(path)
	if err == nil {
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&cfg)
		file.Close()
	}

	// Handle legacy port synchronization
	if len(cfg.ListenPorts) == 0 && cfg.ListenPort != 0 {
		cfg.ListenPorts = []int{cfg.ListenPort}
	}

	// 3. Load from Environment (Overrides File)
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
	if val := os.Getenv("AEGISEDGE_L7_BURST_LIMIT"); val != "" {
		fmt.Sscanf(val, "%d", &cfg.L7BurstLimit)
	}
	if val := os.Getenv("AEGISEDGE_GEOIP_DB"); val != "" {
		cfg.GeoIPDBPath = val
	}
	if val := os.Getenv("AEGISEDGE_BLOCKED_COUNTRIES"); val != "" {
		cfg.BlockedCountries = strings.Split(val, ",")
	}

	return &cfg, nil
}

// DiscoverCerts attempts to find SSL certificates in common system locations.
func (c *Config) DiscoverCerts() (string, string) {
	if c.SSLCertPath != "" && c.SSLKeyPath != "" {
		return c.SSLCertPath, c.SSLKeyPath
	}

	// Priority locations for different environments (WHM, Plesk, Baremetal, etc.)
	searches := []struct {
		certPattern string
		keyPattern  string
	}{
		{"certs/cert.pem", "certs/key.pem"},
		{"/etc/letsencrypt/live/*/fullchain.pem", "/etc/letsencrypt/live/*/privkey.pem"},
		{"/etc/letsencrypt/open/fullchain.pem", "/etc/letsencrypt/open/privkey.pem"},
		{"/etc/ssl/certs/aegis.crt", "/etc/ssl/private/aegis.key"},
		{"/etc/pki/tls/certs/localhost.crt", "/etc/pki/tls/private/localhost.key"},
		// cPanel / WHM
		{"/var/cpanel/ssl/installed/certs/*.crt", "/var/cpanel/ssl/installed/keys/*.key"},
		// Plesk
		{"/usr/local/psa/var/certificates/*", "/usr/local/psa/var/certificates/*"},
	}

	for _, s := range searches {
		certs, _ := filepath.Glob(s.certPattern)
		if len(certs) == 0 {
			continue
		}

		for _, cert := range certs {
			// For each cert found, try to find a matching key
			// If the pattern itself was a direct path, keys will be searched 
			// the same way.
			keys, _ := filepath.Glob(s.keyPattern)
			for _, key := range keys {
				if _, err := os.Stat(cert); err == nil {
					if _, err := os.Stat(key); err == nil {
						return cert, key
					}
				}
			}
		}
	}

	return "", ""
}
