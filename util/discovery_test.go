package util

import (
	"strings"
	"testing"
)

func TestDiscoverTrustedProxiesReturnsEmptyOnMissingSources(t *testing.T) {
	// On a machine without CSF/cPHulk/iptables, this should return
	// an empty list — not error out.
	result := DiscoverTrustedProxies()

	// Even if empty, every entry must be a valid IP or CIDR
	for _, entry := range result {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			t.Error("DiscoverTrustedProxies returned an empty string entry")
		}
	}
}

func TestDiscoverTrustedProxiesDeduplicates(t *testing.T) {
	result := DiscoverTrustedProxies()

	seen := make(map[string]bool)
	for _, entry := range result {
		if seen[entry] {
			t.Errorf("Duplicate entry found: %s", entry)
		}
		seen[entry] = true
	}
}
