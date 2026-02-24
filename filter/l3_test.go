package filter

import (
	"testing"
)

func TestL3Filter(t *testing.T) {
	f := &L3Filter{
		Blacklist: make(map[string]bool),
	}

	ip := "1.2.3.4"
	if f.IsBlacklisted(ip) {
		t.Errorf("Expected IP %s to not be blacklisted initially", ip)
	}

	f.AddIP(ip)
	if !f.IsBlacklisted(ip) {
		t.Errorf("Expected IP %s to be blacklisted after AddIP", ip)
	}

	f.AddIP("8.8.8.8")
	if !f.IsBlacklisted("8.8.8.8") {
		t.Error("Expected 8.8.8.8 to be blacklisted")
	}

	if f.IsBlacklisted("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to not be blacklisted")
	}
}
