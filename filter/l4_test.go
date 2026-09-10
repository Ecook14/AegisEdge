package filter

import (
	"testing"
	"time"

	"aegisedge/store"
)

func TestL4Filter(t *testing.T) {
	s := store.NewLocalStore()
	// Set a small limit of 2 conns per IP
	f := NewL4Filter(2, 1*time.Minute, s, []string{"127.0.0.1"})

	addr := "1.1.1.1:1234"
	ip := "1.1.1.1"

	if !f.AllowConnection(addr) {
		t.Error("Initial connection should be allowed")
	}

	count, err := s.GetCounter("l4:conn:" + ip)
	if err != nil {
		t.Fatalf("GetCounter failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 connection in store for %s, got %d", ip, count)
	}

	if !f.AllowConnection(addr) {
		t.Error("Second connection should be allowed")
	}

	// Third connection should be blocked (limit is 2)
	if f.AllowConnection(addr) {
		t.Error("Third connection should be blocked (limit is 2)")
	}

	// Whitelist bypass
	if !f.AllowConnection("127.0.0.1:9999") {
		t.Error("Whitelisted IP should always be allowed")
	}

	f.ReleaseConnection(addr)
	count, err = s.GetCounter("l4:conn:" + ip)
	if err != nil {
		t.Fatalf("GetCounter failed: %v", err)
	}
	// After releasing one of two held connections, count decrements to 1
	// The limit is 2, so 2 connections held -> count is 2, releasing one -> count=1
	// After releasing both, count=0
	if count != 1 {
		t.Errorf("Expected 1 connection after one release, got %d", count)
	}

	// Release again
	f.ReleaseConnection(addr)
	count, err = s.GetCounter("l4:conn:" + ip)
	if err != nil {
		t.Fatalf("GetCounter failed: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 connections after second release, got %d", count)
	}

	// Zero limit = bypass
	f2 := NewL4Filter(0, 1*time.Minute, s, nil)
	if !f2.AllowConnection("10.0.0.1:1234") {
		t.Error("Zero limit should allow all connections")
	}
}
