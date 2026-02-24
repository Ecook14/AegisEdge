package filter

import (
	"testing"
	"time"

	"aegisedge/store"
)

func TestL4Filter(t *testing.T) {
	s := store.NewLocalStore()
	// Set a small limit of 2 conns per IP
	f := NewL4Filter(2, 1*time.Minute, s)

	addr := "1.1.1.1:1234"
	ip := "1.1.1.1"

	if !f.AllowConnection(addr) {
		t.Error("Initial connection should be allowed")
	}
	
	count, _ := s.GetCounter("l4:conn:" + ip)
	if count != 1 {
		t.Errorf("Expected 1 connection in store for %s, got %d", ip, count)
	}

	if !f.AllowConnection(addr) {
		t.Error("Second connection should be allowed")
	}

	if f.AllowConnection(addr) {
		t.Error("Third connection should be blocked (limit is 2)")
	}

	f.ReleaseConnection(addr)
	count, _ = s.GetCounter("l4:conn:" + ip)
	if count != 1 {
		t.Errorf("Expected 1 connection after release, got %d", count)
	}
}
