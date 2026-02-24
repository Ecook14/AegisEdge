package store

import (
	"testing"
	"time"
)

func TestLocalStore(t *testing.T) {
	s := NewLocalStore()

	// 1. Basic Set/Get
	s.Set("key1", "val1", 0)
	val, _ := s.Get("key1")
	if val != "val1" {
		t.Errorf("Expected val1, got %s", val)
	}

	// 2. Increment
	count, _ := s.Increment("counter", 1*time.Minute)
	if count != 1 {
		t.Errorf("Expected 1, got %d", count)
	}
	count, _ = s.Increment("counter", 1*time.Minute)
	if count != 2 {
		t.Errorf("Expected 2, got %d", count)
	}

	// 3. Blocking
	ip := "1.1.1.1"
	if s.IsBlocked(ip) {
		t.Error("Should not be blocked initially")
	}
	s.Block(ip, 1*time.Minute, "temp")
	if !s.IsBlocked(ip) {
		t.Error("Should be blocked after Block")
	}
	s.Unblock(ip)
	if s.IsBlocked(ip) {
		t.Error("Should be unblocked after Unblock")
	}

	// 4. Expiry (short wait)
	s.Set("exp", "val", 100*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	// Trigger discovery of expiry via cleanup call or reading (LocalStore.Get checks on read)
	val, _ = s.Get("exp")
	if val != "" {
		t.Error("Expected value to be expired and empty")
	}
}
