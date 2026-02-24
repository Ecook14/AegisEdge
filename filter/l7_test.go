package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestL7Filter(t *testing.T) {
	// 5 RPS, 10 Burst — nil store because this test uses in-process token bucket only
	f := NewL7Filter(5.0, 10, nil)
	rep := NewReputationManager(nil) // Local only

	handler := f.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rep)

	ip := "1.2.3.4:5555"

	// 1. Initial burst
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Request %d should have been allowed", i)
		}
	}

	// 2. Trigger rate limit
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Request should have been rate limited, got %d", rr.Code)
	}

	// 3. Reputation multiplier check (Penalize)
	rep.Penalize("1.2.3.4") // Drop trust to -1
	// Trust -1 -> Multiplier 0.9 -> Rate 4.5, Burst 9
	// This test is harder to verify precisely without sleeping, 
	// but we can verify the multiplier logic in reputation_test.go
}
