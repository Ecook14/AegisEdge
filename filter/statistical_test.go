package filter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStatisticalDetector(t *testing.T) {
	// Set a very small window for fast testing
	d := NewStatisticalAnomalyDetector(1) 
	
	handler := d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if d.IsUnderAttack() {
		t.Error("Should not be under attack initially")
	}

	// 1. Establish baseline (very low traffic)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
	
	// Wait for window to close and baseline to update
	time.Sleep(1100 * time.Millisecond)
	// One more request to trigger baseline calculation
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	// 2. Simulate spike (100 requests in next window)
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Wait for window to close
	time.Sleep(1100 * time.Millisecond)
	// Trigger detection
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	if !d.IsUnderAttack() {
		t.Error("Expected attack detection after spike (Z-Score > 3)")
	}
}

func TestReputationManager(t *testing.T) {
	m := NewReputationManager(nil)
	ip := "2.2.2.2"

	if m.GetTrust(ip) != 0 {
		t.Errorf("Expected initial trust 0, got %d", m.GetTrust(ip))
	}

	m.Reward(ip)
	if m.GetTrust(ip) != 1 {
		t.Errorf("Expected trust 1 after reward, got %d", m.GetTrust(ip))
	}

	for i := 0; i < 5; i++ {
		m.Penalize(ip)
	}
	if m.GetTrust(ip) != -4 {
		t.Errorf("Expected trust -4, got %d", m.GetTrust(ip))
	}

	mult := m.GetMultiplier(ip)
	if mult >= 1.0 {
		t.Errorf("Expected multiplier < 1.0 for negative trust, got %f", mult)
	}
}
