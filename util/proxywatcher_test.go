package util

import (
	"testing"
	"time"
)

func TestProxyWatcherManualEntries(t *testing.T) {
	pw := NewProxyWatcher("192.168.1.1,10.0.0.0/8", 1*time.Hour)
	defer pw.Stop()

	// Trusted entries should match
	if !pw.IsTrusted("192.168.1.1") {
		t.Error("Expected 192.168.1.1 to be trusted")
	}

	// IP within the CIDR should match
	if !pw.IsTrusted("10.0.0.5") {
		t.Error("Expected 10.0.0.5 (in 10.0.0.0/8) to be trusted")
	}

	// Random IP should NOT be trusted
	if pw.IsTrusted("8.8.8.8") {
		t.Error("Expected 8.8.8.8 to NOT be trusted")
	}
}

func TestProxyWatcherAddRemove(t *testing.T) {
	pw := NewProxyWatcher("", 1*time.Hour)
	defer pw.Stop()

	// Initially nothing trusted
	if pw.IsTrusted("1.2.3.4") {
		t.Error("Expected 1.2.3.4 to NOT be trusted initially")
	}

	// Add and verify
	pw.AddManual("1.2.3.4")
	if !pw.IsTrusted("1.2.3.4") {
		t.Error("Expected 1.2.3.4 to be trusted after AddManual")
	}

	// Add a CIDR
	pw.AddManual("172.16.0.0/12")
	if !pw.IsTrusted("172.20.5.10") {
		t.Error("Expected 172.20.5.10 (in 172.16.0.0/12) to be trusted after AddManual")
	}

	// Remove and verify
	pw.RemoveManual("1.2.3.4")
	if pw.IsTrusted("1.2.3.4") {
		t.Error("Expected 1.2.3.4 to NOT be trusted after RemoveManual")
	}

	// CIDR should still be there
	if !pw.IsTrusted("172.20.5.10") {
		t.Error("Expected 172.20.5.10 to still be trusted")
	}
}

func TestProxyWatcherReload(t *testing.T) {
	pw := NewProxyWatcher("192.168.0.1", 1*time.Hour)
	defer pw.Stop()

	// Should not panic or break
	pw.Reload()

	// Original manual entry should persist
	if !pw.IsTrusted("192.168.0.1") {
		t.Error("Expected 192.168.0.1 to be trusted after Reload")
	}
}

func TestProxyWatcherEmptyInit(t *testing.T) {
	pw := NewProxyWatcher("", 1*time.Hour)
	defer pw.Stop()

	// Nothing should be trusted
	if pw.IsTrusted("127.0.0.1") {
		t.Error("Expected 127.0.0.1 to NOT be trusted with empty init")
	}
}
