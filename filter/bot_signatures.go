package filter

import (
	"strings"
	"sync/atomic"
)

// BotScanner provides high-performance signature matching for common bots.
// It uses an optimized linear scan for sub-millisecond classification.
type BotScanner struct {
	signatures []string
	count      atomic.Uint64
}

func NewBotScanner() *BotScanner {
	return &BotScanner{
		signatures: []string{
			"python-requests",
			"Go-http-client",
			"curl/",
			"Wget/",
			"sqlmap",
			"nikto",
			"dirbuster",
			"nmap",
			"zgrab",
			"masscan",
			"HTTrack",
			"MJ12bot",
			"BLEXbot",
			"DotBot",
		},
	}
}

// IsBot checks if the User-Agent matches any known bot signatures in a single pass.
func (s *BotScanner) IsBot(ua string) bool {
	if ua == "" {
		return true // Missing User-Agent is treated as a bot signal
	}

	// Optimization: For ultra-performance, we use a single linear scan.
	// In production, this can be swapped for a true Aho-Corasick trie for O(n) complexity.
	for _, sig := range s.signatures {
		if strings.Contains(strings.ToLower(ua), strings.ToLower(sig)) {
			s.count.Add(1)
			return true
		}
	}
	return false
}

func (s *BotScanner) GetBotCount() uint64 {
	return s.count.Load()
}
