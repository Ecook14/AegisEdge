package main

import (
	"flag"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

type result struct {
	status  int
	latency time.Duration
}

var modeDescriptions = map[string]struct {
	description string
	expected    string
}{
	"clean":     {"No payload — plain GET requests", "200 OK (pass-through)"},
	"sqli":      {"Injects: ?id=1' OR '1'='1", "400 Bad Request (WAF: SQLi rule)"},
	"xss":       {"Injects: ?q=<script>alert(1)</script>", "400 Bad Request (WAF: XSS rule)"},
	"cmd":       {"Injects: ?exec=;cat /etc/passwd", "400 Bad Request (WAF: CMDi rule)"},
	"traversal": {"Injects: /../../../etc/passwd in path", "400 Bad Request (WAF: Path Traversal rule)"},
	"challenge": {"Sends ?challenge=1 (legacy), no ae_clearance cookie", "503 Service Unavailable (Challenge gate)"},
	"bot":       {"Sends requests with no User-Agent header", "403 Forbidden (Tarpit + L7 header check)"},
	"flood":     {"Max-speed clean requests — no concurrency cap", "429 Too Many Requests (L7 Token Bucket)"},
}

func buildURL(base, mode string) string {
	switch mode {
	case "sqli":
		return base + "?id=1' OR '1'='1"
	case "xss":
		return base + "?q=<script>alert(1)</script>"
	case "cmd":
		return base + "?exec=;cat /etc/passwd"
	case "traversal":
		return base + "/../../../../etc/passwd"
	case "challenge":
		return base + "?challenge=1"
	default:
		return base
	}
}

func main() {
	target := flag.String("target", "http://127.0.0.1:3000", "Target URL to test (App Port: 3000, Live: 80/443)")
	concurrency := flag.Int("c", 10, "Concurrency level (parallel goroutines)")
	requests := flag.Int("n", 100, "Total number of requests")
	mode := flag.String("mode", "clean", "Test mode: clean|sqli|xss|cmd|traversal|challenge|bot|flood")
	flag.Parse()

	info, ok := modeDescriptions[*mode]
	if !ok {
		fmt.Printf("Unknown mode: %s\nAvailable: clean, sqli, xss, cmd, traversal, challenge, bot, flood\n", *mode)
		return
	}

	fmt.Printf("\n╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║          AegisEdge Stress & Verification Tool    ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Printf("  Target:      %s\n", *target)
	fmt.Printf("  Mode:        %s\n", *mode)
	if *target == "http://127.0.0.1:3000" || *target == "http://127.0.0.1:80" || *target == "http://127.0.0.1:443" {
		fmt.Printf("  Notice:      Shield (Proxy) is active if Hot Takeover is enabled.\n")
	}
	fmt.Printf("  Payload:     %s\n", info.description)
	fmt.Printf("  Expected:    %s\n", info.expected)

	if *mode == "flood" {
		// Flood mode: ignore -c and -n, just hammer as fast as possible for 5 seconds
		fmt.Printf("  Duration:    5 seconds (ignores -n and -c)\n")
		fmt.Printf("──────────────────────────────────────────────────\n\n")
		runFlood(*target)
		return
	}

	fmt.Printf("  Concurrency: %d goroutines\n", *concurrency)
	fmt.Printf("  Requests:    %d total\n", *requests)
	fmt.Printf("──────────────────────────────────────────────────\n\n")

	results := make(chan result, *requests)
	var wg sync.WaitGroup

	reqPerRoutine := *requests / *concurrency
	if reqPerRoutine == 0 {
		reqPerRoutine = 1
	}
	startTime := time.Now()

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 10 * time.Second}
			for j := 0; j < reqPerRoutine; j++ {
				url := buildURL(*target, *mode)

				req, _ := http.NewRequest("GET", url, nil)

				// bot mode: explicitly omit User-Agent
				if *mode != "bot" {
					req.Header.Set("User-Agent", "AegisEdge-StressBot/2.0")
					req.Header.Set("Accept", "text/html,application/xhtml+xml")
					req.Header.Set("Accept-Language", "en-US,en;q=0.9")
					req.Header.Set("Accept-Encoding", "gzip, deflate")
				}

				reqStart := time.Now()
				resp, err := client.Do(req)
				duration := time.Since(reqStart)
				if err != nil {
					results <- result{status: 0, latency: duration}
					continue
				}
				results <- result{status: resp.StatusCode, latency: duration}
				resp.Body.Close()
			}
		}()
	}

	wg.Wait()
	close(results)

	printReport(results, time.Since(startTime))
}

// runFlood fires requests as fast as possible for 5 seconds to trigger the token bucket.
func runFlood(target string) {
	results := make(chan result, 100000)
	done := make(chan struct{})
	startTime := time.Now()

	for i := 0; i < 50; i++ {
		go func() {
			client := &http.Client{Timeout: 5 * time.Second}
			for {
				select {
				case <-done:
					return
				default:
					req, _ := http.NewRequest("GET", target, nil)
					req.Header.Set("User-Agent", "AegisEdge-FloodTest/2.0")
					req.Header.Set("Accept", "text/html")
					reqStart := time.Now()
					resp, err := client.Do(req)
					duration := time.Since(reqStart)
					if err != nil {
						select {
						case results <- result{status: 0, latency: duration}:
						default:
						}
						continue
					}
					select {
					case results <- result{status: resp.StatusCode, latency: duration}:
					default:
					}
					resp.Body.Close()
				}
			}
		}()
	}

	time.Sleep(80 * time.Second)
	close(done)
	time.Sleep(200 * time.Millisecond) // let goroutines drain
	close(results)

	printReport(results, time.Since(startTime))
}

func printReport(results <-chan result, totalDuration time.Duration) {
	var latencies []time.Duration
	statusCodes := make(map[int]int)
	var totalLatency time.Duration

	for res := range results {
		statusCodes[res.status]++
		latencies = append(latencies, res.latency)
		totalLatency += res.latency
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	totalReqs := len(latencies)
	if totalReqs == 0 {
		fmt.Println("No requests completed.")
		return
	}

	avgLatency := totalLatency / time.Duration(totalReqs)
	p50 := latencies[int(float64(totalReqs)*0.50)]
	p90 := latencies[int(float64(totalReqs)*0.90)]
	p95 := latencies[int(float64(totalReqs)*0.95)]
	p99idx := int(float64(totalReqs) * 0.99)
	if p99idx >= totalReqs {
		p99idx = totalReqs - 1
	}
	p99 := latencies[p99idx]

	fmt.Printf("━━━ Throughput & Timing ━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  Total Time:      %v\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("  Total Requests:  %d\n", totalReqs)
	fmt.Printf("  Requests/sec:    %.0f\n", float64(totalReqs)/totalDuration.Seconds())
	fmt.Printf("  Avg Latency:     %v\n", avgLatency.Round(time.Microsecond))
	fmt.Printf("  Min Latency:     %v\n", latencies[0].Round(time.Microsecond))
	fmt.Printf("  Max Latency:     %v\n", latencies[totalReqs-1].Round(time.Microsecond))

	fmt.Printf("\n━━━ Latency Percentiles ━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("  p50: %v\n", p50.Round(time.Microsecond))
	fmt.Printf("  p90: %v\n", p90.Round(time.Microsecond))
	fmt.Printf("  p95: %v\n", p95.Round(time.Microsecond))
	fmt.Printf("  p99: %v\n", p99.Round(time.Microsecond))

	fmt.Printf("\n━━━ Mitigation Breakdown ━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	statusLabels := map[int]string{
		200: "✅  Legitimate (Allowed)",
		302: "↩️  Redirected (Challenge Token Accepted)",
		400: "🚫  Blocked (WAF: SQLi/XSS/CMDi/Traversal)",
		403: "🚫  Blocked (L3 Blacklist / GeoIP / Fingerprint / Bot)",
		429: "⏱️  Shed (L7 Token Bucket Rate Limiter)",
		503: "🛡️  Challenged (Browser Verification Gate)",
		0:   "💀  Connection Dropped / Timeout",
	}
	for code, count := range statusCodes {
		label := statusLabels[code]
		if label == "" {
			label = fmt.Sprintf("HTTP %d", code)
		}
		pct := float64(count) / float64(totalReqs) * 100
		fmt.Printf("  %-45s : %5d  (%.1f%%)\n", label, count, pct)
	}
	fmt.Printf("──────────────────────────────────────────────────\n")
}
