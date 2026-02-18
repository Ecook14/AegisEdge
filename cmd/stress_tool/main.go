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

func main() {
	target := flag.String("target", "http://localhost:8080", "Target URL to test")
	concurrency := flag.Int("c", 10, "Concurrency level (number of goroutines)")
	requests := flag.Int("n", 100, "Total number of requests")
	mode := flag.String("mode", "clean", "Test mode: clean, sqli, xss, cmd, challenge")
	flag.Parse()

	fmt.Printf("Starting AegisEdge Stress Test\n")
	fmt.Printf("Targets:     %s\n", *target)
	fmt.Printf("Concurrency: %d routines\n", *concurrency)
	fmt.Printf("Requests:    %d total\n", *requests)
	fmt.Printf("Mode:         %s\n", *mode)
	fmt.Printf("----------------------------------\n")

	results := make(chan result, *requests)
	var wg sync.WaitGroup

	reqPerRoutine := *requests / *concurrency
	
	startTime := time.Now()

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: 10 * time.Second,
			}
			for j := 0; j < reqPerRoutine; j++ {
				url := *target
				switch *mode {
				case "sqli":
					url += "?id=1' OR '1'='1"
				case "xss":
					url += "?q=<script>alert(1)</script>"
				case "cmd":
					url += "?exec=;cat /etc/passwd"
				case "challenge":
					url += "?challenge=1"
				}

				reqStart := time.Now()
				resp, err := client.Get(url)
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

	totalDuration := time.Since(startTime)
	
	var latencies []time.Duration
	statusCodes := make(map[int]int)
	var totalLatency time.Duration

	for res := range results {
		statusCodes[res.status]++
		latencies = append(latencies, res.latency)
		totalLatency += res.latency
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	totalReqs := len(latencies)
	if totalReqs == 0 {
		fmt.Println("No requests completed.")
		return
	}

	avgLatency := totalLatency / time.Duration(totalReqs)
	p50 := latencies[int(float64(totalReqs)*0.5)]
	p90 := latencies[int(float64(totalReqs)*0.9)]
	p95 := latencies[int(float64(totalReqs)*0.95)]
	p99 := latencies[int(float64(totalReqs)*0.99)]

	fmt.Printf("\n--- Throughput & Timing ---\n")
	fmt.Printf("Total Time:     %v\n", totalDuration)
	fmt.Printf("Requests/sec:   %.2f\n", float64(totalReqs)/totalDuration.Seconds())
	fmt.Printf("Avg Latency:    %v\n", avgLatency)
	fmt.Printf("Min Latency:    %v\n", latencies[0])
	fmt.Printf("Max Latency:    %v\n", latencies[totalReqs-1])

	fmt.Printf("\n--- Latency Percentiles ---\n")
	fmt.Printf("  p50: %v\n", p50)
	fmt.Printf("  p90: %v\n", p90)
	fmt.Printf("  p95: %v\n", p95)
	fmt.Printf("  p99: %v\n", p99)

	fmt.Printf("\n--- Mitigation Summary ---\n")
	for code, count := range statusCodes {
		label := "Unknown"
		switch code {
		case 200: label = "Legitimate (Allowed)"
		case 400: label = "Blocked (WAF Policy)"
		case 403: label = "Blocked (L3/GeoIP/Anomaly)"
		case 429: label = "Shedded (L7 Rate Limit)"
		case 503: label = "Challenge (Tarpit Mode)"
		case 0:   label = "Connection Dropped"
		}
		fmt.Printf("  [%d] %-25s : %d\n", code, label, count)
	}
	fmt.Printf("----------------------------------\n")
}
