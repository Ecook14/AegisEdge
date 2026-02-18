package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	target := flag.String("target", "http://localhost:8080", "Target URL to test")
	concurrency := flag.Int("c", 10, "Concurrency level (number of goroutines)")
	requests := flag.Int("n", 100, "Total number of requests")
	mode := flag.String("mode", "clean", "Test mode: clean, sqli, xss, cmd, challenge")
	flag.Parse()

	fmt.Printf("Starting stress test: target=%s, c=%d, n=%d, mode=%s\n", *target, *concurrency, *requests, *mode)

	results := make(chan int, *requests)
	var wg sync.WaitGroup

	reqPerRoutine := *requests / *concurrency
	
	startTime := time.Now()

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: 5 * time.Second,
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

				resp, err := client.Get(url)
				if err != nil {
					results <- 0
					continue
				}
				results <- resp.StatusCode
				resp.Body.Close()
			}
		}()
	}

	wg.Wait()
	close(results)

	duration := time.Since(startTime)
	
	stats := make(map[int]int)
	total := 0
	for status := range results {
		stats[status]++
		total++
	}

	fmt.Printf("\n--- Results ---\n")
	fmt.Printf("Total Requests: %d\n", total)
	fmt.Printf("Time Taken:     %v\n", duration)
	fmt.Printf("Requests/sec:   %.2f\n", float64(total)/duration.Seconds())
	fmt.Printf("\nStatus Codes:\n")
	for code, count := range stats {
		label := ""
		switch code {
		case 200: label = "OK"
		case 400: label = "Bad Request (Blocked by WAF)"
		case 403: label = "Forbidden (Blocked by L3/GeoIP)"
		case 429: label = "Too Many Requests (Blocked by L7)"
		case 503: label = "Service Unavailable (Challenge/Tarpit)"
		case 0: label = "Connection Error"
		}
		fmt.Printf("  %d [%s]: %d\n", code, label, count)
	}
}
