package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	target := flag.String("t", "http://localhost:8080", "Target URL to ping")
	count := flag.Int("c", 4, "Number of pings to send")
	interval := flag.Duration("i", 1*time.Second, "Interval between pings")
	flag.Parse()

	fmt.Printf("PING AegisEdge %s:\n", *target)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	successCount := 0
	var totalDuration time.Duration

	for i := 0; i < *count; i++ {
		start := time.Now()
		resp, err := client.Get(*target)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("Request %d: FAILED (%v)\n", i+1, err)
		} else {
			fmt.Printf("Response from %s: status=%d time=%v\n", *target, resp.StatusCode, duration)
			resp.Body.Close()
			successCount++
			totalDuration += duration
		}

		if i < *count-1 {
			time.Sleep(*interval)
		}
	}

	fmt.Printf("\n--- %s ping statistics ---\n", *target)
	fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n", *count, successCount, float64(*count-successCount)/float64(*count)*100)
	if successCount > 0 {
		fmt.Printf("avg time = %v\n", totalDuration/time.Duration(successCount))
	}

	if successCount == 0 {
		os.Exit(1)
	}
}
