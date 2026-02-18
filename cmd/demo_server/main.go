package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "--- AegisEdge Demo Upstream ---\n")
		fmt.Fprintf(w, "Time: %s\n", time.Now().Format(time.RFC1123))
		fmt.Fprintf(w, "Path: %s\n", r.URL.Path)
		fmt.Fprintf(w, "RemoteAddr: %s\n", r.RemoteAddr)
		fmt.Fprintf(w, "User-Agent: %s\n", r.UserAgent())
		log.Printf("Matched: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	})

	mux.HandleFunc("/api/heavy-export", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Simulate work
		fmt.Fprintf(w, "Heavy data export complete\n")
	})

	port := "127.0.0.1:3000"
	log.Printf("Demo Upstream Server starting on %s...", port)
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatal(err)
	}
}
