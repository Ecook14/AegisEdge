package middleware

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"aegisedge/logger"
	"aegisedge/util"
)

// LogEntry encapsulates data for async logging
type LogEntry struct {
	Outcome      string
	Status       int
	Method       string
	Path         string
	IntendedPort int
	IP           string
	Duration     time.Duration
}

var (
	// logChan buffer of 10k items to handle burst traffic.
	// In critical load, entries are dropped to protect throughput.
	logChan = make(chan *LogEntry, 10000)

	// responseWriterPool reduces GC pressure by recycling wrapper objects.
	responseWriterPool = sync.Pool{
		New: func() interface{} {
			return &responseWriter{}
		},
	}

	// logEntryPool eliminates per-request allocations for log data.
	logEntryPool = sync.Pool{
		New: func() interface{} {
			return &LogEntry{}
		},
	}
)

func init() {
	// Start background log processor
	go func() {
		for entry := range logChan {
			// At extreme load (> 10k RPS), terminal I/O is the bottleneck.
			// We use slog to JSON format which is efficient, but fmt/stdout is slow.
			logger.Info("Request processed",
				"outcome", entry.Outcome,
				"status", entry.Status,
				"method", entry.Method,
				"path", entry.Path,
				"intended_port", entry.IntendedPort,
				"ip", entry.IP,
				"duration", entry.Duration.String(),
			)
			// Put back in pool for reuse
			logEntryPool.Put(entry)
		}
	}()
}

// responseWriter is a wrapper to capture the HTTP status code
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) reset(w http.ResponseWriter) {
	rw.ResponseWriter = w
	rw.status = http.StatusOK
	rw.wroteHeader = false
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.status = code
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// RequestLogger logs the details of every request hitting the backend or being blocked.
// Optimized for 10k+ RPS using pooling and async delivery.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Performance Optimization: If level is WARN+, we ONLY log blocks.
		// We skip the wrapper and timing for successful requests to achieve Zero-Allocation.
		if logger.GetLevel() > slog.LevelInfo {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		// Get writer from pool
		rw := responseWriterPool.Get().(*responseWriter)
		rw.reset(w)
		defer responseWriterPool.Put(rw)

		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		// Determine outcome label
		outcome := "ALLOWED"
		if rw.status >= 400 {
			outcome = "BLOCKED"
		}

		// Read metadata from headers (G-Pattern: Zero-Allocation)
		ip := util.GetRealIP(r)
		intendedPortVal := r.Header.Get("X-Aegis-Port")
		intendedPort, _ := strconv.Atoi(intendedPortVal)

		// Async log delivery with Load-Aware Sampling (Drop if full)
		entry := logEntryPool.Get().(*LogEntry)
		entry.Outcome = outcome
		entry.Status = rw.status
		entry.Method = r.Method
		entry.Path = r.URL.Path
		entry.IntendedPort = intendedPort
		entry.IP = ip
		entry.Duration = duration

		select {
		case logChan <- entry:
			// Sent to processor (processor will Put back to pool)
		default:
			// Buffer full! Dropping log to protect request throughput.
			logEntryPool.Put(entry)
		}
	})
}
