package filter

import (
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"aegisedge/logger"
)

// OrchestrationMonitor watches L7 block counters and fires external
// automation (Ansible playbook, shell script, webhook) when thresholds
// are exceeded. Runs as a background goroutine with a configurable tick.
type OrchestrationMonitor struct {
	l7Threshold   int
	playbookPath  string
	interval      time.Duration
	stop          chan struct{}
	wg            sync.WaitGroup
	lastTriggered time.Time
	cooldown      time.Duration
}

// orchestrationL7Blocks is an atomic counter incremented by the L7
// middleware whenever a request is blocked. The orchestration monitor
// reads and resets it each window to compute deltas without needing
// to scrape Prometheus.
var orchestrationL7Blocks int64

// IncrementL7Blocks should be called by the L7 filter on every block.
func IncrementL7Blocks() {
	atomic.AddInt64(&orchestrationL7Blocks, 1)
}

// NewOrchestrationMonitor reads thresholds from environment and returns
// a monitor that can be started with .Start().
//
// Environment:
//   - ANSIBLE_TRIGGER_THRESHOLD_L7: L7 block count per window that triggers automation (default: off)
//   - ANSIBLE_PLAYBOOK_PATH: path to playbook/script to execute (default: off)
//   - ANSIBLE_CHECK_INTERVAL: seconds between checks (default: 60)
//   - ANSIBLE_COOLDOWN: seconds between consecutive triggers (default: 300)
func NewOrchestrationMonitor() *OrchestrationMonitor {
	l7Limit, _ := strconv.Atoi(os.Getenv("ANSIBLE_TRIGGER_THRESHOLD_L7"))
	playbookPath := os.Getenv("ANSIBLE_PLAYBOOK_PATH")
	intervalSec, _ := strconv.Atoi(os.Getenv("ANSIBLE_CHECK_INTERVAL"))
	cooldownSec, _ := strconv.Atoi(os.Getenv("ANSIBLE_COOLDOWN"))

	if intervalSec <= 0 {
		intervalSec = 60
	}
	if cooldownSec <= 0 {
		cooldownSec = 300
	}

	return &OrchestrationMonitor{
		l7Threshold:  l7Limit,
		playbookPath: playbookPath,
		interval:     time.Duration(intervalSec) * time.Second,
		cooldown:     time.Duration(cooldownSec) * time.Second,
		stop:         make(chan struct{}),
	}
}

// Start begins the background monitoring loop. Safe to call even if
// thresholds are not configured — it will return immediately.
func (m *OrchestrationMonitor) Start() {
	if m.l7Threshold <= 0 || m.playbookPath == "" {
		if m.l7Threshold > 0 || m.playbookPath != "" {
			logger.Warn("Orchestration: both ANSIBLE_TRIGGER_THRESHOLD_L7 and ANSIBLE_PLAYBOOK_PATH required — monitor disabled")
		}
		return
	}

	logger.Info("External orchestration monitor started",
		"l7_threshold", m.l7Threshold,
		"playbook", m.playbookPath,
		"interval", m.interval,
		"cooldown", m.cooldown,
	)

	m.wg.Add(1)
	go m.run()
}

// Stop cleanly shuts down the background goroutine.
func (m *OrchestrationMonitor) Stop() {
	close(m.stop)
	m.wg.Wait()
}

func (m *OrchestrationMonitor) run() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.check()
		}
	}
}

func (m *OrchestrationMonitor) check() {
	// Atomically read and reset the window counter
	delta := atomic.SwapInt64(&orchestrationL7Blocks, 0)

	if delta < int64(m.l7Threshold) {
		return
	}

	// Cooldown: don't fire again too quickly after a trigger
	if time.Since(m.lastTriggered) < m.cooldown {
		logger.Info("Orchestration: threshold exceeded but in cooldown",
			"delta", delta, "threshold", m.l7Threshold,
			"cooldown_remaining", m.cooldown-time.Since(m.lastTriggered),
		)
		return
	}

	logger.Warn("Orchestration: L7 threshold exceeded — executing playbook",
		"delta", delta, "threshold", m.l7Threshold, "playbook", m.playbookPath,
	)

	m.lastTriggered = time.Now()

	cmd := exec.Command(m.playbookPath)
	cmd.Env = append(os.Environ(),
		"AEGISEDGE_L7_DELTA="+strconv.FormatInt(delta, 10),
		"AEGISEDGE_L7_THRESHOLD="+strconv.Itoa(m.l7Threshold),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Orchestration: playbook execution failed",
			"err", err, "output", string(output),
		)
		return
	}

	logger.Info("Orchestration: playbook executed successfully",
		"output_len", len(output),
	)
}
