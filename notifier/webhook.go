package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"aegisedge/logger"
)

type WebhookMessage struct {
	Text      string    `json:"text"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
}

func SendAlert(msg string, severity string) {
	webhookURL := os.Getenv("AEGISEDGE_WEBHOOK_URL")
	if webhookURL == "" {
		return
	}

	payload := WebhookMessage{
		Text:      fmt.Sprintf("[AegisEdge Alert] %s", msg),
		Timestamp: time.Now(),
		Severity:  severity,
	}

	data, _ := json.Marshal(payload)
	
	// Professional async notification to avoid blocking traffic
	go func() {
		resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(data))
		if err != nil {
			logger.Error("Failed to send webhook alert", "err", err)
			return
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			logger.Warn("Webhook returned non-OK status", "status", resp.Status)
		}
	}()
}
