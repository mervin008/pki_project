// Package notifications handles formatting and dispatching alerts to configured channels.
package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// Alert represents an event to be broadcast to notification channels.
type Alert struct {
	Level     string    `json:"level"` // INFO, WARNING, CRITICAL
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Entity    string    `json:"entity"`
	Timestamp time.Time `json:"timestamp"`
}

// Dispatcher manages dispatching alerts to configured channels.
type Dispatcher struct {
	store      store.Store
	httpClient *http.Client
}

// NewDispatcher creates a new notification dispatcher.
func NewDispatcher(s store.Store) *Dispatcher {
	return &Dispatcher{
		store: s,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Dispatch sends an alert to a specific webhook URL.
func (d *Dispatcher) DispatchWebhook(ctx context.Context, webhookURL string, alert Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with status %d", resp.StatusCode)
	}

	slog.Info("notification dispatched successfully", "title", alert.Title, "level", alert.Level)
	return nil
}
