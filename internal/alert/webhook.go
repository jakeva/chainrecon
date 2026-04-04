package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Webhook sends alert events as JSON POST requests to a URL.
type Webhook struct {
	url    string
	client *http.Client
}

// NewWebhook creates a notifier that POSTs JSON to the given URL.
func NewWebhook(url string) *Webhook {
	return &Webhook{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Notify sends the event as a JSON POST request.
func (w *Webhook) Notify(ctx context.Context, event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "chainrecon-alert/1.0")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// Name implements Notifier.
func (w *Webhook) Name() string { return "webhook" }
