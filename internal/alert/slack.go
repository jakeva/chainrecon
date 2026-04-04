package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Slack sends alert events to a Slack incoming webhook URL.
type Slack struct {
	webhookURL string
	client     *http.Client
}

// NewSlack creates a notifier that posts formatted messages to Slack.
func NewSlack(webhookURL string) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// slackPayload is the Slack incoming webhook message format.
type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}

type slackBlock struct {
	Type string     `json:"type"`
	Text *slackText `json:"text,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Notify sends a formatted alert to Slack.
func (s *Slack) Notify(ctx context.Context, event Event) error {
	payload := s.buildPayload(event)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send slack message: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}
	return nil
}

// Name implements Notifier.
func (s *Slack) Name() string { return "slack" }

func (s *Slack) buildPayload(event Event) slackPayload {
	icon := riskIcon(event.RiskLevel)
	header := fmt.Sprintf("%s *chainrecon alert: %s@%s*", icon, event.Package, event.Version)

	var details strings.Builder
	fmt.Fprintf(&details, "Score: *%.1f* (threshold: %.1f)\n", event.TargetScore, event.Threshold)
	fmt.Fprintf(&details, "Risk: *%s*\n", event.RiskLevel)

	if len(event.Findings) > 0 {
		count := len(event.Findings)
		if count > 5 {
			count = 5
		}
		details.WriteString("\nTop findings:\n")
		for _, f := range event.Findings[:count] {
			fmt.Fprintf(&details, "  [%s] %s\n", f.Severity, f.Message)
		}
		if len(event.Findings) > 5 {
			fmt.Fprintf(&details, "  ... and %d more\n", len(event.Findings)-5)
		}
	}

	return slackPayload{
		Text: fmt.Sprintf("chainrecon alert: %s@%s score %.1f exceeds threshold", event.Package, event.Version, event.TargetScore),
		Blocks: []slackBlock{
			{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: header},
			},
			{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: details.String()},
			},
		},
	}
}

func riskIcon(level string) string {
	switch level {
	case "CRITICAL":
		return ":rotating_light:"
	case "HIGH":
		return ":warning:"
	case "MEDIUM":
		return ":large_yellow_circle:"
	default:
		return ":information_source:"
	}
}
