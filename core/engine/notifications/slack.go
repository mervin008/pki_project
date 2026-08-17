package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// slackConfig is the sealed configuration for a Slack channel.
type slackConfig struct {
	// WebhookURL is a Slack incoming webhook. It is a bearer credential:
	// anyone holding it can post to the channel, which is why it is sealed at
	// rest and never returned by any endpoint.
	WebhookURL string `json:"webhook_url"`
	// Username and IconEmoji override the app's defaults where the workspace
	// permits it. Optional.
	Username  string `json:"username,omitempty"`
	IconEmoji string `json:"icon_emoji,omitempty"`
}

type slackNotifier struct {
	cfg    slackConfig
	client *http.Client
}

func newSlackNotifier(raw []byte, client *http.Client) (Notifier, error) {
	var cfg slackConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("slack configuration is not valid JSON: %w", err)
	}

	cfg.WebhookURL = strings.TrimSpace(cfg.WebhookURL)
	if cfg.WebhookURL == "" {
		return nil, fmt.Errorf("slack needs a webhook_url — create one under Incoming Webhooks in your Slack app")
	}

	parsed, err := url.Parse(cfg.WebhookURL)
	if err != nil {
		return nil, fmt.Errorf("webhook_url is not a valid URL: %w", err)
	}
	// A webhook URL is a credential, so it may not travel in the clear. Checked
	// here rather than trusted to the operator, because the failure is silent:
	// the alert still arrives, and the URL is simply readable to the network.
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf(
			"webhook_url must be https (got %q) — the URL is a credential and must not travel unencrypted",
			parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("webhook_url has no host")
	}

	return &slackNotifier{cfg: cfg, client: client}, nil
}

func (s *slackNotifier) Type() string { return TypeSlack }

// Slack attachment colours by severity. Block Kit has no colour of its own, so
// the blocks are wrapped in a single attachment purely to get the coloured bar —
// which is the part that is legible while scrolling past.
func severityColour(severity string) string {
	switch normalizeSeverity(severity) {
	case "CRITICAL":
		return "#dc2626"
	case "WARNING":
		return "#f59e0b"
	default:
		return "#2563eb"
	}
}

func severityPrefix(severity string) string {
	switch normalizeSeverity(severity) {
	case "CRITICAL":
		return ":rotating_light: CRITICAL"
	case "WARNING":
		return ":warning: WARNING"
	default:
		return ":information_source: INFO"
	}
}

func (s *slackNotifier) Send(ctx context.Context, alert Alert) error {
	body, err := json.Marshal(s.payload(alert))
	if err != nil {
		return fmt.Errorf("could not encode the Slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach Slack: %w", err)
	}
	defer resp.Body.Close()

	// Slack answers with a short plain-text reason — "invalid_token",
	// "channel_not_found" — which is far more useful than the status code, so
	// it is carried through rather than replaced with a generic message.
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	reason := strings.TrimSpace(string(detail))

	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusNotFound || reason == "no_service":
		return fmt.Errorf("Slack rejected the webhook as unknown — it may have been revoked or the app uninstalled (%s)", reason)
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("Slack is rate limiting this webhook (429); the alert was not delivered")
	default:
		return fmt.Errorf("Slack returned %d: %s", resp.StatusCode, fallback(reason, "no detail"))
	}
}

// payload builds a Block Kit message inside one coloured attachment.
func (s *slackNotifier) payload(alert Alert) map[string]any {
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type": "plain_text",
				// Slack truncates a header at 150 characters and rejects the
				// message outright above it, so this is cut rather than risked.
				"text":  truncate(fmt.Sprintf("%s", alert.Title), 148),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s*\n%s", severityPrefix(alert.Severity), escapeSlack(alert.Summary)),
			},
		},
	}

	if len(alert.Fields) > 0 {
		// Slack permits at most 10 fields in a section.
		fields := make([]map[string]any, 0, 10)
		for _, f := range alert.Fields {
			if len(fields) == 10 {
				break
			}
			fields = append(fields, map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s*\n%s", escapeSlack(f.Label), escapeSlack(f.Value)),
			})
		}
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}

	context := fmt.Sprintf("CertPilot · %s · %s",
		escapeSlack(alert.Topic), alert.Timestamp.UTC().Format("2006-01-02 15:04:05 MST"))
	blocks = append(blocks, map[string]any{
		"type":     "context",
		"elements": []map[string]any{{"type": "mrkdwn", "text": context}},
	})

	payload := map[string]any{
		// Plain text alongside the blocks: this is what Slack shows in a
		// notification popup and in the mobile lock screen, which for an alerting
		// tool is where it will most often be read first.
		"text": fmt.Sprintf("[%s] %s", normalizeSeverity(alert.Severity), alert.Title),
		"attachments": []map[string]any{
			{"color": severityColour(alert.Severity), "blocks": blocks},
		},
	}
	if s.cfg.Username != "" {
		payload["username"] = s.cfg.Username
	}
	if s.cfg.IconEmoji != "" {
		payload["icon_emoji"] = s.cfg.IconEmoji
	}
	return payload
}

// escapeSlack escapes the three characters Slack treats as markup control.
//
// A CA's common name is not authored by CertPilot, and an unescaped `<` turns
// the rest of an alert into a malformed link.
func escapeSlack(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
