package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/pkg/webhooksig"
)

// Headers on a signed webhook delivery.
//
// Aliases of the shared definitions: alerts and deployments sign identically,
// and an integrator who writes one verifier should not discover that the other
// feature spells the header differently.
const (
	// WebhookSignatureHeader carries the hex HMAC-SHA256.
	WebhookSignatureHeader = webhooksig.SignatureHeader
	// WebhookTimestampHeader carries the Unix seconds the signature covers.
	WebhookTimestampHeader = webhooksig.TimestampHeader
	// WebhookEventHeader lets a receiver route without parsing the body.
	WebhookEventHeader = webhooksig.EventHeader
)

// reservedWebhookHeaders are set by CertPilot and may not come from config.
// Keyed in canonical form, so the lookup and the check agree.
var reservedWebhookHeaders = map[string]bool{
	http.CanonicalHeaderKey(WebhookSignatureHeader): true,
	http.CanonicalHeaderKey(WebhookTimestampHeader): true,
	http.CanonicalHeaderKey(WebhookEventHeader):     true,
	"Content-Type": true,
}

// webhookConfig is the sealed configuration for a generic webhook.
type webhookConfig struct {
	URL string `json:"url"`
	// SigningSecret enables HMAC-SHA256 signing. Optional but strongly
	// recommended: without it a receiver has no way to tell a CertPilot alert
	// from anything else that can reach the endpoint.
	SigningSecret string `json:"signing_secret,omitempty"`
	// Headers are sent verbatim, for receivers that need an API key or a tenant
	// identifier. Sealed with the rest of the config.
	Headers map[string]string `json:"headers,omitempty"`
	// AllowInsecureHTTP permits a plain-http destination. Off by default, and
	// only worth turning on for a receiver inside a trusted network.
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
}

// WebhookPayload is the JSON body posted to a webhook receiver.
//
// A stable, documented shape: this is a public integration point, and a
// receiver that has to guess at the schema will break the first time an
// unrelated field is added.
type WebhookPayload struct {
	Severity  string  `json:"severity"`
	Topic     string  `json:"topic"`
	Title     string  `json:"title"`
	Summary   string  `json:"summary"`
	EntityID  string  `json:"entity_id,omitempty"`
	Fields    []Field `json:"fields,omitempty"`
	Timestamp string  `json:"timestamp"`
	Source    string  `json:"source"`
}

type webhookNotifier struct {
	cfg    webhookConfig
	client *http.Client
}

func newWebhookNotifier(raw []byte, client *http.Client) (Notifier, error) {
	var cfg webhookConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("webhook configuration is not valid JSON: %w", err)
	}

	cfg.URL = strings.TrimSpace(cfg.URL)
	if cfg.URL == "" {
		return nil, fmt.Errorf("a webhook needs a url")
	}

	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("url is not valid: %w", err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("url has no host")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !cfg.AllowInsecureHTTP {
			return nil, fmt.Errorf(
				"url must be https; set allow_insecure_http if the receiver is on a trusted network and cannot offer TLS")
		}
	default:
		return nil, fmt.Errorf("url scheme %q is not supported; use https", parsed.Scheme)
	}

	// Reserved headers are rejected rather than silently dropped: an operator
	// who set X-CertPilot-Signature by hand believes their receiver is
	// verifying something, and would never find out otherwise.
	//
	// Both sides go through CanonicalHeaderKey. The constants are not already in
	// canonical form — Go title-cases each dash-separated token, so
	// "X-CertPilot-Signature" canonicalises to "X-Certpilot-Signature" — and
	// comparing a canonicalised name against a raw constant silently matches
	// nothing, which is how this check first shipped doing exactly the thing it
	// exists to prevent.
	for name, value := range cfg.Headers {
		if reservedWebhookHeaders[http.CanonicalHeaderKey(name)] {
			return nil, fmt.Errorf("header %q is set by CertPilot and cannot be overridden", name)
		}
		if sanitizeHeaderValue(value) != value {
			return nil, fmt.Errorf("header %q contains a line break", name)
		}
	}

	if cfg.SigningSecret != "" && len(cfg.SigningSecret) < 16 {
		return nil, fmt.Errorf("signing_secret should be at least 16 characters; a short one is not worth the false confidence")
	}

	return &webhookNotifier{cfg: cfg, client: client}, nil
}

func (w *webhookNotifier) Type() string { return TypeWebhook }

func (w *webhookNotifier) Send(ctx context.Context, alert Alert) error {
	body, err := json.Marshal(WebhookPayload{
		Severity:  normalizeSeverity(alert.Severity),
		Topic:     alert.Topic,
		Title:     alert.Title,
		Summary:   alert.Summary,
		EntityID:  alert.EntityID,
		Fields:    alert.Fields,
		Timestamp: alert.Timestamp.UTC().Format(time.RFC3339),
		Source:    "certpilot",
	})
	if err != nil {
		return fmt.Errorf("could not encode the webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(WebhookEventHeader, sanitizeHeaderValue(alert.Topic))
	for name, value := range w.cfg.Headers {
		req.Header.Set(name, value)
	}

	if w.cfg.SigningSecret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set(WebhookTimestampHeader, ts)
		req.Header.Set(WebhookSignatureHeader, SignWebhook(w.cfg.SigningSecret, ts, body))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("the webhook returned %d: %s",
		resp.StatusCode, fallback(strings.TrimSpace(string(detail)), "no detail"))
}

// SignWebhook returns the hex HMAC-SHA256 a receiver should reproduce.
//
// The signed string is `<unix-seconds> "." <raw request body>`: the timestamp
// is inside it, not merely alongside, so a captured delivery cannot be replayed
// indefinitely. See package webhooksig for the full reasoning — the scheme
// lives there because deployments sign the same way, and two copies of a
// signature format is how an integrator ends up with a verifier that works for
// one feature and not for the other.
func SignWebhook(secret, timestamp string, body []byte) string {
	return webhooksig.Sign(secret, timestamp, body)
}

// VerifyWebhook checks a signature in constant time and enforces a freshness
// window. Provided so the property the sender promises is testable, and so a Go
// receiver has no reason to hand-roll the comparison with ==.
func VerifyWebhook(secret, timestamp, signature string, body []byte, tolerance time.Duration) error {
	return webhooksig.Verify(secret, timestamp, signature, body, tolerance)
}
