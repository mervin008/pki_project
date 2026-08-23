package solver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Webhook solves dns-01 challenges by POSTing to an endpoint the operator
// controls.
//
// This exists so CertPilot does not have to implement a solver for every DNS
// provider that will ever matter. Anyone running an unusual or internal DNS
// system writes a small receiver instead of patching the gateway. Requests are
// optionally signed with HMAC-SHA256 so the receiver can verify they came from
// CertPilot before touching a zone.
type Webhook struct {
	url           string
	bearerToken   string
	signingSecret string
	httpClient    *http.Client
}

// WebhookRequest is the JSON body sent to the endpoint.
type WebhookRequest struct {
	// Action is "present" or "cleanup".
	Action string `json:"action"`
	// Type is the ACME challenge type, always "dns-01" here.
	Type string `json:"type"`
	// Domain is the identifier under validation.
	Domain string `json:"domain"`
	// FQDN is the record name to write, e.g. "_acme-challenge.example.com".
	FQDN string `json:"fqdn"`
	// Value is the TXT record contents.
	Value string `json:"value"`
	// Token is the ACME challenge token, for correlation in the receiver's logs.
	Token string `json:"token"`
}

// SignatureHeader carries the hex HMAC-SHA256 of the request body.
const SignatureHeader = "X-CertPilot-Signature"

// NewWebhook builds a webhook DNS-01 solver. bearerToken and signingSecret are
// both optional; supplying at least one is strongly recommended, since the
// receiver is being asked to write DNS records.
func NewWebhook(endpoint, bearerToken, signingSecret string) (*Webhook, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("webhook: url is required")
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("webhook: url must be http or https, got %q", endpoint)
	}

	return &Webhook{
		url:           endpoint,
		bearerToken:   bearerToken,
		signingSecret: signingSecret,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Type implements Solver.
func (w *Webhook) Type() string { return TypeDNS01 }

// Present asks the endpoint to publish the TXT record.
func (w *Webhook) Present(ctx context.Context, ch Challenge) error {
	return w.call(ctx, "present", ch)
}

// CleanUp asks the endpoint to remove it.
func (w *Webhook) CleanUp(ctx context.Context, ch Challenge) error {
	return w.call(ctx, "cleanup", ch)
}

func (w *Webhook) call(ctx context.Context, action string, ch Challenge) error {
	payload := WebhookRequest{
		Action: action,
		Type:   TypeDNS01,
		Domain: ch.Domain,
		FQDN:   ch.FQDN(),
		Value:  ch.Value,
		Token:  ch.Token,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.bearerToken)
	}
	if w.signingSecret != "" {
		mac := hmac.New(sha256.New, []byte(w.signingSecret))
		mac.Write(body)
		req.Header.Set(SignatureHeader, hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %s request failed: %w", action, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("webhook: %s returned status %d: %s", action, resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	slog.Debug("webhook solver call succeeded", "action", action, "fqdn", payload.FQDN)
	return nil
}
