package notifications

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func buildWebhook(t *testing.T, config string) Notifier {
	t.Helper()
	n, err := Build(TypeWebhook, []byte(config), DefaultClient())
	if err != nil {
		t.Fatalf("Build(%s): %v", config, err)
	}
	return n
}

func TestWebhookConfigRejectsWhatCannotWork(t *testing.T) {
	cases := map[string]struct {
		config string
		want   string
	}{
		"no url":              {`{}`, "needs a url"},
		"no host":             {`{"url":"https://"}`, "no host"},
		"unsupported scheme":  {`{"url":"ftp://example.com/hook"}`, "not supported"},
		"malformed json":      {`{"url":`, "not valid JSON"},
		"short secret":        {`{"url":"https://x.test/h","signing_secret":"tooshort"}`, "at least 16"},
		"header with newline": {`{"url":"https://x.test/h","headers":{"X-Tenant":"a\nBcc: x"}}`, "line break"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Build(TypeWebhook, []byte(tc.config), DefaultClient())
			if err == nil {
				t.Fatalf("accepted a configuration that cannot deliver")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Plain http would put whatever the destination authenticates with — and the
// alert content itself — on the wire in the clear. Allowed, but only when it has
// been asked for by name.
func TestWebhookRefusesPlainHTTPUnlessAskedFor(t *testing.T) {
	if _, err := Build(TypeWebhook, []byte(`{"url":"http://relay.internal/hook"}`), DefaultClient()); err == nil {
		t.Fatal("plain http was accepted without allow_insecure_http")
	}
	if _, err := Build(TypeWebhook,
		[]byte(`{"url":"http://relay.internal/hook","allow_insecure_http":true}`), DefaultClient()); err != nil {
		t.Fatalf("plain http was refused even when asked for: %v", err)
	}
}

// An operator who sets X-CertPilot-Signature by hand believes their receiver is
// verifying something. Silently overwriting it would leave that belief intact
// and wrong.
func TestWebhookRefusesToOverrideItsOwnHeaders(t *testing.T) {
	for _, header := range []string{WebhookSignatureHeader, WebhookTimestampHeader, WebhookEventHeader, "Content-Type"} {
		config := `{"url":"https://x.test/h","headers":{"` + header + `":"anything"}}`
		if _, err := Build(TypeWebhook, []byte(config), DefaultClient()); err == nil {
			t.Errorf("%s could be overridden by configuration", header)
		}
	}
}

func TestWebhookPostsASignedPayload(t *testing.T) {
	const secret = "a-secret-long-enough-to-be-accepted"

	var (
		gotBody   []byte
		gotHeader http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHeader = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := buildWebhook(t, `{"url":"`+srv.URL+`","allow_insecure_http":true,"signing_secret":"`+secret+`","headers":{"X-Tenant":"acme"}}`)

	alert := Alert{
		Severity: "CRITICAL", Topic: "ca.expiry_alert",
		Title: "CA expiring: Corporate Issuing CA", Summary: "It expires in 9 days.",
		EntityID: "ca-1", Timestamp: time.Unix(1_700_000_000, 0),
		Fields: []Field{{Label: "Days remaining", Value: "9 days"}},
	}
	if err := n.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// The receiver must be able to verify what it was sent, using the exported
	// helper an integrator would use.
	ts := gotHeader.Get(WebhookTimestampHeader)
	sig := gotHeader.Get(WebhookSignatureHeader)
	if ts == "" || sig == "" {
		t.Fatalf("signature headers missing: %v", gotHeader)
	}
	if err := VerifyWebhook(secret, ts, sig, gotBody, time.Minute); err != nil {
		t.Fatalf("the receiver could not verify what we sent: %v", err)
	}

	if got := gotHeader.Get(WebhookEventHeader); got != "ca.expiry_alert" {
		t.Errorf("%s = %q, want the topic", WebhookEventHeader, got)
	}
	if got := gotHeader.Get("X-Tenant"); got != "acme" {
		t.Errorf("configured header was not sent, got %q", got)
	}

	var payload WebhookPayload
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("body is not the documented shape: %v", err)
	}
	if payload.Severity != "CRITICAL" || payload.Topic != "ca.expiry_alert" || payload.Source != "certpilot" {
		t.Errorf("payload = %+v", payload)
	}
	if payload.Timestamp != "2023-11-14T22:13:20Z" {
		t.Errorf("timestamp = %q, want RFC 3339 UTC", payload.Timestamp)
	}
}

func TestWebhookOmitsSignatureWhenNoSecretIsConfigured(t *testing.T) {
	var gotHeader http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := buildWebhook(t, `{"url":"`+srv.URL+`","allow_insecure_http":true}`)
	if err := n.Send(context.Background(), Alert{Topic: "t", Timestamp: time.Now()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotHeader.Get(WebhookSignatureHeader) != "" {
		t.Error("a signature was sent with no secret configured, which a receiver would try to verify")
	}
}

// The property the timestamp is in the signature for. Signing the body alone
// yields a signature that never expires, so one captured delivery can be
// replayed forever and the receiver cannot tell.
func TestWebhookSignatureCoversTheTimestamp(t *testing.T) {
	const secret = "a-secret-long-enough-to-be-accepted"
	body := []byte(`{"topic":"ca.expiry_alert"}`)

	old := "1700000000"
	sig := SignWebhook(secret, old, body)

	if err := VerifyWebhook(secret, old, sig, body, 0); err != nil {
		t.Fatalf("a valid signature failed with no tolerance set: %v", err)
	}
	if err := VerifyWebhook(secret, old, sig, body, 5*time.Minute); err == nil {
		t.Fatal("a signature from 2023 was accepted inside a five-minute window")
	}

	// Moving the timestamp invalidates the signature, which is what makes the
	// freshness check unforgeable rather than advisory.
	fresh := "1900000000"
	if err := VerifyWebhook(secret, fresh, sig, body, 0); err == nil {
		t.Fatal("the timestamp could be changed without breaking the signature")
	}
}

func TestWebhookVerificationRejectsTampering(t *testing.T) {
	const secret = "a-secret-long-enough-to-be-accepted"
	body := []byte(`{"severity":"INFO"}`)
	ts := "1700000000"
	sig := SignWebhook(secret, ts, body)

	cases := map[string]struct {
		secret, ts, sig string
		body            []byte
	}{
		"altered body":  {secret, ts, sig, []byte(`{"severity":"CRITICAL"}`)},
		"wrong secret":  {"a-different-secret-of-length", ts, sig, body},
		"truncated sig": {secret, ts, sig[:len(sig)-2], body},
		"empty sig":     {secret, ts, "", body},
		"bad timestamp": {secret, "not-a-number", sig, body},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyWebhook(tc.secret, tc.ts, tc.sig, tc.body, 0); err == nil {
				t.Error("verification passed")
			}
		})
	}
}

// The receiver's complaint is usually the only useful thing about a failure —
// "invalid tenant" beats "the webhook returned 400".
func TestWebhookSurfacesTheReceiversReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("unknown tenant identifier"))
	}))
	defer srv.Close()

	n := buildWebhook(t, `{"url":"`+srv.URL+`","allow_insecure_http":true}`)
	err := n.Send(context.Background(), Alert{Topic: "t", Timestamp: time.Now()})
	if err == nil {
		t.Fatal("a 400 was treated as success")
	}
	if !strings.Contains(err.Error(), "unknown tenant identifier") {
		t.Errorf("error = %q, want the receiver's own reason", err)
	}
}
