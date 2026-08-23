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

// A Slack incoming webhook URL is a bearer credential: anyone holding it can
// post to the channel. Refusing plain http here is not pedantry, because the
// failure is silent — the alert still arrives, and the URL is simply readable
// to anything on the path.
func TestSlackRequiresHTTPS(t *testing.T) {
	cases := map[string]string{
		"plain http": `{"webhook_url":"http://hooks.slack.com/services/x"}`,
		"no scheme":  `{"webhook_url":"hooks.slack.com/services/x"}`,
		"missing":    `{}`,
		"empty":      `{"webhook_url":"   "}`,
		"malformed":  `{"webhook_url":`,
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(TypeSlack, []byte(config), DefaultClient()); err == nil {
				t.Error("accepted a webhook_url that must not be used")
			}
		})
	}
}

func TestSlackPayloadIsWellFormed(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Built directly, bypassing the https check, so the payload can be
	// inspected against a local test server.
	n := &slackNotifier{cfg: slackConfig{WebhookURL: srv.URL}, client: DefaultClient()}

	alert := Alert{
		Severity: "CRITICAL", Topic: "ca.expiry_alert",
		Title: "CA expiring: Corporate Issuing CA", Summary: "It expires in 9 days.",
		Fields:    []Field{{Label: "Days remaining", Value: "9 days"}},
		Timestamp: time.Unix(1_700_000_000, 0),
	}
	if err := n.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// The fallback text is what Slack shows in a notification popup and on a
	// phone's lock screen, which for an alerting tool is where it is most often
	// read first. Blocks alone would arrive as an empty notification.
	text, _ := got["text"].(string)
	if !strings.Contains(text, "CRITICAL") || !strings.Contains(text, "Corporate Issuing CA") {
		t.Errorf("fallback text = %q, want severity and the CA name", text)
	}

	attachments, ok := got["attachments"].([]any)
	if !ok || len(attachments) != 1 {
		t.Fatalf("attachments = %v, want exactly one for the colour bar", got["attachments"])
	}
	attachment := attachments[0].(map[string]any)
	if attachment["color"] != severityColour("CRITICAL") {
		t.Errorf("colour = %v, want the critical colour", attachment["color"])
	}
	if blocks, ok := attachment["blocks"].([]any); !ok || len(blocks) < 3 {
		t.Errorf("blocks = %v, want header, section, and context", attachment["blocks"])
	}
}

// Slack rejects a message outright when the header block exceeds 150
// characters, so a CA with a long name would silently stop alerting.
func TestSlackHeaderIsTruncatedRatherThanRejected(t *testing.T) {
	n := &slackNotifier{cfg: slackConfig{WebhookURL: "https://x.test"}, client: DefaultClient()}

	payload := n.payload(Alert{
		Severity: "WARNING", Title: strings.Repeat("A very long certificate authority name ", 20),
		Timestamp: time.Now(),
	})

	attachment := payload["attachments"].([]map[string]any)[0]
	header := attachment["blocks"].([]map[string]any)[0]
	text := header["text"].(map[string]any)["text"].(string)

	if len(text) > 150 {
		t.Errorf("header is %d characters; Slack rejects anything over 150", len(text))
	}
}

// A CA's common name is not authored by CertPilot. An unescaped `<` turns the
// rest of the alert into a malformed Slack link.
func TestSlackMarkupIsEscaped(t *testing.T) {
	n := &slackNotifier{cfg: slackConfig{WebhookURL: "https://x.test"}, client: DefaultClient()}

	payload := n.payload(Alert{
		Severity: "INFO", Title: "CA", Summary: `CN=<script>alert(1)</script> & friends`,
		Timestamp: time.Now(),
	})

	attachment := payload["attachments"].([]map[string]any)[0]
	section := attachment["blocks"].([]map[string]any)[1]
	text := section["text"].(map[string]any)["text"].(string)

	if strings.Contains(text, "<script>") {
		t.Errorf("markup was not escaped: %q", text)
	}
	if !strings.Contains(text, "&lt;script&gt;") || !strings.Contains(text, "&amp;") {
		t.Errorf("escaping lost the content: %q", text)
	}
}

// Slack answers with a short plain-text reason. "invalid_token" tells an
// operator what to do; "the request failed" does not.
func TestSlackSurfacesItsOwnReason(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   string
	}{
		"revoked webhook": {http.StatusNotFound, "no_service", "revoked"},
		"rate limited":    {http.StatusTooManyRequests, "rate_limited", "rate limiting"},
		"bad payload":     {http.StatusBadRequest, "invalid_payload", "invalid_payload"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			n := &slackNotifier{cfg: slackConfig{WebhookURL: srv.URL}, client: DefaultClient()}
			err := n.Send(context.Background(), TestAlert("ops"))
			if err == nil {
				t.Fatal("a failure was reported as success")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestSlackTypeAndSupportedTypes(t *testing.T) {
	n, err := Build(TypeSlack, []byte(`{"webhook_url":"https://hooks.slack.com/services/x"}`), DefaultClient())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if n.Type() != TypeSlack {
		t.Errorf("Type() = %q", n.Type())
	}

	// Teams and PagerDuty were permitted by migration 001 and are deliberately
	// not implemented. Reaching for one must produce an error that names what
	// is available, not a channel that silently never delivers.
	_, err = Build("teams", []byte(`{}`), DefaultClient())
	if err == nil {
		t.Fatal("an unimplemented channel type was accepted")
	}
	for _, want := range SupportedTypes() {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to list %q", err, want)
		}
	}
}
