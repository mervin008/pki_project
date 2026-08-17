package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/engine/notifications"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// receiver is a webhook destination the test can point channels at.
func receiver(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func createChannel(t *testing.T, r *gin.Engine, body gin.H) *httptest.ResponseRecorder {
	t.Helper()
	return do(r, http.MethodPost, "/api/v1/notification-channels", body, nil)
}

// The single most important property of this endpoint. A Slack webhook URL and
// an SMTP password are bearer credentials; a list endpoint that echoes them back
// turns any reader into someone who can post to the channel.
func TestChannelConfigurationIsNeverReturned(t *testing.T) {
	r, _ := realRouter(t)

	const secretURL = "https://hooks.slack.com/services/T0/B0/XXXXSECRETXXXX"
	w := createChannel(t, r, gin.H{
		"name": "pki-oncall", "channel_type": "slack",
		"config": gin.H{"webhook_url": secretURL},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "XXXXSECRETXXXX") {
		t.Errorf("the create response echoed the webhook URL back:\n%s", w.Body.String())
	}

	list := do(r, http.MethodGet, "/api/v1/notification-channels", nil, nil)
	if strings.Contains(list.Body.String(), "XXXXSECRETXXXX") {
		t.Errorf("the list response leaked the webhook URL:\n%s", list.Body.String())
	}
	// Nor the ciphertext, which is of no use to a client and only widens what an
	// offline attacker has to work with.
	if strings.Contains(list.Body.String(), "config_encrypted") {
		t.Errorf("the list response included the sealed configuration:\n%s", list.Body.String())
	}
}

// A configuration that cannot deliver has to be refused where it is entered.
// Accepting it produces a channel that looks configured on the dashboard and
// silently drops every alert routed to it — worse than having no channel.
func TestAChannelThatCannotDeliverIsRefusedAtCreation(t *testing.T) {
	r, st := realRouter(t)

	cases := map[string]struct {
		body gin.H
		want string
	}{
		"slack over plain http": {
			gin.H{"name": "a", "channel_type": "slack", "config": gin.H{"webhook_url": "http://hooks.slack.com/x"}},
			"https",
		},
		"webhook with no url": {
			gin.H{"name": "b", "channel_type": "webhook", "config": gin.H{}},
			"needs a url",
		},
		"email with no recipient": {
			gin.H{"name": "c", "channel_type": "email", "config": gin.H{"host": "smtp.test", "from": "a@b.test"}},
			"recipient",
		},
		"unimplemented type": {
			gin.H{"name": "d", "channel_type": "teams", "config": gin.H{}},
			"channel_type must be one of",
		},
		"bad severity": {
			gin.H{"name": "e", "channel_type": "webhook", "severity_threshold": "URGENT",
				"config": gin.H{"url": "https://x.test/h"}},
			"severity_threshold must be",
		},
		"unknown topic": {
			gin.H{"name": "f", "channel_type": "webhook", "topics": []string{"ca.expiry"},
				"config": gin.H{"url": "https://x.test/h"}},
			"unknown topic",
		},
		"no name": {
			gin.H{"channel_type": "webhook", "config": gin.H{"url": "https://x.test/h"}},
			"",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := createChannel(t, r, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", w.Code, w.Body.String())
			}
			if tc.want != "" && !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("body = %s, want it to mention %q", w.Body.String(), tc.want)
			}
		})
	}

	channels, err := st.ListNotificationChannels(t.Context())
	if err != nil {
		t.Fatalf("ListNotificationChannels: %v", err)
	}
	if len(channels) != 0 {
		t.Errorf("%d rejected channels were stored anyway", len(channels))
	}
}

// A typo'd topic is the quiet version of the same failure: the channel is valid,
// enabled, and matches nothing.
func TestTopicFilterIsValidatedAgainstRealTopics(t *testing.T) {
	r, _ := realRouter(t)

	w := createChannel(t, r, gin.H{
		"name": "expiry-only", "channel_type": "webhook",
		"topics": []string{"ca.expiry_alert", "cert.renewal_failed"},
		"config": gin.H{"url": "https://x.test/h"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("a valid topic filter was rejected: %s", w.Body.String())
	}

	// The list advertises what is available, so a client does not have to guess.
	list := do(r, http.MethodGet, "/api/v1/notification-channels", nil, nil)
	var payload struct {
		Topics         []string `json:"topics"`
		SupportedTypes []string `json:"supported_types"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &payload); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(payload.Topics) == 0 {
		t.Error("the list does not advertise the valid topics")
	}
	if len(payload.SupportedTypes) != 3 {
		t.Errorf("supported_types = %v, want the three implemented types", payload.SupportedTypes)
	}
}

// An operator cannot read a stored SMTP password back, so requiring it on every
// edit would mean re-typing a credential to change a threshold — which ends with
// the credential written somewhere it should not be.
func TestUpdateWithoutConfigKeepsTheStoredCredentials(t *testing.T) {
	r, st := realRouter(t)

	created := createChannel(t, r, gin.H{
		"name": "ops", "channel_type": "webhook", "severity_threshold": "CRITICAL",
		"config": gin.H{"url": "https://x.test/h"},
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %s", created.Body.String())
	}
	var wrapper struct {
		Data store.NotificationChannel `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &wrapper); err != nil {
		t.Fatalf("create body: %v", err)
	}
	id := wrapper.Data.ID

	before, err := st.GetNotificationChannel(t.Context(), id)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	sealed := before.ConfigEncrypted
	if sealed == "" {
		t.Fatal("the configuration was not sealed")
	}

	w := do(r, http.MethodPut, "/api/v1/notification-channels/"+id, gin.H{
		"name": "ops", "channel_type": "webhook", "severity_threshold": "INFO",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d (%s)", w.Code, w.Body.String())
	}

	after, err := st.GetNotificationChannel(t.Context(), id)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	if after.ConfigEncrypted != sealed {
		t.Error("omitting config replaced the stored credentials")
	}
	if after.SeverityThreshold != "INFO" {
		t.Errorf("threshold = %q, want INFO", after.SeverityThreshold)
	}
}

// Changing the type without supplying a config would leave a channel holding
// settings its new notifier cannot read: enabled on screen, undeliverable in
// practice.
func TestChangingTypeWithoutConfigIsRefused(t *testing.T) {
	r, _ := realRouter(t)

	created := createChannel(t, r, gin.H{
		"name": "ops", "channel_type": "webhook",
		"config": gin.H{"url": "https://x.test/h"},
	})
	var wrapper struct {
		Data store.NotificationChannel `json:"data"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &wrapper)

	w := do(r, http.MethodPut, "/api/v1/notification-channels/"+wrapper.Data.ID, gin.H{
		"name": "ops", "channel_type": "email",
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not valid for a email channel") {
		t.Errorf("body = %s", w.Body.String())
	}
}

// The endpoint that makes the whole subsystem trustworthy: it actually sends.
func TestTestEndpointDeliversAndReportsTheDestinationsReason(t *testing.T) {
	r, _ := realRouter(t)

	good := receiver(t, http.StatusOK, "")
	bad := receiver(t, http.StatusForbidden, "token is not authorised for this channel")

	mk := func(name, url string) string {
		t.Helper()
		w := createChannel(t, r, gin.H{
			"name": name, "channel_type": "webhook",
			"config": gin.H{"url": url, "allow_insecure_http": true},
		})
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: %s", name, w.Body.String())
		}
		var wrapper struct {
			Data store.NotificationChannel `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &wrapper)
		return wrapper.Data.ID
	}

	okID := mk("reachable", good)
	badID := mk("refusing", bad)

	w := do(r, http.MethodPost, "/api/v1/notification-channels/"+okID+"/test", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("test status = %d, want 200 (%s)", w.Code, w.Body.String())
	}

	w = do(r, http.MethodPost, "/api/v1/notification-channels/"+badID+"/test", nil, nil)
	// 502, not 500: CertPilot worked and the destination did not, and that
	// distinction is the entire content of the answer.
	if w.Code != http.StatusBadGateway {
		t.Fatalf("test status = %d, want 502 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "token is not authorised") {
		t.Errorf("the destination's own reason was not returned: %s", w.Body.String())
	}
}

func TestTestEndpointIsClearlyLabelledAsATest(t *testing.T) {
	// Otherwise an operator testing a channel at 4pm leaves the on-call engineer
	// at 4am wondering whether the CA in the alert is real.
	alert := notifications.TestAlert("pki-oncall")
	if !strings.Contains(strings.ToLower(alert.Title), "test") {
		t.Errorf("title = %q, want it to say this is a test", alert.Title)
	}
	if !strings.Contains(alert.Summary, "No certificate authority is in trouble") {
		t.Errorf("summary = %q, want it to say nothing is wrong", alert.Summary)
	}
}

func TestChannelChangesAreAudited(t *testing.T) {
	r, st := realRouter(t)

	created := createChannel(t, r, gin.H{
		"name": "ops", "channel_type": "webhook",
		"config": gin.H{"url": "https://x.test/h"},
	})
	var wrapper struct {
		Data store.NotificationChannel `json:"data"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &wrapper)

	do(r, http.MethodPut, "/api/v1/notification-channels/"+wrapper.Data.ID, gin.H{
		"name": "ops", "channel_type": "webhook", "config": gin.H{"url": "https://y.test/h"},
	}, nil)
	do(r, http.MethodDelete, "/api/v1/notification-channels/"+wrapper.Data.ID, nil, nil)

	for _, action := range []string{
		"notification_channel.created",
		"notification_channel.updated",
		"notification_channel.deleted",
	} {
		logs, _, err := st.ListAuditLogs(t.Context(), store.AuditLogFilter{
			Actions: []string{action}, Limit: 10,
		})
		if err != nil {
			t.Fatalf("ListAuditLogs: %v", err)
		}
		if len(logs) == 0 {
			t.Errorf("%s was not audited", action)
		}
		// Where alerts go is not a secret, but the credential is.
		for _, entry := range logs {
			if strings.Contains(entry.Details, "y.test") || strings.Contains(entry.Details, "x.test") {
				t.Errorf("%s audit detail carries the destination URL: %s", action, entry.Details)
			}
		}
	}
}

// A wall display has no business knowing the alerting topology, and its token is
// GET-only anyway — but the write routes are what would actually hurt.
func TestDisplayTokensCannotChangeNotificationChannels(t *testing.T) {
	r, _ := realRouter(t)
	raw, _ := mintToken(t, r, "corridor", 30)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/notification-channels"},
		{http.MethodPut, "/api/v1/notification-channels/abc"},
		{http.MethodDelete, "/api/v1/notification-channels/abc"},
		{http.MethodPost, "/api/v1/notification-channels/abc/test"},
	} {
		w := do(r, tc.method, tc.path, gin.H{}, map[string]string{"X-Display-Token": raw})
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", tc.method, tc.path, w.Code)
		}
	}
}
