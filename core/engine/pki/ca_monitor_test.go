package pki

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// caIn builds a CA authority expiring in the given number of days.
func caIn(days int, thresholds string) *store.CAAuthority {
	return &store.CAAuthority{
		ID:              "ca-1",
		Name:            "Example Issuing CA",
		CAType:          "ISSUING",
		NotAfter:        time.Now().Add(time.Duration(days) * 24 * time.Hour),
		AlertThresholds: thresholds,
	}
}

// alertsFrom runs a threshold evaluation against a fresh in-memory store and
// returns the CA expiry alerts it recorded.
func alertsFrom(t *testing.T, ca *store.CAAuthority, days int) []map[string]any {
	t.Helper()

	st := store.NewMemoryStore()
	t.Cleanup(st.Close)

	m := NewCAMonitor(st, nil)
	m.evaluateAlertThresholds(context.Background(), ca, days, time.Now())

	logs, _, err := st.ListAuditLogs(context.Background(), 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}

	var alerts []map[string]any
	for _, l := range logs {
		if l.Action != "ca.expiry_alert" {
			continue
		}
		var details map[string]any
		if err := json.Unmarshal([]byte(l.Details), &details); err != nil {
			t.Fatalf("alert details are not valid JSON (%q): %v", l.Details, err)
		}
		alerts = append(alerts, details)
	}
	return alerts
}

// The alert must reach somewhere a monitoring team actually looks. A log line
// on stdout is indistinguishable from no alert at all.
func TestExpiryAlertIsRecordedToTheAuditLog(t *testing.T) {
	alerts := alertsFrom(t, caIn(25, ""), 25)

	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]

	if a["ca_name"] != "Example Issuing CA" {
		t.Errorf("ca_name = %v", a["ca_name"])
	}
	if a["days_remaining"].(float64) != 25 {
		t.Errorf("days_remaining = %v, want 25", a["days_remaining"])
	}
	if a["threshold"].(float64) != 30 {
		t.Errorf("threshold = %v, want the 30-day threshold to be the one that fires", a["threshold"])
	}
	if a["severity"] != "CRITICAL" {
		t.Errorf("severity = %v, want CRITICAL inside 30 days", a["severity"])
	}
}

func TestSeverityEscalatesInsideThirtyDays(t *testing.T) {
	cases := map[int]string{
		200: "WARNING",
		100: "WARNING",
		45:  "WARNING",
		30:  "CRITICAL",
		5:   "CRITICAL",
	}

	for days, want := range cases {
		alerts := alertsFrom(t, caIn(days, ""), days)
		if len(alerts) != 1 {
			t.Fatalf("%d days: got %d alerts, want 1", days, len(alerts))
		}
		if got := alerts[0]["severity"]; got != want {
			t.Errorf("%d days: severity = %v, want %v", days, got, want)
		}
	}
}

// The tightest crossed threshold should fire, regardless of how the thresholds
// happen to be ordered in configuration.
func TestTightestThresholdFiresRegardlessOfConfiguredOrder(t *testing.T) {
	for _, order := range []string{
		"[365, 180, 90, 30, 14, 7]",
		"[7, 14, 30, 90, 180, 365]",
		"[90, 365, 7, 180, 14, 30]",
	} {
		alerts := alertsFrom(t, caIn(10, order), 10)
		if len(alerts) != 1 {
			t.Fatalf("%s: got %d alerts, want 1", order, len(alerts))
		}
		if got := alerts[0]["threshold"].(float64); got != 14 {
			t.Errorf("%s: threshold = %v, want 14", order, got)
		}
	}
}

// Re-checking a CA every few hours must not re-alert at the same threshold, or
// the dashboard fills with duplicates and the team stops reading it.
func TestAlertIsNotRepeatedAtTheSameThreshold(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()

	m := NewCAMonitor(st, nil)
	ca := caIn(25, "")

	for i := 0; i < 5; i++ {
		m.evaluateAlertThresholds(context.Background(), ca, 25, time.Now())
	}

	logs, _, err := st.ListAuditLogs(context.Background(), 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}

	var count int
	for _, l := range logs {
		if l.Action == "ca.expiry_alert" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("recorded %d alerts across 5 checks, want 1", count)
	}
}

// It must re-alert when the situation genuinely worsens.
func TestAlertFiresAgainAtATighterThreshold(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()

	m := NewCAMonitor(st, nil)
	ca := caIn(100, "")

	// Crosses 180, then 90, then 30 as time passes.
	for _, days := range []int{100, 100, 60, 60, 20} {
		ca.NotAfter = time.Now().Add(time.Duration(days) * 24 * time.Hour)
		m.evaluateAlertThresholds(context.Background(), ca, days, time.Now())
	}

	logs, _, err := st.ListAuditLogs(context.Background(), 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}

	var thresholds []float64
	for _, l := range logs {
		if l.Action != "ca.expiry_alert" {
			continue
		}
		var d map[string]any
		_ = json.Unmarshal([]byte(l.Details), &d)
		thresholds = append(thresholds, d["threshold"].(float64))
	}

	if len(thresholds) != 3 {
		t.Fatalf("got %d alerts, want 3 (one per threshold crossed): %v", len(thresholds), thresholds)
	}
}

// A CA with plenty of life left must not alert at all.
func TestHealthyCADoesNotAlert(t *testing.T) {
	if alerts := alertsFrom(t, caIn(800, ""), 800); len(alerts) != 0 {
		t.Fatalf("got %d alerts for a CA with 800 days remaining, want 0", len(alerts))
	}
}

func TestCustomThresholds(t *testing.T) {
	alerts := alertsFrom(t, caIn(50, "[60, 45]"), 50)

	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if got := alerts[0]["threshold"].(float64); got != 60 {
		t.Errorf("threshold = %v, want the custom 60-day threshold", got)
	}
}

func TestStatusReflectsRemainingLife(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()
	m := NewCAMonitor(st, nil)

	cases := map[int]string{
		-5:  "EXPIRED",
		10:  "CRITICAL",
		100: "WARNING",
		400: "HEALTHY",
	}

	for days, want := range cases {
		ca := caIn(days, "")
		if err := m.CheckCA(context.Background(), ca); err != nil {
			// The store rejects an unknown CA id; the status assignment has
			// already happened by then, which is what this test is about.
			if !strings.Contains(err.Error(), "not found") {
				t.Fatalf("%d days: CheckCA: %v", days, err)
			}
		}
		if ca.Status != want {
			t.Errorf("%d days: status = %q, want %q", days, ca.Status, want)
		}
	}
}

func TestStopIsIdempotent(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()

	m := NewCAMonitor(st, nil)
	m.Start(time.Hour)

	// A double Stop must not panic on a closed channel.
	m.Stop()
	m.Stop()
}

// ── Event publishing ──────────────────────────────────────

// collect drains a subscription without blocking.
func collect(sub *events.Subscription) []events.Event {
	var out []events.Event
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				return out
			}
			out = append(out, evt)
		default:
			return out
		}
	}
}

func TestThresholdCrossingPublishesAnEvent(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCAExpiryAlert)
	defer sub.Close()

	m := NewCAMonitor(st, broker)
	m.evaluateAlertThresholds(context.Background(), caIn(10, ""), 10, time.Now())

	got := collect(sub)
	if len(got) != 1 {
		t.Fatalf("published %d events, want 1", len(got))
	}
	if got[0].Severity != events.SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL inside 30 days", got[0].Severity)
	}
	if got[0].EntityID != "ca-1" {
		t.Errorf("entity = %q, want the CA id", got[0].EntityID)
	}

	payload, ok := got[0].Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload type %T, want map", got[0].Payload)
	}
	if payload["threshold"] != 14 {
		t.Errorf("threshold = %v, want the tightest crossed (14)", payload["threshold"])
	}
	if payload["days_remaining"] != 10 {
		t.Errorf("days_remaining = %v, want 10", payload["days_remaining"])
	}
}

// "HEALTHY -> WARNING" is only detectable if the prior status is captured
// before the record is overwritten. Without it the dashboard sees the end
// state and cannot tell a fresh degradation from a steady one.
func TestStatusTransitionIsPublished(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCAHealth)
	defer sub.Close()

	ca := &store.CAAuthority{
		Name:     "Transitioning CA",
		CAType:   "ISSUING",
		Status:   "HEALTHY",
		NotAfter: time.Now().Add(100 * 24 * time.Hour),
	}
	if err := st.CreateCAAuthority(context.Background(), ca); err != nil {
		t.Fatalf("CreateCAAuthority: %v", err)
	}

	m := NewCAMonitor(st, broker)
	if err := m.CheckCA(context.Background(), ca); err != nil {
		t.Fatalf("CheckCA: %v", err)
	}

	got := collect(sub)
	if len(got) != 1 {
		t.Fatalf("published %d events, want 1 for HEALTHY -> WARNING", len(got))
	}

	payload := got[0].Payload.(map[string]any)
	if payload["previous_status"] != "HEALTHY" {
		t.Errorf("previous_status = %v, want HEALTHY", payload["previous_status"])
	}
	if payload["status"] != "WARNING" {
		t.Errorf("status = %v, want WARNING at 100 days", payload["status"])
	}
	if got[0].Severity != events.SeverityWarning {
		t.Errorf("severity = %q, want WARNING", got[0].Severity)
	}
}

// A CA whose status has not moved must stay quiet, or a six-hourly sweep
// republishes everything and the stream becomes noise.
func TestUnchangedStatusPublishesNothing(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCAHealth)
	defer sub.Close()

	ca := &store.CAAuthority{
		Name:     "Steady CA",
		CAType:   "ROOT",
		Status:   "HEALTHY",
		NotAfter: time.Now().Add(1000 * 24 * time.Hour),
	}
	if err := st.CreateCAAuthority(context.Background(), ca); err != nil {
		t.Fatalf("CreateCAAuthority: %v", err)
	}

	m := NewCAMonitor(st, broker)
	for i := 0; i < 3; i++ {
		if err := m.CheckCA(context.Background(), ca); err != nil {
			t.Fatalf("CheckCA: %v", err)
		}
	}

	if got := collect(sub); len(got) != 0 {
		t.Fatalf("published %d events for an unchanged CA, want 0", len(got))
	}
}

// A nil broker is a supported configuration and must not panic.
func TestNilBrokerIsSafe(t *testing.T) {
	st := store.NewMemoryStore()
	defer st.Close()

	m := NewCAMonitor(st, nil)
	m.evaluateAlertThresholds(context.Background(), caIn(5, ""), 5, time.Now())
}
