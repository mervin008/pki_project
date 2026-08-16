package pki

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

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

	m := NewCAMonitor(st)
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

	m := NewCAMonitor(st)
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

	m := NewCAMonitor(st)
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
	m := NewCAMonitor(st)

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

	m := NewCAMonitor(st)
	m.Start(time.Hour)

	// A double Stop must not panic on a closed channel.
	m.Stop()
	m.Stop()
}
