package notifications

import (
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
)

func fieldValue(alert Alert, label string) (string, bool) {
	for _, f := range alert.Fields {
		if f.Label == label {
			return f.Value, true
		}
	}
	return "", false
}

// The alert has to say what breaks, not merely what happened. "Expires in 9
// days" is a fact; whether that is a Tuesday problem or an outage depends on
// what the CA signs, and the person reading it at 2am should not have to know.
func TestAnExpiryAlertStatesTheConsequence(t *testing.T) {
	cases := map[string]string{
		"ISSUING":      "Every certificate it has issued stops validating",
		"INTERMEDIATE": "Every certificate it has issued stops validating",
		"ROOT":         "Everything beneath it in the hierarchy stops validating",
	}

	for caType, want := range cases {
		t.Run(caType, func(t *testing.T) {
			alert := AlertFromEvent(events.Event{
				Topic: events.TopicCAExpiryAlert, Severity: "CRITICAL", EntityID: "ca-1",
				Timestamp: time.Now(),
				Payload: map[string]any{
					"ca_name": "Corporate Issuing CA", "ca_type": caType,
					"days_remaining": 9, "threshold": 14,
					"not_after": "2026-08-27T00:04:53Z",
				},
			})

			if !strings.Contains(alert.Summary, want) {
				t.Errorf("summary = %q, want it to mention %q", alert.Summary, want)
			}
			if !strings.Contains(alert.Title, "Corporate Issuing CA") {
				t.Errorf("title = %q, want the CA named", alert.Title)
			}
			if got, ok := fieldValue(alert, "Days remaining"); !ok || got != "9 days" {
				t.Errorf("Days remaining = %q", got)
			}
			if got, _ := fieldValue(alert, "Threshold crossed"); got != "14-day threshold" {
				t.Errorf("Threshold crossed = %q", got)
			}
			if got, _ := fieldValue(alert, "Expires"); got != "27 August 2026" {
				t.Errorf("Expires = %q, want a readable date", got)
			}
		})
	}
}

// The producer publishes a struct in-process and JSON over SSE. Rendering has to
// read both identically, or an email and a webhook describe the same event
// differently.
func TestPayloadIsReadTheSameAsAStructOrAMap(t *testing.T) {
	type caExpiryPayload struct {
		CAName        string `json:"ca_name"`
		CAType        string `json:"ca_type"`
		DaysRemaining int    `json:"days_remaining"`
		Threshold     int    `json:"threshold"`
	}

	fromStruct := AlertFromEvent(events.Event{
		Topic: events.TopicCAExpiryAlert, Severity: "CRITICAL", Timestamp: time.Unix(0, 0),
		Payload: caExpiryPayload{CAName: "Root", CAType: "ROOT", DaysRemaining: 3, Threshold: 7},
	})
	fromMap := AlertFromEvent(events.Event{
		Topic: events.TopicCAExpiryAlert, Severity: "CRITICAL", Timestamp: time.Unix(0, 0),
		Payload: map[string]any{"ca_name": "Root", "ca_type": "ROOT", "days_remaining": 3, "threshold": 7},
	})

	if fromStruct.Title != fromMap.Title || fromStruct.Summary != fromMap.Summary {
		t.Errorf("a struct and a map produced different alerts:\n  %+v\n  %+v", fromStruct, fromMap)
	}
}

// A missing days_remaining must not render as "today". Zero is a real value and
// a fabricated one would send someone running at the wrong moment.
func TestAMissingNumberIsUnknownNotZero(t *testing.T) {
	missing := AlertFromEvent(events.Event{
		Topic: events.TopicCAExpiryAlert, Severity: "WARNING", Timestamp: time.Now(),
		Payload: map[string]any{"ca_name": "CA"},
	})
	if got, _ := fieldValue(missing, "Days remaining"); got != "unknown" {
		t.Errorf("Days remaining = %q, want %q", got, "unknown")
	}

	today := AlertFromEvent(events.Event{
		Topic: events.TopicCAExpiryAlert, Severity: "CRITICAL", Timestamp: time.Now(),
		Payload: map[string]any{"ca_name": "CA", "days_remaining": 0},
	})
	if got, _ := fieldValue(today, "Days remaining"); got != "today" {
		t.Errorf("Days remaining = %q, want %q", got, "today")
	}

	expired := AlertFromEvent(events.Event{
		Topic: events.TopicCAExpiryAlert, Severity: "CRITICAL", Timestamp: time.Now(),
		Payload: map[string]any{"ca_name": "CA", "days_remaining": -4},
	})
	if got, _ := fieldValue(expired, "Days remaining"); got != "expired 4 days ago" {
		t.Errorf("Days remaining = %q", got)
	}
}

// Topics get added by producers over time. A dispatcher that silently drops what
// it does not recognise turns every new event type into a coverage gap that
// nothing reports.
func TestAnUnrecognisedTopicStillProducesAnAlert(t *testing.T) {
	alert := AlertFromEvent(events.Event{
		Topic: "ca.key_ceremony_due", Severity: "WARNING", Timestamp: time.Now(),
		Payload: map[string]any{"zeta": 1, "alpha": "yes"},
	})

	if alert.Title == "" || !strings.Contains(alert.Title, "ca.key_ceremony_due") {
		t.Errorf("title = %q, want the topic named", alert.Title)
	}
	// Sorted, so the same event does not render differently between runs.
	if len(alert.Fields) != 2 || alert.Fields[0].Label != "alpha" {
		t.Errorf("fields = %+v, want them sorted by label", alert.Fields)
	}
}

// Alert text comes from certificates CertPilot did not issue. A newline in a CA
// name reaching an email Subject or an HTTP header is header injection.
func TestControlCharactersNeverSurviveIntoAlertText(t *testing.T) {
	alert := AlertFromEvent(events.Event{
		Topic: events.TopicCAExpiryAlert, Severity: "CRITICAL", Timestamp: time.Now(),
		Payload: map[string]any{
			"ca_name":        "Evil CA\r\nBcc: attacker@example.com",
			"days_remaining": 1,
		},
	})

	if strings.ContainsAny(alert.Title, "\r\n") {
		t.Errorf("title carries a line break: %q", alert.Title)
	}
	for _, f := range alert.Fields {
		if strings.ContainsAny(f.Value, "\r\n") {
			t.Errorf("field %q carries a line break: %q", f.Label, f.Value)
		}
	}
}

// An alert padded with "Error: —" makes the fields that hold something harder to
// find, and an alert nobody reads carefully fails at its one job.
func TestEmptyFieldsAreDropped(t *testing.T) {
	alert := AlertFromEvent(events.Event{
		Topic: events.TopicCertRenewFail, Severity: "CRITICAL", Timestamp: time.Now(),
		Payload: map[string]any{"common_name": "www.example.com"},
	})

	for _, f := range alert.Fields {
		if f.Value == "" || f.Value == "—" {
			t.Errorf("field %q was kept with an empty value", f.Label)
		}
	}
	if _, ok := fieldValue(alert, "Common name"); !ok {
		t.Error("the one field that had a value was dropped")
	}
}

// A failed renewal is an expiry with a delay on it, and the wording should say
// so rather than reading as a transient hiccup.
func TestRenewalFailureNamesWhatItBecomes(t *testing.T) {
	alert := AlertFromEvent(events.Event{
		Topic: events.TopicCertRenewFail, Severity: "CRITICAL", Timestamp: time.Now(),
		Payload: map[string]any{
			"common_name": "api.example.com", "days_remaining": 12,
			"error": "dns-01 challenge timed out",
		},
	})

	if !strings.Contains(alert.Summary, "will expire") {
		t.Errorf("summary = %q, want it to say the certificate will expire", alert.Summary)
	}
	if got, _ := fieldValue(alert, "Error"); got != "dns-01 challenge timed out" {
		t.Errorf("Error = %q, want the underlying reason carried through", got)
	}
}

func TestUnrecognisedSeverityBecomesCritical(t *testing.T) {
	alert := AlertFromEvent(events.Event{
		Topic: events.TopicCAHealth, Severity: "urgent-ish", Timestamp: time.Now(),
	})
	// Delivering an alert whose severity was spelled unexpectedly is a far
	// cheaper mistake than dropping it.
	if alert.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", alert.Severity)
	}
}

func TestAnEventWithNoTimestampGetsOne(t *testing.T) {
	alert := AlertFromEvent(events.Event{Topic: events.TopicCAHealth, Severity: "INFO"})
	if alert.Timestamp.IsZero() {
		t.Error("a zero timestamp survived, which renders as the year 1")
	}
}

// A discovery alert has to say what the finding means, not that a job ran. "A
// scan completed" is not actionable; "nothing renews these" is.
func TestDiscoveryAlertNamesTheConsequence(t *testing.T) {
	alert := AlertFromEvent(events.Event{
		Topic:    events.TopicDiscoveryUnmanaged,
		Severity: events.SeverityWarning,
		EntityID: "scan-1",
		Payload: map[string]any{
			"unmanaged_count": 3,
			"scanned_count":   12,
			"hosts":           []any{"10.0.0.4:443", "10.0.0.9:8443"},
		},
	})

	if !strings.Contains(alert.Title, "3") {
		t.Errorf("title does not carry the count: %q", alert.Title)
	}
	if !strings.Contains(alert.Summary, "Nothing renews them") {
		t.Errorf("summary does not state the consequence: %q", alert.Summary)
	}
	// The hosts are the actionable part: an alert that only gives a number
	// sends the reader back to the dashboard to find out which.
	hosts, _ := fieldValue(alert, "Hosts")
	if !strings.Contains(hosts, "10.0.0.4:443") {
		t.Errorf("the alert does not name the hosts found: %+v", alert.Fields)
	}
}
