// Package notifications delivers alerts to the channels an operator has
// configured: Slack, a generic signed webhook, or email over SMTP.
//
// The reason this package exists is stated plainly: an alert that only lands in
// an audit table is barely better than a log line. CertPilot's whole purpose is
// to prevent a CA expiring while everyone believed they were watching, and
// nobody watches a table.
//
// Two rules shape everything here.
//
// **A channel that cannot deliver must fail at configuration time, not at 3am.**
// Every config is parsed and validated when it is saved, and there is a test
// endpoint that actually sends. A channel that looks configured on the dashboard
// and silently drops every alert is worse than no channel at all, because it
// buys the confidence without providing the coverage.
//
// **Delivery must never be able to stall monitoring.** The dispatcher consumes
// the broker like any other subscriber, so a wedged Slack webhook loses its
// place in the queue rather than applying backpressure to the CA health sweep.
package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Channel types with a notifier behind them.
//
// Migration 004 narrowed the database constraint to exactly these. 001 also
// permitted `teams` and `pagerduty`, neither implemented nor planned, and a
// channel of a type nothing can deliver is the silent-failure case above.
const (
	TypeSlack   = "slack"
	TypeWebhook = "webhook"
	TypeEmail   = "email"
)

// Alert is one thing worth telling a human about.
//
// Rendered once, here, rather than per notifier: three channels describing the
// same event differently is how an on-call engineer ends up reconciling a Slack
// message against an email instead of acting on either.
type Alert struct {
	// Severity is the broker's vocabulary: INFO, WARNING, CRITICAL.
	Severity string `json:"severity"`
	// Topic is the event topic, e.g. "ca.expiry_alert".
	Topic string `json:"topic"`
	// Title is one line, suitable for a Slack header or an email subject.
	Title string `json:"title"`
	// Summary is a sentence of context beneath the title.
	Summary string `json:"summary"`
	// EntityID is the CA or certificate concerned, when there is one.
	EntityID string `json:"entity_id,omitempty"`
	// Fields carry the specifics, in the order they should be shown.
	Fields []Field `json:"fields,omitempty"`
	// Timestamp is when the underlying event happened, not when this was sent.
	Timestamp time.Time `json:"timestamp"`
}

// Field is one label/value pair in an alert body.
type Field struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Notifier delivers an alert to one destination.
//
// Send is expected to be synchronous and to respect the context's deadline. It
// must return an error the operator can act on: "connection refused" and
// "authentication failed" call for different responses, and collapsing both to
// "delivery failed" wastes the only chance to say which.
type Notifier interface {
	Type() string
	Send(ctx context.Context, alert Alert) error
}

// Build constructs a notifier from a channel type and its decrypted config.
//
// This is the single place a config is interpreted, so validation at save time
// and delivery at send time cannot drift apart: ValidateConfig is implemented by
// calling Build and discarding the result.
func Build(channelType string, config []byte, client *http.Client) (Notifier, error) {
	if client == nil {
		client = DefaultClient()
	}

	switch strings.ToLower(strings.TrimSpace(channelType)) {
	case TypeSlack:
		return newSlackNotifier(config, client)
	case TypeWebhook:
		return newWebhookNotifier(config, client)
	case TypeEmail:
		return newEmailNotifier(config)
	case "":
		return nil, fmt.Errorf("a channel type is required (%s)", strings.Join(SupportedTypes(), ", "))
	default:
		// Named explicitly rather than "unsupported type": someone reaching for
		// Teams or PagerDuty should learn that in one read, not by searching.
		return nil, fmt.Errorf(
			"channel type %q is not supported; CertPilot delivers to %s",
			channelType, strings.Join(SupportedTypes(), ", "))
	}
}

// SupportedTypes lists the channel types that have a notifier, sorted so error
// messages and API responses agree on their order.
func SupportedTypes() []string {
	types := []string{TypeEmail, TypeSlack, TypeWebhook}
	sort.Strings(types)
	return types
}

// ValidateConfig checks a configuration and returns it as canonical JSON, ready
// to be sealed.
//
// Called on create and on update. Everything it rejects would otherwise be
// discovered by an alert failing to arrive, which is the one moment nobody is
// in a position to notice.
func ValidateConfig(channelType string, config map[string]any) ([]byte, error) {
	if config == nil {
		config = map[string]any{}
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("configuration could not be encoded: %w", err)
	}
	if _, err := Build(channelType, raw, DefaultClient()); err != nil {
		return nil, err
	}
	return raw, nil
}

// DefaultClient is the HTTP client used for outbound deliveries.
//
// The timeout is deliberately short. A notification is worth retrying but never
// worth waiting on: a destination that has not answered in ten seconds is down,
// and holding a worker open for it delays every other channel behind it.
func DefaultClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// severityRank orders severities for comparison and for picking a colour.
var severityRank = map[string]int{"INFO": 0, "WARNING": 1, "CRITICAL": 2}

// normalizeSeverity maps anything unrecognised to CRITICAL.
//
// The same choice as store.NotificationChannel.Accepts, for the same reason:
// mis-delivering an alert whose severity was spelled unexpectedly is a far
// cheaper mistake than dropping it.
func normalizeSeverity(s string) string {
	up := strings.ToUpper(strings.TrimSpace(s))
	if _, ok := severityRank[up]; !ok {
		return "CRITICAL"
	}
	return up
}

// sanitizeHeaderValue strips CR and LF.
//
// Alert text is derived from data CertPilot did not author — a CA's name comes
// from a certificate someone else issued — and it reaches an email Subject and
// outbound HTTP headers. A bare newline in either is header injection, so the
// characters that make it possible never survive this function.
func sanitizeHeaderValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}
