package notifications

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// recorder is a webhook receiver that counts and can be made to fail.
type recorder struct {
	mu       sync.Mutex
	requests int
	bodies   []string

	failFirst atomic.Int32
	block     chan struct{}
	srv       *httptest.Server
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.block != nil {
			<-r.block
		}

		buf := make([]byte, 4096)
		n, _ := req.Body.Read(buf)

		r.mu.Lock()
		r.requests++
		r.bodies = append(r.bodies, string(buf[:n]))
		r.mu.Unlock()

		if r.failFirst.Load() > 0 {
			r.failFirst.Add(-1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("temporarily unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

func (r *recorder) lastBody() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return ""
	}
	return r.bodies[len(r.bodies)-1]
}

// waitFor polls until cond holds, so tests do not depend on a fixed sleep being
// long enough on a loaded machine.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// testKeyring is a real keyring, so these tests exercise the same seal/unseal
// path production uses rather than a bypass that could rot independently.
var testKeyring = func() *secrets.Keyring {
	kr, err := secrets.NewEphemeralKeyring()
	if err != nil {
		panic(err)
	}
	return kr
}()

func newTestDispatcher(t *testing.T, s store.Store, b *events.Broker, opts ...Option) *Dispatcher {
	t.Helper()
	base := []Option{
		WithBackoff(func(int) time.Duration { return time.Millisecond }),
		// Effectively no caching, so a channel saved mid-test takes effect.
		WithChannelTTL(time.Millisecond),
		WithSendTimeout(2 * time.Second),
	}
	d := NewDispatcher(s, testKeyring, b, append(base, opts...)...)
	t.Cleanup(d.Stop)
	return d
}

// sealPlain seals a channel's configuration and saves it, the way the API does.
func sealPlain(t *testing.T, s store.Store, ch *store.NotificationChannel, config string) {
	t.Helper()
	sealed, err := testKeyring.EncryptString(config, secrets.ContextNotificationConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	ch.ConfigEncrypted = sealed
	if err := s.UpdateNotificationChannel(context.Background(), ch); err != nil {
		t.Fatalf("UpdateNotificationChannel: %v", err)
	}
}

func addChannel(t *testing.T, s store.Store, ch *store.NotificationChannel) *store.NotificationChannel {
	t.Helper()
	if err := s.CreateNotificationChannel(context.Background(), ch); err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	return ch
}

// webhookChannel builds an enabled webhook channel. Its configuration is sealed
// separately with sealPlain, because the store assigns the ID on create and the
// seal needs a saved row to update.
func webhookChannel(name, _url, severity string, topics []string) *store.NotificationChannel {
	return &store.NotificationChannel{
		Name:              name,
		ChannelType:       TypeWebhook,
		IsEnabled:         true,
		SeverityThreshold: severity,
		Topics:            topics,
	}
}

func TestDispatcherDeliversAnAlertToAMatchingChannel(t *testing.T) {
	rec := newRecorder(t)
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("ops", rec.srv.URL, "WARNING", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	broker.PublishTopic(events.TopicCAExpiryAlert, events.SeverityCritical, "ca-1", map[string]any{
		"ca_name": "Corporate Issuing CA", "ca_type": "ISSUING",
		"days_remaining": 9, "threshold": 14,
	})

	waitFor(t, 3*time.Second, "the alert to arrive", func() bool { return rec.count() == 1 })

	body := rec.lastBody()
	for _, want := range []string{"ca.expiry_alert", "CRITICAL", "Corporate Issuing CA", "9 days"} {
		if !strings.Contains(body, want) {
			t.Errorf("delivered body does not mention %q:\n%s", want, body)
		}
	}
	// The consequence, not just the fact. This is the sentence that makes an
	// alert actionable at 2am.
	if !strings.Contains(body, "stops validating") {
		t.Errorf("the alert does not say what breaks when the CA expires:\n%s", body)
	}
}

func TestDispatcherRespectsSeverityAndTopicFilters(t *testing.T) {
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	critical := newRecorder(t)
	expiryOnly := newRecorder(t)
	disabled := newRecorder(t)

	c1 := addChannel(t, s, webhookChannel("critical-only", critical.srv.URL, "CRITICAL", nil))
	sealPlain(t, s, c1, `{"url":"`+critical.srv.URL+`","allow_insecure_http":true}`)

	c2 := addChannel(t, s, webhookChannel("expiry-only", expiryOnly.srv.URL, "INFO", []string{events.TopicCAExpiryAlert}))
	sealPlain(t, s, c2, `{"url":"`+expiryOnly.srv.URL+`","allow_insecure_http":true}`)

	c3 := webhookChannel("switched-off", disabled.srv.URL, "INFO", nil)
	c3.IsEnabled = false
	addChannel(t, s, c3)
	sealPlain(t, s, c3, `{"url":"`+disabled.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	// A WARNING on a topic only one channel wants.
	broker.PublishTopic(events.TopicCertExpiring, events.SeverityWarning, "cert-1", map[string]any{
		"common_name": "www.example.com", "days_remaining": 20,
	})
	// A CRITICAL on the topic both enabled channels want.
	broker.PublishTopic(events.TopicCAExpiryAlert, events.SeverityCritical, "ca-1", map[string]any{
		"ca_name": "Root CA", "days_remaining": 3,
	})

	waitFor(t, 3*time.Second, "both expected deliveries", func() bool {
		return critical.count() == 1 && expiryOnly.count() == 1
	})

	// Give anything mistaken a chance to arrive before asserting it did not.
	time.Sleep(150 * time.Millisecond)

	if got := critical.count(); got != 1 {
		t.Errorf("critical-only channel received %d alerts, want 1 (the WARNING should be below its threshold)", got)
	}
	if got := expiryOnly.count(); got != 1 {
		t.Errorf("expiry-only channel received %d alerts, want 1 (it should not get cert.expiring)", got)
	}
	if got := disabled.count(); got != 0 {
		t.Errorf("a disabled channel received %d alerts", got)
	}
}

func TestDispatcherRetriesAndThenGivesUp(t *testing.T) {
	rec := newRecorder(t)
	rec.failFirst.Store(2) // fail twice, succeed on the third

	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("flaky", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker, WithAttempts(3))
	d.Start()

	broker.PublishTopic(events.TopicCAHealth, events.SeverityWarning, "ca-1", map[string]any{"ca_name": "CA"})

	waitFor(t, 3*time.Second, "three attempts", func() bool { return rec.count() == 3 })
	waitFor(t, 2*time.Second, "the success to be recorded", func() bool { return d.Stats().Delivered == 1 })

	if got := d.Stats().Failed; got != 0 {
		t.Errorf("a delivery that eventually succeeded was counted as %d failures", got)
	}
}

func TestDispatcherStopsRetryingAfterTheLimit(t *testing.T) {
	rec := newRecorder(t)
	rec.failFirst.Store(1000) // never succeeds

	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("down", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker, WithAttempts(2))
	d.Start()

	broker.PublishTopic(events.TopicCAHealth, events.SeverityCritical, "ca-1", map[string]any{"ca_name": "CA"})

	waitFor(t, 3*time.Second, "the failure to be recorded", func() bool { return d.Stats().Failed == 1 })
	time.Sleep(150 * time.Millisecond)

	if got := rec.count(); got != 2 {
		t.Errorf("made %d attempts, want exactly 2 — an endpoint that is down must not be retried indefinitely", got)
	}
	if last := d.Stats().LastError; !strings.Contains(last, "temporarily unavailable") {
		t.Errorf("LastError = %q, want the receiver's own reason", last)
	}
}

// The property this whole subsystem is arranged around. A destination that
// accepts connections and never answers must not be able to slow down the
// producer, because the producer is the CA health sweep.
func TestAWedgedDestinationCannotBlockThePublisher(t *testing.T) {
	rec := newRecorder(t)
	rec.block = make(chan struct{})

	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("wedged", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker, WithSendTimeout(30*time.Second))
	d.Start()

	// Far more events than the dispatcher's buffer or its concurrency limit.
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		for i := 0; i < 500; i++ {
			broker.PublishTopic(events.TopicCAHealth, events.SeverityCritical,
				fmt.Sprintf("ca-%d", i), map[string]any{"ca_name": "CA"})
		}
		done <- time.Since(start)
	}()

	select {
	case took := <-done:
		// Publishing is a channel send with a drop-oldest fallback; it should be
		// microseconds. A generous bound still fails loudly if it ever blocks.
		if took > 2*time.Second {
			t.Errorf("publishing 500 events took %s while a destination was wedged", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the CA health sweep would have been blocked by a wedged notification destination")
	}

	close(rec.block)
}

// Stop must be safe twice and safe when never started — unlike Scheduler's bare
// close(stopCh), which panics on the second call.
func TestStopIsSafeTwiceAndWithoutStart(t *testing.T) {
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	never := NewDispatcher(s, nil, broker)
	never.Stop()
	never.Stop()

	started := NewDispatcher(s, nil, broker)
	started.Start()
	started.Start() // second Start must be a no-op, not a second subscription
	started.Stop()
	started.Stop()
}

func TestDispatcherAuditsBothOutcomes(t *testing.T) {
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	good := newRecorder(t)
	bad := newRecorder(t)
	bad.failFirst.Store(1000)

	c1 := addChannel(t, s, webhookChannel("reachable", good.srv.URL, "INFO", nil))
	sealPlain(t, s, c1, `{"url":"`+good.srv.URL+`","allow_insecure_http":true}`)
	c2 := addChannel(t, s, webhookChannel("unreachable", bad.srv.URL, "INFO", nil))
	sealPlain(t, s, c2, `{"url":"`+bad.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker, WithAttempts(1))
	d.Start()

	broker.PublishTopic(events.TopicCAExpiryAlert, events.SeverityCritical, "ca-1",
		map[string]any{"ca_name": "CA", "days_remaining": 5})

	waitFor(t, 3*time.Second, "both outcomes", func() bool {
		return d.Stats().Delivered == 1 && d.Stats().Failed == 1
	})

	// "We tried and it refused" and "we never tried" look identical from
	// outside, and only one of them means the configuration is wrong.
	sent := auditCount(t, s, "notification.sent")
	failed := auditCount(t, s, "notification.failed")
	if sent != 1 {
		t.Errorf("notification.sent audit entries = %d, want 1", sent)
	}
	if failed != 1 {
		t.Errorf("notification.failed audit entries = %d, want 1", failed)
	}
}

func TestDeliverReportsTheErrorVerbatimAndDoesNotRetry(t *testing.T) {
	rec := newRecorder(t)
	rec.failFirst.Store(1000)

	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("probe", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker)

	err := d.Deliver(context.Background(), ch, TestAlert("probe"))
	if err == nil {
		t.Fatal("a failing destination reported success")
	}
	if !strings.Contains(err.Error(), "temporarily unavailable") {
		t.Errorf("error = %q, want the receiver's reason", err)
	}
	// One attempt. An operator staring at a form wants the answer now, not
	// after three backoffs.
	if got := rec.count(); got != 1 {
		t.Errorf("made %d attempts, want 1 — the test endpoint must not retry", got)
	}
}

// A channel whose type has no notifier can never deliver. That has to surface
// as a loud, audited failure rather than a quiet nothing.
func TestAChannelThatCannotDeliverIsReportedNotIgnored(t *testing.T) {
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, &store.NotificationChannel{
		Name: "teams-please", ChannelType: "teams",
		IsEnabled: true, SeverityThreshold: "INFO",
	})
	sealPlain(t, s, ch, `{}`)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	broker.PublishTopic(events.TopicCAExpiryAlert, events.SeverityCritical, "ca-1", map[string]any{"ca_name": "CA"})

	waitFor(t, 3*time.Second, "the misconfiguration to be recorded", func() bool {
		return d.Stats().Failed == 1
	})
	if n := auditCount(t, s, "notification.failed"); n != 1 {
		t.Errorf("audit entries = %d, want 1", n)
	}
	if last := d.Stats().LastError; !strings.Contains(last, "not supported") {
		t.Errorf("LastError = %q, want it to name the unsupported type", last)
	}
}

func auditCount(t *testing.T, s store.Store, action string) int {
	t.Helper()
	logs, _, err := s.ListAuditLogs(context.Background(), store.AuditLogFilter{
		Actions: []string{action}, Limit: 100,
	})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	return len(logs)
}

// ── Acknowledgement and silencing ───────────────────────

func ptrInt(v int) *int { return &v }

func ackFor(t *testing.T, s store.Store, entityID string, threshold *int, silenceFor time.Duration) *store.AlertAcknowledgement {
	t.Helper()
	ack := &store.AlertAcknowledgement{
		EntityType: store.AckEntityCAAuthority,
		EntityID:   entityID,
		Threshold:  threshold,
		Note:       "handled",
	}
	if silenceFor != 0 {
		until := time.Now().Add(silenceFor)
		ack.SilenceUntil = &until
	}
	if err := s.CreateAcknowledgement(context.Background(), ack); err != nil {
		t.Fatalf("CreateAcknowledgement: %v", err)
	}
	return ack
}

func expiryEvent(broker *events.Broker, entityID string, days, threshold int) {
	broker.PublishTopic(events.TopicCAExpiryAlert, events.SeverityCritical, entityID, map[string]any{
		"ca_name": "Corporate Issuing CA", "ca_type": "ISSUING",
		"days_remaining": days, "threshold": threshold,
	})
}

// An explicit silence keeps the alert out of Slack. Note what is *not* asserted
// here: anything about the dashboard. The event has already reached the broker
// by the time the dispatcher sees it, so display is untouched by construction —
// the API tests cover that the row is still shown, marked.
func TestAnExplicitSilenceSuppressesDelivery(t *testing.T) {
	rec := newRecorder(t)
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("ops", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)
	ackFor(t, s, "ca-1", ptrInt(14), time.Hour)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	expiryEvent(broker, "ca-1", 12, 14)
	time.Sleep(300 * time.Millisecond)

	if got := rec.count(); got != 0 {
		t.Errorf("a silenced alert was delivered %d times", got)
	}
}

// Acknowledging is not silencing. The common case is "yes, we have seen it" —
// the alert stops being new on the dashboard, and still goes out.
func TestAcknowledgingWithoutSilencingStillDelivers(t *testing.T) {
	rec := newRecorder(t)
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("ops", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)
	ackFor(t, s, "ca-1", ptrInt(14), 0) // acknowledged, not silenced

	d := newTestDispatcher(t, s, broker)
	d.Start()

	expiryEvent(broker, "ca-1", 12, 14)
	waitFor(t, 3*time.Second, "the alert to be delivered", func() bool { return rec.count() == 1 })
}

// The property that makes silencing safe rather than dangerous. Someone who
// silenced a CA at 14 days answered a different question from the one asked at
// 7, so the tighter alert must page regardless.
func TestASilenceDoesNotCoverATighterThreshold(t *testing.T) {
	rec := newRecorder(t)
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("ops", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)
	ackFor(t, s, "ca-1", ptrInt(14), time.Hour)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	// Still inside the silenced threshold: quiet.
	expiryEvent(broker, "ca-1", 12, 14)
	time.Sleep(250 * time.Millisecond)
	if got := rec.count(); got != 0 {
		t.Fatalf("the 14-day alert was delivered despite the silence (%d)", got)
	}

	// The CA has since crossed 7 days. That is a new situation.
	expiryEvent(broker, "ca-1", 5, 7)
	waitFor(t, 3*time.Second, "the tighter alert to page", func() bool { return rec.count() == 1 })
}

// A silence covers the entity it was granted for and nothing else.
func TestASilenceIsScopedToItsEntity(t *testing.T) {
	rec := newRecorder(t)
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("ops", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)
	ackFor(t, s, "ca-1", nil, time.Hour)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	expiryEvent(broker, "ca-2", 5, 7)
	waitFor(t, 3*time.Second, "the unrelated CA to alert", func() bool { return rec.count() == 1 })
}

func TestAnExpiredSilenceStopsSuppressing(t *testing.T) {
	rec := newRecorder(t)
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("ops", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)
	ackFor(t, s, "ca-1", ptrInt(14), -time.Minute) // already lapsed

	d := newTestDispatcher(t, s, broker)
	d.Start()

	expiryEvent(broker, "ca-1", 12, 14)
	waitFor(t, 3*time.Second, "delivery once the silence has lapsed", func() bool { return rec.count() == 1 })
}

func TestWithdrawingASilenceResumesDelivery(t *testing.T) {
	rec := newRecorder(t)
	s := store.NewMemoryStore()
	broker := events.NewBroker()
	defer broker.Stop()

	ch := addChannel(t, s, webhookChannel("ops", rec.srv.URL, "INFO", nil))
	sealPlain(t, s, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)
	ack := ackFor(t, s, "ca-1", ptrInt(14), time.Hour)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	expiryEvent(broker, "ca-1", 12, 14)
	time.Sleep(250 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("the silence did not take effect")
	}

	if err := s.RevokeAcknowledgement(context.Background(), ack.ID, nil); err != nil {
		t.Fatalf("RevokeAcknowledgement: %v", err)
	}

	expiryEvent(broker, "ca-1", 12, 14)
	waitFor(t, 3*time.Second, "delivery to resume", func() bool { return rec.count() == 1 })
}

// Fail open. A database blip must not turn into an alert nobody received: the
// cost of a duplicate notification is an annoyed engineer, and the cost of a
// suppressed one is an expired CA.
func TestAFailedAcknowledgementLookupStillDelivers(t *testing.T) {
	rec := newRecorder(t)
	broker := events.NewBroker()
	defer broker.Stop()

	base := store.NewMemoryStore()
	s := &ackLookupFails{Store: base}

	ch := addChannel(t, base, webhookChannel("ops", rec.srv.URL, "INFO", nil))
	sealPlain(t, base, ch, `{"url":"`+rec.srv.URL+`","allow_insecure_http":true}`)

	d := newTestDispatcher(t, s, broker)
	d.Start()

	expiryEvent(broker, "ca-1", 5, 7)
	waitFor(t, 3*time.Second, "delivery despite the failed lookup", func() bool { return rec.count() == 1 })
}

// ackLookupFails is a store whose acknowledgement lookup is broken.
type ackLookupFails struct{ store.Store }

func (a *ackLookupFails) GetActiveAcknowledgement(context.Context, string, string) (*store.AlertAcknowledgement, error) {
	return nil, fmt.Errorf("the acknowledgement table is unreachable")
}
