package notifications

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// Defaults, all overridable for tests.
const (
	// defaultBuffer is how far behind the dispatcher may fall before the broker
	// starts dropping its oldest queued events.
	//
	// Deliberately shallower than the SSE handler's. A browser absorbing a
	// burst wants depth; a dispatcher making outbound HTTP calls does not, and
	// working through a backlog of superseded alerts is worse than reporting
	// current reality late.
	defaultBuffer = 64

	// defaultAttempts includes the first try. A destination that has refused
	// three times inside a minute is down, and retrying past that turns one
	// outage into a queue that outlives it.
	defaultAttempts = 3

	// defaultConcurrency bounds in-flight deliveries. Without a bound, a relay
	// that accepts connections and never answers accumulates a goroutine per
	// alert per channel until the process runs out of memory.
	defaultConcurrency = 8

	// defaultChannelTTL is how long the channel list is cached.
	//
	// A health sweep publishes one event per CA, and reading the channel table
	// per event would turn a sweep across a few hundred CAs into a few hundred
	// queries for data that changes weekly. The cost is that a newly saved
	// channel can take this long to start delivering.
	defaultChannelTTL = 30 * time.Second

	// defaultSendTimeout bounds one delivery attempt.
	defaultSendTimeout = 15 * time.Second
)

// Dispatcher delivers published events to the configured notification channels.
//
// It is an ordinary broker subscriber, which is the whole design: the CA health
// sweep publishes and moves on, and a wedged Slack webhook can only ever cost
// this subscriber its place in the queue. Nothing here can apply backpressure to
// monitoring.
type Dispatcher struct {
	store   store.Store
	keyring *secrets.Keyring
	broker  *events.Broker
	client  *http.Client

	attempts    int
	concurrency int
	channelTTL  time.Duration
	sendTimeout time.Duration

	// backoff returns the delay before attempt n (1-based). Replaceable so
	// tests do not have to sleep through real backoff.
	backoff func(attempt int) time.Duration

	mu         sync.Mutex
	cached     []*store.NotificationChannel
	cachedAt   time.Time
	lastErr    error
	deliveries uint64
	failures   uint64

	sub      *events.Subscription
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	sem      chan struct{}
	started  bool
}

// Option configures a Dispatcher.
type Option func(*Dispatcher)

// WithAttempts sets how many times a delivery is tried, including the first.
func WithAttempts(n int) Option {
	return func(d *Dispatcher) {
		if n > 0 {
			d.attempts = n
		}
	}
}

// WithBackoff replaces the retry schedule.
func WithBackoff(fn func(attempt int) time.Duration) Option {
	return func(d *Dispatcher) {
		if fn != nil {
			d.backoff = fn
		}
	}
}

// WithChannelTTL sets how long the channel list is cached.
func WithChannelTTL(ttl time.Duration) Option {
	return func(d *Dispatcher) { d.channelTTL = ttl }
}

// WithHTTPClient replaces the client used by the Slack and webhook notifiers.
func WithHTTPClient(c *http.Client) Option {
	return func(d *Dispatcher) {
		if c != nil {
			d.client = c
		}
	}
}

// WithSendTimeout bounds a single delivery attempt.
func WithSendTimeout(t time.Duration) Option {
	return func(d *Dispatcher) {
		if t > 0 {
			d.sendTimeout = t
		}
	}
}

// NewDispatcher creates a dispatcher. It does not subscribe until Start.
func NewDispatcher(s store.Store, kr *secrets.Keyring, b *events.Broker, opts ...Option) *Dispatcher {
	d := &Dispatcher{
		store:       s,
		keyring:     kr,
		broker:      b,
		client:      DefaultClient(),
		attempts:    defaultAttempts,
		concurrency: defaultConcurrency,
		channelTTL:  defaultChannelTTL,
		sendTimeout: defaultSendTimeout,
		backoff:     exponentialBackoff,
		stopCh:      make(chan struct{}),
	}
	for _, opt := range opts {
		opt(d)
	}
	d.sem = make(chan struct{}, d.concurrency)
	return d
}

// exponentialBackoff waits 1s, 2s, 4s… with jitter, capped at 30 seconds.
//
// Jittered so that several channels failing against the same outage do not
// retry in lockstep and arrive together the moment it recovers.
func exponentialBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := time.Second << (attempt - 1)
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	jitter := 0.8 + rand.Float64()*0.4 //nolint:gosec // scheduling jitter, not a security decision
	return time.Duration(float64(base) * jitter)
}

// Start subscribes to the broker and begins delivering.
//
// Following CAMonitor's idiom rather than Scheduler's: Stop is safe to call
// twice, and safe to call on a dispatcher that was never started.
func (d *Dispatcher) Start() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return
	}
	d.started = true
	d.mu.Unlock()

	// Every topic. Which events matter is a per-channel decision, made by the
	// operator through severity thresholds and topic filters, not baked in here.
	d.sub = d.broker.SubscribeWithBuffer(defaultBuffer)

	d.wg.Add(1)
	go d.run()

	slog.Info("notification dispatcher started",
		"attempts", d.attempts, "concurrency", d.concurrency)
}

func (d *Dispatcher) run() {
	defer d.wg.Done()

	for {
		select {
		case <-d.stopCh:
			return
		case evt, ok := <-d.sub.Events():
			if !ok {
				// The broker stopped. Nothing further will arrive.
				return
			}
			d.handle(evt)
		}
	}
}

// handle fans one event out to every channel that accepts it.
//
// Deliberately does not block on delivery: it acquires a slot and hands off, so
// the loop returns to draining the subscription. A dispatcher blocked on SMTP is
// a dispatcher losing events it has not looked at yet.
func (d *Dispatcher) handle(evt events.Event) {
	channels, err := d.channels(context.Background())
	if err != nil {
		d.recordError(fmt.Errorf("could not load notification channels: %w", err))
		slog.Error("notification channels could not be loaded; alerts are not being delivered",
			"error", err, "topic", evt.Topic)
		return
	}

	alert := AlertFromEvent(evt)
	severity := normalizeSeverity(evt.Severity)

	for _, ch := range channels {
		if !ch.Accepts(evt.Topic, severity) {
			continue
		}

		select {
		case d.sem <- struct{}{}:
		case <-d.stopCh:
			return
		}

		d.wg.Add(1)
		go func(ch *store.NotificationChannel) {
			defer d.wg.Done()
			defer func() { <-d.sem }()
			d.deliver(ch, alert)
		}(ch)
	}
}

// deliver sends one alert to one channel, retrying, and records the outcome.
func (d *Dispatcher) deliver(ch *store.NotificationChannel, alert Alert) {
	notifier, err := d.notifierFor(ch)
	if err != nil {
		// A channel whose configuration cannot be read will never deliver, so
		// it is reported loudly rather than retried into silence.
		d.audit(ch, alert, err)
		slog.Error("notification channel is misconfigured and cannot deliver",
			"channel", ch.Name, "type", ch.ChannelType, "error", err)
		d.recordFailure(err)
		return
	}

	var lastErr error
	for attempt := 1; attempt <= d.attempts; attempt++ {
		if attempt > 1 {
			select {
			case <-time.After(d.backoff(attempt - 1)):
			case <-d.stopCh:
				// Shutting down. Recording the abandonment beats a silent drop.
				d.audit(ch, alert, fmt.Errorf("shutting down before retry %d: %w", attempt, lastErr))
				d.recordFailure(lastErr)
				return
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), d.sendTimeout)
		err := notifier.Send(ctx, alert)
		cancel()

		if err == nil {
			d.audit(ch, alert, nil)
			d.markSent(ch)
			d.recordSuccess()
			slog.Debug("alert delivered", "channel", ch.Name, "topic", alert.Topic, "attempt", attempt)
			return
		}

		lastErr = err
		slog.Warn("alert delivery failed",
			"channel", ch.Name, "type", ch.ChannelType,
			"topic", alert.Topic, "attempt", attempt, "of", d.attempts, "error", err)
	}

	d.audit(ch, alert, lastErr)
	d.recordFailure(lastErr)
	slog.Error("alert was not delivered after every attempt",
		"channel", ch.Name, "topic", alert.Topic, "attempts", d.attempts, "error", lastErr)
}

// Deliver sends an alert to one named channel immediately, without retry, and
// returns the error verbatim.
//
// This is what the test endpoint calls. It does not retry and does not swallow:
// an operator who has just saved a configuration needs the relay's actual
// complaint, and needs it now rather than after three backoffs.
func (d *Dispatcher) Deliver(ctx context.Context, ch *store.NotificationChannel, alert Alert) error {
	// A nil dispatcher is a valid "delivery disabled" configuration, matching
	// the nil broker it subscribes to. Saying so beats a panic, and beats
	// reporting a success that never happened.
	if d == nil {
		return fmt.Errorf("notification delivery is not configured on this server")
	}

	notifier, err := d.notifierFor(ch)
	if err != nil {
		return err
	}

	sendCtx, cancel := context.WithTimeout(ctx, d.sendTimeout)
	defer cancel()

	if err := notifier.Send(sendCtx, alert); err != nil {
		d.audit(ch, alert, err)
		return err
	}
	d.audit(ch, alert, nil)
	d.markSent(ch)
	return nil
}

// notifierFor unseals a channel's configuration and builds its notifier.
func (d *Dispatcher) notifierFor(ch *store.NotificationChannel) (Notifier, error) {
	config := []byte("{}")
	if ch.ConfigEncrypted != "" {
		if d.keyring == nil {
			return nil, fmt.Errorf("no encryption keyring is available to read this channel's configuration")
		}
		plain, err := d.keyring.DecryptString(ch.ConfigEncrypted, secrets.ContextNotificationConfig)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt the channel configuration: %w", err)
		}
		config = []byte(plain)
	}
	return Build(ch.ChannelType, config, d.client)
}

// channels returns the enabled channels, from cache when it is fresh.
func (d *Dispatcher) channels(ctx context.Context) ([]*store.NotificationChannel, error) {
	d.mu.Lock()
	if d.cached != nil && time.Since(d.cachedAt) < d.channelTTL {
		cached := d.cached
		d.mu.Unlock()
		return cached, nil
	}
	d.mu.Unlock()

	loadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	all, err := d.store.ListNotificationChannels(loadCtx)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.cached = all
	d.cachedAt = time.Now()
	d.mu.Unlock()

	return all, nil
}

// InvalidateChannels drops the cached channel list.
//
// Called by the API after a channel is saved, so a newly configured destination
// starts delivering immediately rather than at the end of the TTL — the moment
// an operator most wants to see it work.
func (d *Dispatcher) InvalidateChannels() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.cached = nil
	d.mu.Unlock()
}

// markSent records a successful delivery against the channel.
func (d *Dispatcher) markSent(ch *store.NotificationChannel) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.store.MarkNotificationChannelSent(ctx, ch.ID, time.Now()); err != nil {
		slog.Warn("could not record the delivery time", "channel", ch.Name, "error", err)
	}
}

// audit writes the outcome to the audit log.
//
// Both outcomes are recorded. "We tried and Slack refused" and "we never tried"
// look identical from the outside, and only one of them means the alerting
// configuration is wrong.
func (d *Dispatcher) audit(ch *store.NotificationChannel, alert Alert, sendErr error) {
	action := "notification.sent"
	detail := fmt.Sprintf(`{"channel":%q,"type":%q,"topic":%q,"severity":%q}`,
		ch.Name, ch.ChannelType, alert.Topic, alert.Severity)
	if sendErr != nil {
		action = "notification.failed"
		detail = fmt.Sprintf(`{"channel":%q,"type":%q,"topic":%q,"severity":%q,"error":%q}`,
			ch.Name, ch.ChannelType, alert.Topic, alert.Severity, truncate(sendErr.Error(), 500))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	channelID := ch.ID
	if err := d.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     action,
		EntityType: "notification_channel",
		EntityID:   &channelID,
		Details:    detail,
	}); err != nil {
		slog.Warn("could not audit a notification outcome", "channel", ch.Name, "error", err)
	}
}

func (d *Dispatcher) recordSuccess() {
	d.mu.Lock()
	d.deliveries++
	d.lastErr = nil
	d.mu.Unlock()
}

func (d *Dispatcher) recordFailure(err error) {
	d.mu.Lock()
	d.failures++
	d.lastErr = err
	d.mu.Unlock()
}

func (d *Dispatcher) recordError(err error) {
	d.mu.Lock()
	d.lastErr = err
	d.mu.Unlock()
}

// Stats reports what the dispatcher has done, for the health endpoint.
type Stats struct {
	Delivered uint64 `json:"delivered"`
	Failed    uint64 `json:"failed"`
	LastError string `json:"last_error,omitempty"`
}

// Stats returns delivery counters since start.
func (d *Dispatcher) Stats() Stats {
	if d == nil {
		return Stats{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s := Stats{Delivered: d.deliveries, Failed: d.failures}
	if d.lastErr != nil {
		s.LastError = d.lastErr.Error()
	}
	return s
}

// Stop ends delivery and waits for in-flight sends to finish or abandon.
//
// Safe to call more than once, and safe on a dispatcher that never started —
// unlike Scheduler's bare close, which panics on the second call.
func (d *Dispatcher) Stop() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() {
		close(d.stopCh)
		if d.sub != nil {
			d.sub.Close()
		}
	})

	// Bounded: a send already in flight has its own timeout, and shutdown must
	// not be held open by a relay that has stopped answering.
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		slog.Warn("notification dispatcher did not finish in time; abandoning in-flight deliveries")
	}
}

// Lossy reports whether the dispatcher has fallen behind and lost events.
//
// Worth surfacing rather than hiding: it means alerts were published that this
// subscriber never saw, which is precisely the kind of gap this subsystem is
// supposed to close.
func (d *Dispatcher) Lossy() bool {
	if d == nil {
		return false
	}
	return d.sub != nil && d.sub.Lossy()
}

// Dropped returns how many events the dispatcher never saw.
func (d *Dispatcher) Dropped() uint64 {
	if d.sub == nil {
		return 0
	}
	return d.sub.Dropped()
}

// TestAlert builds the alert the test endpoint sends.
//
// Explicitly labelled. An operator testing a channel at 4pm must not leave the
// on-call engineer wondering at 4am whether the CA in the alert is real.
func TestAlert(channelName string) Alert {
	return Alert{
		Severity: events.SeverityWarning,
		Topic:    "notification.test",
		Title:    "CertPilot test alert",
		Summary: strings.TrimSpace(fmt.Sprintf(
			"This is a test of the %q notification channel. No certificate authority is in trouble; "+
				"if you received this, delivery is working.", channelName)),
		Fields: []Field{
			{Label: "Channel", Value: channelName},
			{Label: "Sent by", Value: "an operator, from the CertPilot settings page"},
		},
		Timestamp: time.Now(),
	}
}
