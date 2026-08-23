package renewal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// The property that makes renewal backoff different from every other kind:
// as the deadline approaches, the delay must shrink rather than grow.
//
// Ordinary exponential backoff assumes there is no deadline. A certificate
// violates that outright — the cost of not retrying grows without bound as
// expiry nears, while the cost of retrying stays flat.
func TestBackoffTightensAsExpiryApproaches(t *testing.T) {
	q := NewQueue(store.NewMemoryStore(), &fakeRenewer{}, nil)
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	// The same job, failing the same number of times, at different distances
	// from its deadline.
	delayWith := func(runway time.Duration) time.Duration {
		expiry := now.Add(runway)
		job := &store.RenewalJob{Attempts: 8, NotAfter: &expiry}
		return q.retryAt(job, now).Sub(now)
	}

	month := delayWith(30 * 24 * time.Hour)
	day := delayWith(24 * time.Hour)
	hour := delayWith(time.Hour)

	if !(month > day && day > hour) {
		t.Fatalf("backoff did not tighten towards the deadline: month=%s day=%s hour=%s", month, day, hour)
	}

	// And the tightening has to be worth something. With a day left, a fixed
	// exponential would have been sitting at the six-hour ceiling — four more
	// tries before expiry. The budget has to buy considerably more than that.
	if day > 2*time.Hour {
		t.Errorf("with 24 hours left the retry delay is %s; that leaves almost no attempts", day)
	}
	if hour > 10*time.Minute {
		t.Errorf("with 1 hour left the retry delay is %s", hour)
	}
}

// Never faster than the floor, however desperate. A CA answering the same error
// once a second will not answer differently on the two hundredth try.
func TestBackoffNeverDropsBelowTheFloor(t *testing.T) {
	q := NewQueue(store.NewMemoryStore(), &fakeRenewer{}, nil)
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	for _, runway := range []time.Duration{time.Minute, 0, -48 * time.Hour} {
		expiry := now.Add(runway)
		job := &store.RenewalJob{Attempts: 20, NotAfter: &expiry}
		for i := 0; i < 20; i++ {
			if got := q.retryAt(job, now).Sub(now); got < minRetryDelay {
				t.Fatalf("runway %s produced a %s delay, below the %s floor", runway, got, minRetryDelay)
			}
		}
	}
}

// An already-expired certificate is an outage, and getting it back matters more
// than politeness — but it still must not be hammered.
func TestAnExpiredCertificateRetriesAtTheFloor(t *testing.T) {
	q := NewQueue(store.NewMemoryStore(), &fakeRenewer{}, nil)
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-3 * 24 * time.Hour)

	job := &store.RenewalJob{Attempts: 15, NotAfter: &expired}
	got := q.retryAt(job, now).Sub(now)
	if got > 2*minRetryDelay {
		t.Errorf("an expired certificate backed off %s; it is failing right now", got)
	}
}

// With no deadline recorded there is nothing to tighten towards, so it must
// fall back to the ordinary curve rather than to the floor.
func TestWithoutADeadlineTheOrdinaryCurveApplies(t *testing.T) {
	q := NewQueue(store.NewMemoryStore(), &fakeRenewer{}, nil)
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	early := q.retryAt(&store.RenewalJob{Attempts: 1}, now).Sub(now)
	late := q.retryAt(&store.RenewalJob{Attempts: 6}, now).Sub(now)
	if late <= early {
		t.Errorf("without a deadline the curve did not grow: %s then %s", early, late)
	}
}

// ── rate limiting ───────────────────────────────────────────

func accountWithLimit(t *testing.T, st store.Store, name string, limit, windowHours int) *store.CAAccount {
	t.Helper()
	acc := &store.CAAccount{
		Name: name, ProviderType: "acme", GatewayAddr: "localhost:9091", Status: "CONNECTED",
		RenewalRateLimit: limit, RenewalRateWindowHours: windowHours,
	}
	if err := st.CreateCAAccount(context.Background(), acc); err != nil {
		t.Fatalf("CreateCAAccount: %v", err)
	}
	return acc
}

func certForAccount(t *testing.T, st store.Store, cn string, acc *store.CAAccount, expiresIn time.Duration) *store.Certificate {
	t.Helper()
	notAfter := time.Now().Add(expiresIn)
	cert := &store.Certificate{
		CommonName: cn, SerialNumber: "serial-" + cn, FingerprintSHA256: "fp-" + cn,
		NotAfter: &notAfter, Status: "ISSUED", CAAccountID: &acc.ID,
	}
	if err := st.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return cert
}

// A renewal held back by a quota must not read as a failure. It is the system
// working — it declined to spend a limit whose exhaustion suspends issuance for
// the whole organisation.
func TestARateLimitedRenewalIsDeferredNotFailed(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	acc := accountWithLimit(t, st, "letsencrypt-prod", 1, 168)
	first := certForAccount(t, st, "first.example.com", acc, 20*24*time.Hour)
	second := certForAccount(t, st, "second.example.com", acc, 20*24*time.Hour)

	sched := NewScheduler(st, 30)
	gateway := &fakeRenewer{}
	q := NewQueue(st, gateway, nil)

	// Spend the account's single slot.
	if _, err := sched.Enqueue(ctx, first, store.RenewalReasonScheduled, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !q.RunOnce(ctx) {
		t.Fatal("the first renewal was not claimed")
	}
	if gateway.callCount() != 1 {
		t.Fatalf("the first renewal did not reach the gateway (%d calls)", gateway.callCount())
	}

	// The second must now wait rather than spend a slot that does not exist.
	if _, err := sched.Enqueue(ctx, second, store.RenewalReasonScheduled, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !q.RunOnce(ctx) {
		t.Fatal("the second renewal was not claimed")
	}
	if gateway.callCount() != 1 {
		t.Fatal("a renewal was sent to the CA past its rate limit")
	}

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: second.ID})
	job := jobs[0]

	if job.Status != store.RenewalPending {
		t.Errorf("status = %s, want PENDING", job.Status)
	}
	if job.Attempts != 0 {
		t.Errorf("attempts = %d, want 0 — nothing was attempted, so nothing may be counted", job.Attempts)
	}
	if job.LastError != "" {
		t.Errorf("last_error = %q; a deferral is not an error and must not overwrite one", job.LastError)
	}
	if job.EscalatedAt != nil {
		t.Error("a certificate waiting on a quota was escalated as broken")
	}
	if len(job.AttemptLog) != 1 || !job.AttemptLog[0].Deferred {
		t.Fatalf("the deferral was not recorded distinctly: %+v", job.AttemptLog)
	}
	if job.AttemptLog[0].Reason == "" {
		t.Error("the deferral does not say why, so nobody can tell it from a stall")
	}

	// And it comes back exactly when a slot opens, not by polling.
	if !job.RunAfter.After(time.Now().Add(160 * time.Hour)) {
		t.Errorf("run_after = %s; the slot does not open for a week", job.RunAfter)
	}
}

// The sharpest thing this engine can say: the quota does not free up until
// after the certificate has expired. Not a deferral — a loss with a date on it.
func TestALimitThatOutlastsTheCertificateIsEscalated(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	acc := accountWithLimit(t, st, "letsencrypt-prod", 1, 168)
	spent := certForAccount(t, st, "spent.example.com", acc, 90*24*time.Hour)
	// Expires well inside the window that has to elapse before a slot opens.
	doomed := certForAccount(t, st, "doomed.example.com", acc, 48*time.Hour)

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCertRenewFail)
	defer sub.Close()

	sched := NewScheduler(st, 30)
	q := NewQueue(st, &fakeRenewer{}, broker)

	_, _ = sched.Enqueue(ctx, spent, store.RenewalReasonScheduled, nil, nil)
	q.RunOnce(ctx)

	_, _ = sched.Enqueue(ctx, doomed, store.RenewalReasonScheduled, nil, nil)
	q.RunOnce(ctx)

	select {
	case evt := <-sub.Events():
		payload, _ := evt.Payload.(map[string]any)
		if payload["blocked_by"] == nil {
			t.Fatalf("the alert does not say it is a quota rather than a fault: %+v", payload)
		}
		if evt.Severity != events.SeverityCritical {
			t.Errorf("severity = %s, want CRITICAL", evt.Severity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a certificate that will expire before its CA's quota frees up produced no alert")
	}
}

// An account with no limit set must never be held back. Inventing a
// conservative default for a CA whose real limits nobody entered would delay
// renewals for a constraint that does not exist.
func TestAnAccountWithNoLimitIsNeverHeldBack(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	acc := accountWithLimit(t, st, "internal-ca", 0, 168)
	sched := NewScheduler(st, 30)
	gateway := &fakeRenewer{}
	q := NewQueue(st, gateway, nil)

	for i := 0; i < 5; i++ {
		cert := certForAccount(t, st, string(rune('a'+i))+".internal", acc, 20*24*time.Hour)
		if _, err := sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil); err != nil {
			t.Fatal(err)
		}
		if !q.RunOnce(ctx) {
			t.Fatalf("renewal %d was not claimed", i)
		}
	}
	if gateway.callCount() != 5 {
		t.Errorf("%d of 5 renewals reached the gateway; an unlimited account held renewals back", gateway.callCount())
	}
}

// A failure to read the limit must not stop the renewal. Refusing to renew
// because a quota could not be counted turns a database hiccup into an expiry,
// and being one over a quota is a far smaller problem than being one
// certificate short.
func TestAnUnreadableLimitDoesNotBlockRenewal(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	cert := testCertificate(t, st, "orphan.example.com", 20*24*time.Hour)
	// A CA account id that does not resolve — the lookup will fail.
	missing := "no-such-account"
	cert.CAAccountID = &missing
	if err := st.UpdateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}

	sched := NewScheduler(st, 30)
	gateway := &fakeRenewer{}
	q := NewQueue(st, gateway, nil)

	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)
	if !q.RunOnce(ctx) {
		t.Fatal("the job was not claimed")
	}
	if gateway.callCount() != 1 {
		t.Fatal("a renewal was blocked because its account's rate limit could not be read")
	}
}

// Deferrals must not accumulate into an escalation. A job that has waited on a
// quota nine times has not failed nine times.
func TestRepeatedDeferralsDoNotEscalate(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	acc := accountWithLimit(t, st, "busy-ca", 1, 168)
	spent := certForAccount(t, st, "spent.example.com", acc, 200*24*time.Hour)
	waiting := certForAccount(t, st, "waiting.example.com", acc, 200*24*time.Hour)

	sched := NewScheduler(st, 30)
	q := NewQueue(st, &fakeRenewer{}, nil)

	_, _ = sched.Enqueue(ctx, spent, store.RenewalReasonScheduled, nil, nil)
	q.RunOnce(ctx)
	_, _ = sched.Enqueue(ctx, waiting, store.RenewalReasonScheduled, nil, nil)

	for i := 0; i < 9; i++ {
		jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: waiting.ID})
		// Pull it forward so the queue keeps finding it ready.
		if err := st.DeferRenewalJob(ctx, jobs[0].ID, time.Now().Add(-time.Second), "test", false); err != nil {
			t.Fatal(err)
		}
		if !q.RunOnce(ctx) {
			t.Fatalf("deferral round %d claimed nothing", i)
		}
	}

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: waiting.ID})
	if jobs[0].Attempts != 0 {
		t.Errorf("attempts = %d after nine deferrals, want 0", jobs[0].Attempts)
	}
	if jobs[0].EscalatedAt != nil {
		t.Fatal("waiting on a quota nine times escalated a certificate that is not broken")
	}
}

// A real failure after a deferral still escalates normally: the deferral must
// suppress false alarms without suppressing true ones.
func TestARealFailureStillEscalatesAfterDeferrals(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	cert := testCertificate(t, st, "genuinely-broken.example.com", 200*24*time.Hour)
	sched := NewScheduler(st, 30)
	q := NewQueue(st, &fakeRenewer{err: errors.New("the gateway is not connected")}, nil)
	_, _ = sched.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)

	jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: cert.ID})
	id := jobs[0].ID
	for i := 0; i < 3; i++ {
		_ = st.DeferRenewalJob(ctx, id, time.Now().Add(-time.Second), "waiting", false)
	}

	for i := 0; i < 3; i++ {
		_ = st.CompleteRenewalJob(ctx, id, store.RenewalPending, store.RenewalAttempt{}, time.Now().Add(-time.Second), false)
		if !q.RunOnce(ctx) {
			t.Fatalf("attempt %d claimed nothing", i)
		}
	}

	job, _ := st.GetRenewalJob(ctx, id)
	if job.EscalatedAt == nil {
		t.Fatal("three genuine failures did not escalate; deferrals suppressed a real alarm")
	}
}

// The blocked-by-quota alert must fire once, not on every deferral.
//
// Found live: the announcement went out but the escalation mark was never
// persisted, so a certificate deferred every hour would have sent the same
// CRITICAL message every hour until it expired.
func TestTheBlockedAlertIsAnnouncedOnce(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	acc := accountWithLimit(t, st, "tiny-quota", 1, 20000)
	spent := certForAccount(t, st, "spent.example.com", acc, 200*24*time.Hour)
	doomed := certForAccount(t, st, "doomed.example.com", acc, 48*time.Hour)

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCertRenewFail)
	defer sub.Close()

	sched := NewScheduler(st, 30)
	q := NewQueue(st, &fakeRenewer{}, broker)

	_, _ = sched.Enqueue(ctx, spent, store.RenewalReasonScheduled, nil, nil)
	q.RunOnce(ctx)
	_, _ = sched.Enqueue(ctx, doomed, store.RenewalReasonScheduled, nil, nil)

	// Deferred five times over, as it would be by a poller.
	for i := 0; i < 5; i++ {
		jobs, _, _ := st.ListRenewalJobs(ctx, store.RenewalJobFilter{CertificateID: doomed.ID})
		if err := st.DeferRenewalJob(ctx, jobs[0].ID, time.Now().Add(-time.Second), "pulled forward", false); err != nil {
			t.Fatal(err)
		}
		if !q.RunOnce(ctx) {
			t.Fatalf("round %d claimed nothing", i)
		}
	}

	published := 0
	for {
		select {
		case <-sub.Events():
			published++
			continue
		case <-time.After(300 * time.Millisecond):
		}
		break
	}
	if published != 1 {
		t.Fatalf("%d alerts for one certificate blocked by a quota, want exactly 1", published)
	}
}
