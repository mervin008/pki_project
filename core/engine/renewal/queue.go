package renewal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// Constants governing how the queue paces itself.
const (
	// pollInterval is how often an idle worker looks for work. Renewals are
	// measured in days, so a few seconds of latency costs nothing — and polling
	// harder would mean N replicas issuing a claim query every second forever.
	pollInterval = 5 * time.Second
	// leaseDuration is how long a claim is held without a heartbeat.
	//
	// Long enough that an ACME order waiting on DNS propagation is not stolen
	// mid-flight, which would turn one renewal into two certificates. Short
	// enough that a worker killed by an OOM does not strand a certificate for
	// an hour.
	leaseDuration = 5 * time.Minute
	// heartbeatInterval keeps a long renewal's lease alive while it runs.
	heartbeatInterval = 90 * time.Second
	// defaultWorkers is how many renewals one replica runs at once. Small on
	// purpose: the bottleneck is a CA's rate limit, not this process, and the
	// failure mode of too many is an account suspended for a week.
	defaultWorkers = 2

	// Retry pacing. Replaced in step 2 by a curve that tightens as the
	// certificate's expiry approaches; a fixed schedule is wrong in both
	// directions, retrying a month-away certificate too eagerly and a
	// three-day-away one nowhere near hard enough.
	baseRetryDelay = 2 * time.Minute
	maxRetryDelay  = 6 * time.Hour

	// escalateAfterAttempts is when a failing renewal stops being noise and
	// becomes somebody's problem. Two failures is a blip — a CA restarting, a
	// DNS propagation delay. Three in a row is a configuration that is not
	// going to fix itself.
	escalateAfterAttempts = 3
	// escalateWithinHours is the other trigger: a certificate close enough to
	// expiry that even one failure matters, because there may not be room for
	// many more attempts.
	escalateWithinHours = 7 * 24
)

// Queue runs renewals from durable rows rather than from calls.
//
// Every replica runs one and none of them is special. Claims use
// FOR UPDATE SKIP LOCKED and enqueues collide on a partial unique index, so two
// workers can never take the same job and two schedulers can never create the
// same one. That is deliberately not leader election: a leader is a single
// point of failure with a window after it dies during which nothing renews at
// all, which is a strange thing to build into the component whose entire job is
// that nothing lapses.
type Queue struct {
	store    store.Store
	executor renewer
	broker   *events.Broker

	worker  string
	workers int
	poll    time.Duration
	lease   time.Duration
	now     func() time.Time

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// QueueOption configures a Queue.
type QueueOption func(*Queue)

// WithWorkers sets how many renewals this replica runs at once.
func WithWorkers(n int) QueueOption {
	return func(q *Queue) {
		if n > 0 {
			q.workers = n
		}
	}
}

// WithPollInterval sets how often an idle worker looks for work.
func WithPollInterval(d time.Duration) QueueOption {
	return func(q *Queue) {
		if d > 0 {
			q.poll = d
		}
	}
}

// WithLease sets how long a claim survives without a heartbeat.
func WithLease(d time.Duration) QueueOption {
	return func(q *Queue) {
		if d > 0 {
			q.lease = d
		}
	}
}

// renewer is the one thing the queue needs from the executor.
//
// An interface so the queue's own behaviour — leases, retries, escalation, the
// crash guard — can be tested without a CA, a gateway, or a network. Those are
// the parts most likely to be wrong and least likely to be exercised by an
// end-to-end run against one working ACME account.
type renewer interface {
	RenewCertificate(ctx context.Context, certID string) (*store.Certificate, error)
}

// NewQueue creates a queue.
func NewQueue(s store.Store, e renewer, broker *events.Broker, opts ...QueueOption) *Queue {
	q := &Queue{
		store:    s,
		executor: e,
		broker:   broker,
		worker:   workerName(),
		workers:  defaultWorkers,
		poll:     pollInterval,
		lease:    leaseDuration,
		now:      time.Now,
		stopCh:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(q)
	}
	return q
}

// workerName identifies this process in the attempt log.
//
// Host and pid, because "every failure came from one replica" and "every
// replica is failing" are different problems and the attempt log is the only
// place that distinction can be seen.
func workerName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Sprintf("%s/%d", host, os.Getpid())
	}
	return fmt.Sprintf("%s/%d-%s", host, os.Getpid(), hex.EncodeToString(suffix))
}

// Start begins the worker pool.
func (q *Queue) Start() {
	if q == nil {
		return
	}
	q.mu.Lock()
	if q.started {
		q.mu.Unlock()
		return
	}
	q.started = true
	q.mu.Unlock()

	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go q.run()
	}
	slog.Info("renewal queue started", "worker", q.worker, "concurrency", q.workers, "lease", q.lease)
}

// Stop ends the pool. Safe to call twice, and on one that never started —
// unlike the scheduler this replaces, whose bare close panicked on the second
// call and made a double shutdown crash the process it was trying to end
// cleanly.
func (q *Queue) Stop() {
	if q == nil {
		return
	}
	q.stopped.Do(func() { close(q.stopCh) })
	q.wg.Wait()
}

func (q *Queue) run() {
	defer q.wg.Done()

	ticker := time.NewTicker(q.poll)
	defer ticker.Stop()

	for {
		// Drain rather than take one per tick: a sweep that enqueues forty
		// renewals should not take forty polling intervals to start them.
		for q.RunOnce(context.Background()) {
			select {
			case <-q.stopCh:
				return
			default:
			}
		}
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// RunOnce claims and runs at most one job. It reports whether it found one, so
// a caller can drain. Exported so a test can drive the queue without a ticker.
func (q *Queue) RunOnce(ctx context.Context) bool {
	job, err := q.store.ClaimRenewalJob(ctx, q.worker, q.lease, q.now())
	if err != nil {
		slog.Error("could not claim a renewal job; renewals are not running", "error", err)
		return false
	}
	if job == nil {
		return false
	}

	q.execute(ctx, job)
	return true
}

// execute runs one claimed job and records what happened.
func (q *Queue) execute(ctx context.Context, job *store.RenewalJob) {
	started := q.now()
	attempt := store.RenewalAttempt{
		Number:    job.Attempts,
		StartedAt: started,
		Worker:    q.worker,
	}
	finish := func(status string, cause error, escalate bool) {
		attempt.DurationMS = q.now().Sub(started).Milliseconds()
		if cause != nil {
			attempt.Error = cause.Error()
		}
		runAfter := q.retryAt(job, started)
		if err := q.store.CompleteRenewalJob(ctx, job.ID, status, attempt, runAfter, escalate); err != nil {
			slog.Error("a renewal finished but its job could not be updated",
				"job", job.ID, "certificate", job.CertificateID, "error", err)
		}
	}

	// The certificate may have been deleted while the job sat in the queue.
	// Cancelled, not failed: nobody needs to be told that a certificate they
	// removed did not renew.
	cert, err := q.store.GetCertificate(ctx, job.CertificateID)
	if err != nil {
		slog.Info("a renewal job outlived its certificate", "job", job.ID, "certificate", job.CertificateID)
		finish(store.RenewalCancelled, fmt.Errorf("the certificate no longer exists"), false)
		return
	}

	// The crash guard.
	//
	// A worker that finalised an order and died before writing the result would
	// otherwise issue a second certificate on the retry — against a rate limit
	// counted per week, for a certificate that is already fine. So the outcome
	// is checked rather than trusted: if the fingerprint has moved on its own,
	// the renewal already happened.
	if job.FingerprintAtEnqueue != "" && cert.FingerprintSHA256 != "" &&
		cert.FingerprintSHA256 != job.FingerprintAtEnqueue {
		slog.Info("renewal already completed by an earlier attempt; not issuing again",
			"job", job.ID, "common_name", cert.CommonName)
		finish(store.RenewalSucceeded, nil, false)
		return
	}

	// Keep the lease alive while the renewal runs. An ACME order waiting on DNS
	// propagation can outlive the lease, and a stolen job means one renewal
	// becomes two certificates.
	done := make(chan struct{})
	defer close(done)
	go q.heartbeat(ctx, job.ID, done)

	if _, err := q.executor.RenewCertificate(ctx, job.CertificateID); err != nil {
		escalate := q.shouldEscalate(job, started)
		slog.Warn("renewal attempt failed",
			"job", job.ID, "common_name", cert.CommonName,
			"attempt", job.Attempts, "runway_hours", int(job.RunwayHours(started)),
			"escalated", escalate, "error", err)

		// Left PENDING: a renewal nobody cancelled keeps trying. There is no
		// attempt count at which a certificate stops needing to be renewed, and
		// a queue that gives up on its own is one that goes quiet exactly when
		// it matters.
		finish(store.RenewalPending, err, escalate)

		if escalate && job.EscalatedAt == nil {
			q.announceEscalation(job, cert, err, started)
		}
		return
	}

	finish(store.RenewalSucceeded, nil, false)
}

// heartbeat extends the lease until the renewal finishes.
func (q *Queue) heartbeat(ctx context.Context, jobID string, done <-chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-q.stopCh:
			return
		case <-ticker.C:
			if err := q.store.ExtendRenewalLease(ctx, jobID, q.worker, q.now().Add(q.lease)); err != nil {
				// Losing the lease is not fatal to the attempt in flight, but
				// it means another worker may now be running the same renewal,
				// which is worth saying out loud.
				slog.Warn("could not extend a renewal lease; another worker may take this job",
					"job", jobID, "error", err)
				return
			}
		}
	}
}

// retryAt decides when a failed job may be attempted again.
//
// Exponential with a cap, and jittered so that forty renewals failing against
// one CA outage do not all come back at the same instant and fail together
// again — a thundering herd against a CA is how a transient outage becomes a
// rate-limit suspension.
//
// Step 2 replaces this with a curve tied to the certificate's remaining life.
// A fixed schedule is wrong in both directions: too eager for a certificate
// with a month left, nowhere near urgent enough for one with three days.
func (q *Queue) retryAt(job *store.RenewalJob, now time.Time) time.Time {
	backoff := time.Duration(float64(baseRetryDelay) * math.Pow(2, float64(max(job.Attempts-1, 0))))
	if backoff > maxRetryDelay || backoff <= 0 {
		backoff = maxRetryDelay
	}

	// Up to 20% either way. Deterministic sources of jitter would defeat the
	// purpose, so this uses crypto/rand rather than a seeded generator that
	// several replicas starting together would agree on.
	jitter := time.Duration(float64(backoff) * 0.2 * randUnit())
	return now.Add(backoff + jitter)
}

// randUnit returns a value in [-1, 1).
func randUnit() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	v := float64(uint64(b[0])<<8|uint64(b[1])) / float64(1<<16)
	return v*2 - 1
}

// shouldEscalate decides whether this failure is somebody's problem yet.
func (q *Queue) shouldEscalate(job *store.RenewalJob, now time.Time) bool {
	if job.Attempts >= escalateAfterAttempts {
		return true
	}
	// Close to expiry, one failure is already enough: there may not be room for
	// many more attempts, and finding out at the third is finding out late.
	runway := job.RunwayHours(now)
	return job.NotAfter != nil && runway < escalateWithinHours
}

// announceEscalation publishes a failing renewal once, when it first becomes
// somebody's problem.
//
// Once, not per attempt. A renewal retrying every few minutes for a fortnight
// would otherwise put thousands of messages in the channel that also carries CA
// expiry alerts, and a channel people mute is worse than no channel.
func (q *Queue) announceEscalation(job *store.RenewalJob, cert *store.Certificate, cause error, now time.Time) {
	if q.broker == nil {
		return
	}

	runway := job.RunwayHours(now)
	q.broker.Publish(events.Event{
		Topic:    events.TopicCertRenewFail,
		Severity: events.SeverityCritical,
		EntityID: cert.ID,
		Payload: map[string]any{
			"common_name":    cert.CommonName,
			"days_remaining": cert.DaysRemaining,
			"attempts":       job.Attempts,
			"runway_hours":   int(runway),
			"job_id":         job.ID,
			"error":          cause.Error(),
		},
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
