package deploy

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
	// pollInterval is how often an idle worker looks for work.
	pollInterval = 5 * time.Second
	// leaseDuration is how long a claim is held without a heartbeat.
	leaseDuration = 3 * time.Minute
	// heartbeatInterval keeps a slow deployment's lease alive while it runs.
	heartbeatInterval = 60 * time.Second

	// defaultWorkers is how many deployments one replica runs at once.
	//
	// Small, and not for throughput. This number is how much of an estate one
	// bad certificate can reach before a person has a chance to cancel the
	// rest: a wildcard bound to forty load balancers deploying all at once is
	// forty listeners changed before anybody has read the first alert.
	defaultWorkers = 2

	// Retry pacing. Faster at the start than renewal's, because a deployment
	// costs nothing on the far side and the commonest failure is a receiver
	// that is briefly restarting.
	baseRetryDelay = 60 * time.Second
	maxRetryDelay  = 1 * time.Hour
	minRetryDelay  = 30 * time.Second

	// attemptBudget is how many more tries the pacing aims to fit before the
	// certificate expires — the same deadline-aware shape as the renewal queue.
	// A certificate that is renewed and undeployed is on exactly the same clock
	// as one that was never renewed at all.
	attemptBudget = 24

	// escalateAfterAttempts is when a failing deployment stops being noise.
	escalateAfterAttempts = 3
	// escalateWithinHours is the other trigger: close enough to expiry that one
	// failure already matters.
	escalateWithinHours = 7 * 24
)

// deployer is the one thing the queue needs from the executor.
//
// An interface so the queue's own behaviour — leases, retries, escalation — is
// testable without a target, a network, or a certificate.
type deployer interface {
	Deploy(ctx context.Context, job *store.DeploymentJob) (string, error)
}

// Queue runs deployments from durable rows rather than from calls.
//
// Same shape as the renewal queue and safe on every replica for the same
// reasons: claims use FOR UPDATE SKIP LOCKED, and enqueues collide on a partial
// unique index. One difference, and it is the important one — that index is on
// the binding, not the certificate. A certificate going to six targets is six
// jobs outstanding at once, and copying renewal's constraint would have
// deployed to the first and dropped five without a word.
type Queue struct {
	store    store.Store
	executor deployer
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

// WithWorkers sets how many deployments this replica runs at once.
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

// NewQueue creates a queue.
func NewQueue(s store.Store, e deployer, broker *events.Broker, opts ...QueueOption) *Queue {
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

// workerName identifies this process in the attempt log. Host and pid, because
// "every failure came from one replica" and "every replica is failing" are
// different problems.
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
	slog.Info("deployment queue started", "worker", q.worker, "concurrency", q.workers, "lease", q.lease)
}

// Stop ends the pool. Safe to call twice, and on one that never started.
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
		// Drain rather than take one per tick: a renewal that fans out to six
		// targets should not take six polling intervals to reach the sixth.
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
	job, err := q.store.ClaimDeploymentJob(ctx, q.worker, q.lease, q.now())
	if err != nil {
		slog.Error("could not claim a deployment job; deployments are not running", "error", err)
		return false
	}
	if job == nil {
		return false
	}

	q.execute(ctx, job)
	return true
}

// execute runs one claimed job and records what happened.
func (q *Queue) execute(ctx context.Context, job *store.DeploymentJob) {
	started := q.now()
	attempt := store.DeploymentAttempt{
		Number:    job.Attempts,
		StartedAt: started,
		Worker:    q.worker,
	}
	finish := func(status string, detail string, cause error, escalate bool) {
		attempt.DurationMS = q.now().Sub(started).Milliseconds()
		attempt.Detail = detail
		if cause != nil {
			attempt.Error = cause.Error()
		}
		runAfter := q.retryAt(job, started)
		if err := q.store.CompleteDeploymentJob(ctx, job.ID, status, attempt, runAfter, escalate); err != nil {
			slog.Error("a deployment finished but its job could not be updated",
				"job", job.ID, "deployment", job.DeploymentID, "error", err)
		}
	}

	// Keep the lease alive while the deployment runs. A target that writes and
	// then waits for a reload can outlive the lease, and a stolen job means the
	// same certificate installed twice — harmless in itself, but it also means
	// two workers reporting different outcomes for one place.
	done := make(chan struct{})
	defer close(done)
	go q.heartbeat(ctx, job.ID, done)

	detail, err := q.executor.Deploy(ctx, job)
	if err != nil {
		escalate := q.shouldEscalate(job, started)
		slog.Warn("deployment attempt failed",
			"job", job.ID, "deployment", job.DeploymentID,
			"attempt", job.Attempts, "escalated", escalate, "error", err)

		// Left PENDING. A certificate that has been renewed and not installed
		// is on the same clock as one that was never renewed, so there is no
		// attempt count at which giving up is the right answer. It escalates
		// instead, once.
		finish(store.DeployPending, "", err, escalate)

		if escalate && job.EscalatedAt == nil {
			q.announceEscalation(ctx, job, err, started)
		}
		return
	}

	finish(store.DeploySucceeded, detail, nil, false)
}

// heartbeat extends the lease until the deployment finishes.
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
			if err := q.store.ExtendDeploymentLease(ctx, jobID, q.worker, q.now().Add(q.lease)); err != nil {
				slog.Warn("could not extend a deployment lease; another worker may take this job",
					"job", jobID, "error", err)
				return
			}
		}
	}
}

// retryAt decides when a failed job may be attempted again.
//
// The smaller of ordinary exponential backoff and what the deadline allows —
// the same shape as the renewal queue, for the same reason. A certificate that
// exists and has not reached the server expires on exactly the schedule of one
// that was never renewed, so as the runway shrinks the cost of not retrying
// grows without bound while the cost of retrying stays flat.
func (q *Queue) retryAt(job *store.DeploymentJob, now time.Time) time.Time {
	delay := time.Duration(float64(baseRetryDelay) * math.Pow(2, float64(maxInt(job.Attempts-1, 0))))
	if delay > maxRetryDelay || delay <= 0 {
		delay = maxRetryDelay
	}

	if job.NotAfter != nil {
		runway := job.NotAfter.Sub(now)
		switch {
		case runway <= 0:
			delay = minRetryDelay
		default:
			if budgeted := runway / attemptBudget; budgeted < delay {
				delay = budgeted
			}
		}
	}

	// Jittered, because a receiver that restarts takes every deployment queued
	// against it down at once, and all of them returning at the same instant is
	// how a restart becomes a thundering herd.
	jittered := delay + time.Duration(float64(delay)*0.2*randUnit())
	if jittered < minRetryDelay {
		jittered = minRetryDelay
	}
	return now.Add(jittered)
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
func (q *Queue) shouldEscalate(job *store.DeploymentJob, now time.Time) bool {
	if job.Attempts >= escalateAfterAttempts {
		return true
	}
	if job.NotAfter == nil {
		return false
	}
	return job.NotAfter.Sub(now).Hours() < escalateWithinHours
}

// announceEscalation publishes a failing deployment once, when it first becomes
// somebody's problem.
//
// Once, not per attempt, for the reason the renewal queue gives: a job retrying
// every few minutes for a fortnight would put thousands of messages into the
// channel that also carries CA expiry alerts, and a muted channel takes those
// with it.
//
// The message names the place, not just the certificate. "certificate X failed
// to deploy" sends somebody to the certificate, which is fine; "failed to reach
// the load balancer in Frankfurt" sends them where the problem is.
func (q *Queue) announceEscalation(ctx context.Context, job *store.DeploymentJob, cause error, now time.Time) {
	if q.broker == nil {
		return
	}

	payload := map[string]any{
		"certificate_id": job.CertificateID,
		"attempts":       job.Attempts,
		"job_id":         job.ID,
		"error":          cause.Error(),
	}

	// What is stuck behind this one, which is the part that changes what
	// somebody does about it. A single failing target is an errand; a failing
	// target holding back eleven others is the reason the other eleven are
	// still on a certificate that expires next week — and they are held back
	// deliberately, so the message has to say so or it reads as a second fault.
	if waiting := q.waitingBehind(ctx, job); waiting > 0 {
		payload["waiting_behind"] = waiting
	}

	// Looked up per escalation rather than denormalised onto the job. This
	// happens once per stuck deployment, and a job row carrying a copy of a
	// name somebody has since changed would report the old one.
	if cert, err := q.store.GetCertificate(ctx, job.CertificateID); err == nil {
		payload["common_name"] = cert.CommonName
		payload["days_remaining"] = cert.DaysRemaining
		if cert.NotAfter != nil {
			payload["not_after"] = cert.NotAfter.Format(time.RFC3339)
		}
	}
	if target, err := q.store.GetDeploymentTarget(ctx, job.TargetID); err == nil {
		payload["target"] = target.Name
		payload["target_type"] = target.TargetType
	}
	if job.NotAfter != nil {
		payload["runway_hours"] = int(job.NotAfter.Sub(now).Hours())
	}

	q.broker.Publish(events.Event{
		Topic:    events.TopicCertDeployFailed,
		Severity: events.SeverityCritical,
		EntityID: job.CertificateID,
		Payload:  payload,
	})
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// CompleteReported records the outcome of a job that was run somewhere else.
//
// The one job in this system that no worker here performs. An agent host is
// behind two firewalls with nothing able to reach inwards, so it claims the job
// over its own signed API and installs the certificate from a spec on the host
// — and then has to be able to say what happened.
//
// It goes through the same retry curve, the same escalation rule and the same
// attempt log as a deployment this process ran itself, deliberately. The pacing
// is the part most likely to be subtly wrong and least likely to be noticed,
// and a second copy of it written for the agent path would drift from this one
// within a release. What differs is one field: the attempt log names the host
// rather than a replica, because "every failure came from one machine" is the
// same question in both cases.
func (q *Queue) CompleteReported(ctx context.Context, job *store.DeploymentJob,
	worker string, startedAt time.Time, detail string, cause error) error {

	now := q.now()
	// Passed in rather than derived from this queue's own lease. A host claims
	// for much longer than a local worker does — it has files to write, a
	// configuration to check and a service to reload before it can say anything
	// — so working the start time back from `q.lease` put it in the future and
	// wrote a negative duration into the attempt log.
	started := startedAt
	if started.IsZero() || started.After(now) {
		started = now
	}
	attempt := store.DeploymentAttempt{
		Number: job.Attempts,
		// How long the machine took, which is the interesting number: a reload
		// that takes ninety seconds is a fact about that host worth having.
		StartedAt:  started,
		DurationMS: now.Sub(started).Milliseconds(),
		Worker:     worker,
		Detail:     detail,
	}

	status := store.DeploySucceeded
	escalate := false
	if cause != nil {
		attempt.Error = cause.Error()
		// Left PENDING rather than FAILED, exactly as a local failure is. A
		// certificate that has been renewed and not installed is on the same
		// clock as one that was never renewed, so there is no attempt count at
		// which giving up is the right answer.
		status = store.DeployPending
		escalate = q.shouldEscalate(job, now)
	}

	if err := q.store.CompleteDeploymentJob(ctx, job.ID, status, attempt, q.retryAt(job, now), escalate); err != nil {
		return err
	}
	if cause != nil {
		slog.Warn("a host reported that it could not install a certificate",
			"job", job.ID, "deployment", job.DeploymentID, "host", worker,
			"attempt", job.Attempts, "escalated", escalate, "error", cause)
		if escalate && job.EscalatedAt == nil {
			q.announceEscalation(ctx, job, cause, now)
		}
	}
	return nil
}

// waitingBehind counts the deployments this failure is holding still.
//
// The queue refuses to start a fresh job for a certificate while another job
// for it is failing, so one bad target stops the rollout rather than letting it
// march through the estate. That is the intended behaviour and it is invisible
// from the outside — a person looking at eleven PENDING jobs that never move
// would reasonably conclude the queue was broken.
func (q *Queue) waitingBehind(ctx context.Context, job *store.DeploymentJob) int {
	jobs, _, err := q.store.ListDeploymentJobs(ctx, store.DeploymentJobFilter{
		CertificateID:   job.CertificateID,
		OutstandingOnly: true,
		Limit:           200,
	})
	if err != nil {
		return 0
	}
	waiting := 0
	for _, other := range jobs {
		// The same rule the claim query uses: a job that has not itself failed
		// is the one being held. Counting by attempts instead would include the
		// other failures, which are not waiting on this — they are failing on
		// their own account and have their own alert.
		if other.ID != job.ID && other.LastError == "" {
			waiting++
		}
	}
	return waiting
}
