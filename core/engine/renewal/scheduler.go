package renewal

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// Scheduler finds certificates that are due and puts them on the queue.
//
// It no longer renews anything itself. The distinction matters more than it
// sounds: a sweep that renewed inline held every certificate's fate in one
// goroutine, so a core that restarted mid-sweep left no record that an attempt
// had been made, and a renewal that had been failing for six days looked
// exactly like one that had never been due.
//
// Safe to run on every replica. Two schedulers enqueueing the same renewal in
// the same second collide on a partial unique index and the second is a no-op,
// which is why there is no leader here to fail over.
type Scheduler struct {
	store           store.Store
	defaultLeadDays int
	now             func() time.Time

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// NewScheduler creates a scheduler.
func NewScheduler(s store.Store, defaultLeadDays int) *Scheduler {
	if defaultLeadDays <= 0 {
		defaultLeadDays = 30
	}
	return &Scheduler{
		store:           s,
		defaultLeadDays: defaultLeadDays,
		now:             time.Now,
		stopCh:          make(chan struct{}),
	}
}

// Start begins the sweep.
func (s *Scheduler) Start(interval time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()

	slog.Info("renewal scheduler started", "interval", interval, "default_lead_days", s.defaultLeadDays)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		s.RunScan(context.Background())
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.RunScan(context.Background())
			}
		}
	}()
}

// Stop halts the sweep. Safe to call twice, and on one that never started —
// the previous implementation's bare close panicked on the second call, so a
// double shutdown crashed the process it was trying to end cleanly.
func (s *Scheduler) Stop() {
	if s == nil {
		return
	}
	s.stopped.Do(func() { close(s.stopCh) })
	s.wg.Wait()
}

// RunScan enqueues every certificate that is due. Exported so a test can drive
// it without waiting on a ticker.
func (s *Scheduler) RunScan(ctx context.Context) {
	certs, err := s.store.GetCertificatesDueForRenewal(ctx, s.defaultLeadDays)
	if err != nil {
		slog.Error("renewal sweep could not read the certificates due; nothing is being renewed", "error", err)
		return
	}
	if len(certs) == 0 {
		slog.Debug("renewal sweep complete: nothing due")
		return
	}

	enqueued := 0
	for _, cert := range certs {
		created, err := s.Enqueue(ctx, cert, store.RenewalReasonScheduled, nil, nil)
		if err != nil {
			slog.Error("could not enqueue a renewal",
				"certificate", cert.ID, "common_name", cert.CommonName, "error", err)
			continue
		}
		if created {
			enqueued++
		}
	}

	// Both numbers, because they mean different things. Everything already
	// queued is the normal steady state on a busy estate; it is not the same as
	// a sweep that found nothing to do.
	slog.Info("renewal sweep complete", "due", len(certs), "enqueued", enqueued,
		"already_queued", len(certs)-enqueued)
}

// Enqueue puts one certificate on the queue.
//
// Returns false when a job for it is already outstanding, which is not an
// error: it is the ordinary answer when the previous attempt has not finished,
// or when another replica got there first.
func (s *Scheduler) Enqueue(ctx context.Context, cert *store.Certificate, reason string,
	actorID, actorEmail *string) (bool, error) {
	job := &store.RenewalJob{
		CertificateID: cert.ID,
		Reason:        reason,
		Status:        store.RenewalPending,
		RunAfter:      s.now(),
		NotAfter:      cert.NotAfter,
		// What the certificate is now, so a retry after a crash can tell
		// whether the renewal already happened rather than issuing a second
		// one.
		FingerprintAtEnqueue: cert.FingerprintSHA256,
		TriggeredBy:          actorID,
		ActorEmail:           actorEmail,
	}
	return s.store.EnqueueRenewal(ctx, job)
}
