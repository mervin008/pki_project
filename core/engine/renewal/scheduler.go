package renewal

import (
	"context"
	"log/slog"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// Scheduler runs periodically to scan for certificates needing renewal.
type Scheduler struct {
	store           store.Store
	executor        *Executor
	defaultLeadDays int
	stopCh          chan struct{}
}

// NewScheduler creates a new renewal scheduler.
func NewScheduler(s store.Store, e *Executor, defaultLeadDays int) *Scheduler {
	if defaultLeadDays <= 0 {
		defaultLeadDays = 30
	}
	return &Scheduler{
		store:           s,
		executor:        e,
		defaultLeadDays: defaultLeadDays,
		stopCh:          make(chan struct{}),
	}
}

// Start begins periodic renewal scanning at the specified interval.
func (s *Scheduler) Start(interval time.Duration) {
	slog.Info("starting certificate renewal scheduler", "interval", interval, "default_lead_days", s.defaultLeadDays)

	ticker := time.NewTicker(interval)
	go func() {
		// Run once on startup
		s.RunScan(context.Background())

		for {
			select {
			case <-ticker.C:
				s.RunScan(context.Background())
			case <-s.stopCh:
				ticker.Stop()
				return
			}
		}
	}()
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	close(s.stopCh)
}

// RunScan checks for certificates due for renewal and executes them.
func (s *Scheduler) RunScan(ctx context.Context) {
	certs, err := s.store.GetCertificatesDueForRenewal(ctx, s.defaultLeadDays)
	if err != nil {
		slog.Error("renewal scan failed to query certificates", "error", err)
		return
	}

	if len(certs) == 0 {
		slog.Debug("renewal scan complete: no certificates due for renewal")
		return
	}

	slog.Info("found certificates due for renewal", "count", len(certs))

	for _, cert := range certs {
		slog.Info("auto-renewing certificate",
			"cert_id", cert.ID,
			"common_name", cert.CommonName,
			"days_remaining", cert.DaysRemaining,
		)

		if _, err := s.executor.RenewCertificate(ctx, cert.ID); err != nil {
			slog.Error("auto-renewal failed for certificate",
				"cert_id", cert.ID,
				"common_name", cert.CommonName,
				"error", err,
			)
		}
	}
}
