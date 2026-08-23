package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

const (
	// tickInterval is how often the scheduler looks for due work. Schedules are
	// measured in hours and days, so a minute's granularity is ample and keeps
	// the query — one indexed lookup — negligible.
	tickInterval = 1 * time.Minute
	// MinScheduleMinutes is the shortest interval a schedule may have.
	//
	// Not a performance limit. A scan every minute against the same range is
	// indistinguishable from a denial of service aimed at your own estate, and
	// it would be configured by accident long before it was configured on
	// purpose.
	MinScheduleMinutes = 15
)

// Scheduler runs discovery scans on their own, without anyone remembering to.
//
// This is what turns discovery from a snapshot into monitoring. The finding it
// exists to produce — an endpoint serving a certificate nobody registered — is
// created continuously, by deployments nobody mentioned and appliances nobody
// asked about. A scan run once caught the ones that existed that morning.
//
// Follows CAMonitor's lifecycle idiom rather than the original Scheduler's:
// Stop is safe to call twice and safe on one that was never started.
type Scheduler struct {
	store   store.Store
	scanner *Scanner
	tick    time.Duration
	now     func() time.Time

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// NewScheduler creates a scheduler.
func NewScheduler(s store.Store, scanner *Scanner) *Scheduler {
	return &Scheduler{
		store:   s,
		scanner: scanner,
		tick:    tickInterval,
		now:     time.Now,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the loop.
func (s *Scheduler) Start() {
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

	s.wg.Add(1)
	go s.run()

	slog.Info("discovery scheduler started", "tick", s.tick)
}

// Stop ends the loop and waits for the current tick to finish. Safe to call
// more than once, and safe on a scheduler that was never started.
func (s *Scheduler) Stop() {
	if s == nil {
		return
	}
	s.stopped.Do(func() { close(s.stopCh) })
	s.wg.Wait()
}

func (s *Scheduler) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()

	// A first pass immediately, so a core that has been down through a
	// schedule's window catches up rather than waiting out a full interval.
	s.RunDue(context.Background())

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.RunDue(context.Background())
		}
	}
}

// RunDue starts every schedule that is due. Exported so a test can drive it
// without waiting on a ticker.
func (s *Scheduler) RunDue(ctx context.Context) {
	now := s.now()

	schedules, err := s.store.GetDueDiscoverySchedules(ctx, now)
	if err != nil {
		slog.Error("could not read discovery schedules; scheduled scans are not running", "error", err)
		return
	}

	for _, schedule := range schedules {
		s.trigger(ctx, schedule, now)
	}
}

// trigger starts one schedule's scan.
//
// The schedule is moved on *before* the scan starts, and moved on even when
// starting fails. A schedule that only advanced on success would retry a
// permanently broken target every tick, which turns one bad entry into a scan
// running continuously against somebody else's network.
func (s *Scheduler) trigger(ctx context.Context, schedule *store.DiscoverySchedule, now time.Time) {
	next := now.Add(time.Duration(schedule.IntervalMinutes) * time.Minute)

	scan, err := s.startScan(ctx, schedule)
	if err != nil {
		slog.Error("a scheduled discovery scan could not start",
			"schedule", schedule.Name, "error", err)
		// The error is recorded on the schedule rather than only logged. A
		// schedule that fails every night and is never read is worse than no
		// schedule: it is the appearance of coverage.
		if markErr := s.store.MarkDiscoveryScheduleRun(ctx, schedule.ID, now, next, nil, err.Error()); markErr != nil {
			slog.Error("could not record a failed scheduled scan", "schedule", schedule.Name, "error", markErr)
		}
		return
	}

	if err := s.store.MarkDiscoveryScheduleRun(ctx, schedule.ID, now, next, &scan.ID, ""); err != nil {
		// The scan is already running, so this is bookkeeping. Reported
		// loudly anyway: a schedule whose next run was not written will fire
		// again on the very next tick.
		slog.Error("a scheduled scan started but the schedule could not be updated; it may run again immediately",
			"schedule", schedule.Name, "scan_id", scan.ID, "error", err)
	}

	slog.Info("scheduled discovery scan started",
		"schedule", schedule.Name, "scan_id", scan.ID, "next_run", next)
}

func (s *Scheduler) startScan(ctx context.Context, schedule *store.DiscoverySchedule) (*store.DiscoveryScan, error) {
	targets, err := ExpandTargets(schedule.Targets, schedule.Ports, DefaultExpansionLimit)
	if err != nil {
		// Expansion fails at save time too, so reaching here means the limits
		// changed or the schedule predates a validation. Either way it must not
		// be scanned on a guess.
		return nil, fmt.Errorf("expanding the schedule's targets: %w", err)
	}

	actor := "schedule:" + schedule.Name
	return s.scanner.Start(ScanRequest{
		Targets: targets,
		Specs:   schedule.Targets,
		// Attributed to the schedule, not to whoever created it. The audit
		// question about an automated scan is "which schedule reached out",
		// and the person who wrote it may have left the company since.
		ActorEmail: &actor,
	})
}

// ValidateSchedule checks a schedule can actually run, before it is stored.
//
// Validated at save time rather than at run time for the same reason a
// notification channel is: a schedule that looks configured and silently never
// scans is worse than no schedule, and the night it matters is the wrong time
// to discover its targets do not parse.
func ValidateSchedule(schedule *store.DiscoverySchedule) error {
	if schedule.Name == "" {
		return fmt.Errorf("a schedule needs a name — it is what identifies it when a run fails")
	}
	if len(schedule.Targets) == 0 {
		return fmt.Errorf("a schedule needs at least one target")
	}
	if schedule.IntervalMinutes < MinScheduleMinutes {
		return fmt.Errorf("the shortest interval is %d minutes; %d would scan the same range continuously",
			MinScheduleMinutes, schedule.IntervalMinutes)
	}

	targets, err := ExpandTargets(schedule.Targets, schedule.Ports, DefaultExpansionLimit)
	if err != nil {
		return err
	}

	// A schedule whose scan cannot finish before the next one starts would
	// overlap itself indefinitely. Estimated from the slowest case — every
	// endpoint timing out — because that is what an unreachable range does.
	worstCase := time.Duration(len(targets)/defaultConcurrency+1) * defaultDialTimeout
	interval := time.Duration(schedule.IntervalMinutes) * time.Minute
	if worstCase > interval {
		return fmt.Errorf(
			"%d endpoints could take up to %s to scan, which is longer than the %s interval; the runs would overlap",
			len(targets), worstCase.Round(time.Minute), interval)
	}

	return nil
}
