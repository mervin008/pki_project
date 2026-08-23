package discovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

func TestValidateSchedule(t *testing.T) {
	cases := map[string]struct {
		schedule *store.DiscoverySchedule
		wantErr  string
	}{
		"a workable schedule": {
			&store.DiscoverySchedule{Name: "nightly", Targets: []string{"10.0.0.0/28"}, IntervalMinutes: 1440},
			"",
		},
		"no name": {
			&store.DiscoverySchedule{Targets: []string{"a.test"}, IntervalMinutes: 60},
			"needs a name",
		},
		"no targets": {
			&store.DiscoverySchedule{Name: "empty", IntervalMinutes: 60},
			"at least one target",
		},
		// A scan every minute against the same range is indistinguishable from
		// a denial of service aimed at your own estate.
		"too frequent": {
			&store.DiscoverySchedule{Name: "hammer", Targets: []string{"a.test"}, IntervalMinutes: 1},
			"shortest interval",
		},
		// Validated where it is entered, not on the night it matters.
		"targets that do not parse": {
			&store.DiscoverySchedule{Name: "typo", Targets: []string{"https://a.test"}, IntervalMinutes: 60},
			"looks like a URL",
		},
		"a range past the expansion limit": {
			&store.DiscoverySchedule{Name: "huge", Targets: []string{"10.0.0.0/8"}, IntervalMinutes: 1440},
			"past the",
		},
		// A scan that cannot finish before the next one starts would overlap
		// itself indefinitely. A /20 is 4094 endpoints; at twelve at a time and
		// six seconds each that is over half an hour in the worst case.
		"more endpoints than the interval allows": {
			&store.DiscoverySchedule{Name: "overlapping", Targets: []string{"10.0.0.0/20"}, IntervalMinutes: 15},
			"would overlap",
		},
		// The same range with room to finish is fine.
		"a wide range with a long enough interval": {
			&store.DiscoverySchedule{Name: "roomy", Targets: []string{"10.0.0.0/20"}, IntervalMinutes: 1440},
			"",
		},
	}

	for name, tc := range cases {
		err := ValidateSchedule(tc.schedule)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s: accepted, want an error mentioning %q", name, tc.wantErr)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s: error = %q, want it to mention %q", name, err, tc.wantErr)
		}
	}
}

// A schedule that has never run is due immediately: someone who has just
// written one wants to know it works, not to find out tomorrow.
func TestANewScheduleRunsStraightAway(t *testing.T) {
	st := newEmptyStore()
	ca := newTestCA(t, "Test CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	schedule := &store.DiscoverySchedule{
		Name:            "nightly",
		Targets:         []string{srv.target.String()},
		IntervalMinutes: 1440,
		IsEnabled:       true,
	}
	if err := st.CreateDiscoverySchedule(context.Background(), schedule); err != nil {
		t.Fatalf("CreateDiscoverySchedule: %v", err)
	}

	scheduler := NewScheduler(st, newTestScanner(st))
	scheduler.RunDue(context.Background())

	waitFor(t, 10*time.Second, func() bool {
		scans, _, _ := st.ListDiscoveryScans(context.Background(), 10, 0)
		return len(scans) == 1 && scans[0].Status == store.ScanCompleted
	}, "the scheduled scan to run")

	stored, err := st.GetDiscoverySchedule(context.Background(), schedule.ID)
	if err != nil {
		t.Fatalf("GetDiscoverySchedule: %v", err)
	}
	if stored.LastRunAt == nil {
		t.Error("the schedule does not record that it ran")
	}
	if stored.NextRunAt == nil {
		t.Fatal("the schedule has no next run, so it will fire again on the next tick")
	}
	if stored.LastScanID == nil {
		t.Error("the schedule does not point at the scan it produced")
	}
	if stored.LastError != "" {
		t.Errorf("last_error = %q on a successful run", stored.LastError)
	}

	// And it does not run again immediately.
	scheduler.RunDue(context.Background())
	scans, _, _ := st.ListDiscoveryScans(context.Background(), 10, 0)
	if len(scans) != 1 {
		t.Errorf("%d scans after a second tick, want 1 — the schedule was not moved on", len(scans))
	}
}

func TestADisabledScheduleNeverRuns(t *testing.T) {
	st := newEmptyStore()
	if err := st.CreateDiscoverySchedule(context.Background(), &store.DiscoverySchedule{
		Name: "off", Targets: []string{"127.0.0.1:9"}, IntervalMinutes: 60, IsEnabled: false,
	}); err != nil {
		t.Fatalf("CreateDiscoverySchedule: %v", err)
	}

	NewScheduler(st, newTestScanner(st)).RunDue(context.Background())

	scans, _, _ := st.ListDiscoveryScans(context.Background(), 10, 0)
	if len(scans) != 0 {
		t.Errorf("a disabled schedule ran %d scan(s)", len(scans))
	}
}

// A schedule whose targets stopped expanding must advance anyway, and must say
// why it did nothing.
//
// A schedule that only advanced on success would retry a permanently broken
// target every tick — one bad entry turning into a scan running continuously
// against somebody else's network. And a schedule that fails every night
// without recording it is worse than no schedule: it is the appearance of
// coverage.
func TestABrokenScheduleAdvancesAndRecordsWhy(t *testing.T) {
	st := newEmptyStore()
	schedule := &store.DiscoverySchedule{
		Name: "broken", Targets: []string{"10.0.0.0/8"}, IntervalMinutes: 60, IsEnabled: true,
	}
	if err := st.CreateDiscoverySchedule(context.Background(), schedule); err != nil {
		t.Fatalf("CreateDiscoverySchedule: %v", err)
	}

	NewScheduler(st, newTestScanner(st)).RunDue(context.Background())

	stored, err := st.GetDiscoverySchedule(context.Background(), schedule.ID)
	if err != nil {
		t.Fatalf("GetDiscoverySchedule: %v", err)
	}
	if stored.NextRunAt == nil {
		t.Fatal("a failed run left the schedule due, so it will retry every tick forever")
	}
	if stored.LastError == "" {
		t.Error("the schedule does not say why the run did not happen")
	}
	if !strings.Contains(stored.LastError, "16777216") {
		t.Errorf("last_error = %q; it should name the actual problem", stored.LastError)
	}

	scans, _, _ := st.ListDiscoveryScans(context.Background(), 10, 0)
	if len(scans) != 0 {
		t.Errorf("a schedule that could not expand still started %d scan(s)", len(scans))
	}
}

// The next run is computed from when the run started, not when it finished, so
// a long scan does not push its own schedule later every time it runs.
func TestTheNextRunIsMeasuredFromTheStart(t *testing.T) {
	st := newEmptyStore()
	schedule := &store.DiscoverySchedule{
		Name: "hourly", Targets: []string{"127.0.0.1:9"}, IntervalMinutes: 60, IsEnabled: true,
	}
	if err := st.CreateDiscoverySchedule(context.Background(), schedule); err != nil {
		t.Fatalf("CreateDiscoverySchedule: %v", err)
	}

	fixed := time.Date(2026, 8, 18, 2, 0, 0, 0, time.UTC)
	scheduler := NewScheduler(st, newTestScanner(st))
	scheduler.now = func() time.Time { return fixed }
	scheduler.RunDue(context.Background())

	stored, err := st.GetDiscoverySchedule(context.Background(), schedule.ID)
	if err != nil {
		t.Fatalf("GetDiscoverySchedule: %v", err)
	}
	want := fixed.Add(time.Hour)
	if stored.NextRunAt == nil || !stored.NextRunAt.Equal(want) {
		t.Errorf("next run = %v, want %v", stored.NextRunAt, want)
	}
}

// Stop must be safe twice, and safe on one that never started — the idiom the
// original renewal scheduler got wrong by calling close() on a bare channel.
func TestSchedulerLifecycleIsSafe(t *testing.T) {
	scheduler := NewScheduler(newEmptyStore(), newTestScanner(newEmptyStore()))
	scheduler.Stop()
	scheduler.Stop()

	running := NewScheduler(newEmptyStore(), newTestScanner(newEmptyStore()))
	running.tick = 10 * time.Millisecond
	running.Start()
	running.Start() // idempotent
	time.Sleep(30 * time.Millisecond)
	running.Stop()
	running.Stop()
}
