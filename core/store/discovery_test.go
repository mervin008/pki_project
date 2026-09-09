package store

import (
	"context"
	"testing"
	"time"
)

func TestDiscoveryScanLifecycle(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		started := time.Now()
		scan := &DiscoveryScan{
			ScanType:  ScanTypeNetwork,
			Targets:   []string{"a.test:443", "b.test:443"},
			Status:    ScanRunning,
			StartedAt: &started,
		}
		if err := st.CreateDiscoveryScan(ctx, scan); err != nil {
			t.Fatalf("CreateDiscoveryScan: %v", err)
		}
		if scan.ID == "" {
			t.Fatal("the store must assign an id")
		}

		scan.Status = ScanCompleted
		scan.ResultsCount = 2
		scan.UnmanagedCount = 1
		scan.ManagedCount = 1
		completed := time.Now()
		scan.CompletedAt = &completed
		if err := st.UpdateDiscoveryScan(ctx, scan); err != nil {
			t.Fatalf("UpdateDiscoveryScan: %v", err)
		}

		got, err := st.GetDiscoveryScan(ctx, scan.ID)
		if err != nil {
			t.Fatalf("GetDiscoveryScan: %v", err)
		}
		if got.Status != ScanCompleted || got.UnmanagedCount != 1 {
			t.Errorf("stored scan = %+v, want the updated counts", got)
		}
		// A caller must not be able to back-date the record of a scan: it is
		// evidence of an outbound action, not a document.
		if !got.CreatedAt.Equal(scan.CreatedAt) {
			t.Error("created_at changed on update")
		}

		if _, err := st.GetDiscoveryScan(ctx, "no-such-scan"); err == nil {
			t.Error("an unknown scan id must be an error, not an empty run")
		}
		if err := st.UpdateDiscoveryScan(ctx, &DiscoveryScan{ID: "no-such-scan"}); err == nil {
			t.Error("updating an unknown scan must fail rather than silently do nothing")
		}
	})
}

func TestDiscoveryScansListNewestFirst(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		for _, name := range []string{"first", "second", "third"} {
			if err := st.CreateDiscoveryScan(ctx, &DiscoveryScan{
				ScanType: ScanTypeNetwork, Targets: []string{name},
			}); err != nil {
				t.Fatalf("CreateDiscoveryScan: %v", err)
			}
		}

		scans, total, err := st.ListDiscoveryScans(ctx, 2, 0)
		if err != nil {
			t.Fatalf("ListDiscoveryScans: %v", err)
		}
		if total != 3 {
			t.Errorf("total = %d, want 3", total)
		}
		if len(scans) != 2 {
			t.Fatalf("got %d scans, want the 2 asked for", len(scans))
		}
		// Scan history is only ever read newest first: the question is "what did we
		// find just now", never "what did we find when we started".
		if scans[0].Targets[0] != "third" || scans[1].Targets[0] != "second" {
			t.Errorf("order = %v, %v; want third, second", scans[0].Targets, scans[1].Targets)
		}
	})
}

func TestDiscoveryResultFiltering(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		scan := &DiscoveryScan{ScanType: ScanTypeNetwork}
		if err := st.CreateDiscoveryScan(ctx, scan); err != nil {
			t.Fatalf("CreateDiscoveryScan: %v", err)
		}

		results := []*DiscoveryResult{
			{ScanID: scan.ID, Host: "unmanaged.test", Port: 443, Reachable: true,
				ManagementState: DiscoveryUnmanaged, TrustState: TrustUntrusted},
			{ScanID: scan.ID, Host: "managed.test", Port: 443, Reachable: true,
				ManagementState: DiscoveryManaged, TrustState: TrustInternal},
			{ScanID: scan.ID, Host: "dead.test", Port: 443,
				ManagementState: DiscoveryUnreachable, TrustState: TrustUnknown},
		}
		if err := st.CreateDiscoveryResults(ctx, results); err != nil {
			t.Fatalf("CreateDiscoveryResults: %v", err)
		}
		for _, r := range results {
			if r.ID == "" {
				t.Fatal("every result must be assigned an id")
			}
		}

		cases := map[string]struct {
			filter DiscoveryResultFilter
			want   int
		}{
			"everything":  {DiscoveryResultFilter{ScanID: scan.ID}, 3},
			"unmanaged":   {DiscoveryResultFilter{ManagementState: DiscoveryUnmanaged}, 1},
			"unreachable": {DiscoveryResultFilter{ManagementState: DiscoveryUnreachable}, 1},
			"internal":    {DiscoveryResultFilter{TrustState: TrustInternal}, 1},
			"by host":     {DiscoveryResultFilter{Host: "dead.test"}, 1},
			"other scan":  {DiscoveryResultFilter{ScanID: "00000000-0000-4000-8000-000000000000"}, 0},
		}
		for name, tc := range cases {
			got, total, err := st.ListDiscoveryResults(ctx, tc.filter)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(got) != tc.want || int(total) != tc.want {
				t.Errorf("%s: got %d results (total %d), want %d", name, len(got), total, tc.want)
			}
		}
	})
}

// Adopting a result settles the question it was raised about. A list that still
// called it unmanaged would keep asking for work already done.
func TestImportedResultStopsBeingUnmanaged(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		scan := &DiscoveryScan{ScanType: ScanTypeNetwork}
		_ = st.CreateDiscoveryScan(ctx, scan)
		result := &DiscoveryResult{
			ScanID: scan.ID, Host: "adopted.test", Port: 443, Reachable: true,
			ManagementState: DiscoveryUnmanaged, TrustState: TrustPublic,
		}
		if err := st.CreateDiscoveryResults(ctx, []*DiscoveryResult{result}); err != nil {
			t.Fatalf("CreateDiscoveryResults: %v", err)
		}

		// A real certificate, not an invented id: matched_certificate_id is a
		// uuid column, and "cert-123" only ever worked because these tests had
		// never met a database.
		adopted := sampleCertificate("discovery-adopted")
		if err := st.CreateCertificate(ctx, adopted); err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		if err := st.MarkDiscoveryResultImported(ctx, result.ID, adopted.ID); err != nil {
			t.Fatalf("MarkDiscoveryResultImported: %v", err)
		}

		got, err := st.GetDiscoveryResult(ctx, result.ID)
		if err != nil {
			t.Fatalf("GetDiscoveryResult: %v", err)
		}
		if !got.IsImported {
			t.Error("the result is not marked imported")
		}
		if got.ManagementState != DiscoveryManaged {
			t.Errorf("management state = %q, want MANAGED", got.ManagementState)
		}
		if got.ImportedCertificateID == nil || *got.ImportedCertificateID != adopted.ID {
			t.Errorf("imported certificate = %v, want the adopted certificate", got.ImportedCertificateID)
		}

		unimported, _, err := st.ListDiscoveryResults(ctx, DiscoveryResultFilter{UnimportedOnly: true})
		if err != nil {
			t.Fatalf("ListDiscoveryResults: %v", err)
		}
		if len(unimported) != 0 {
			t.Errorf("an adopted result still appears as outstanding: %+v", unimported)
		}

		if err := st.MarkDiscoveryResultImported(ctx, "no-such-result", "cert-123"); err == nil {
			t.Error("marking an unknown result must fail")
		}
	})
}

// Reads must hand back copies. The scanner writes results while a dashboard
// reads them, and sharing pointers between those two makes a data race out of
// an ordinary page refresh — the defect the audit log shipped with.
func TestDiscoveryReadsReturnCopies(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		scan := &DiscoveryScan{ScanType: ScanTypeNetwork, Targets: []string{"a.test"}}
		_ = st.CreateDiscoveryScan(ctx, scan)
		_ = st.CreateDiscoveryResults(ctx, []*DiscoveryResult{
			{ScanID: scan.ID, Host: "a.test", Port: 443, ManagementState: DiscoveryUnmanaged},
		})

		got, _ := st.GetDiscoveryScan(ctx, scan.ID)
		got.Status = "TAMPERED"
		again, _ := st.GetDiscoveryScan(ctx, scan.ID)
		if again.Status == "TAMPERED" {
			t.Error("a caller mutated the stored scan through the record it was handed")
		}

		results, _, _ := st.ListDiscoveryResults(ctx, DiscoveryResultFilter{ScanID: scan.ID})
		results[0].Host = "tampered.test"
		fresh, _, _ := st.ListDiscoveryResults(ctx, DiscoveryResultFilter{ScanID: scan.ID})
		if fresh[0].Host == "tampered.test" {
			t.Error("a caller mutated a stored result through the slice it was handed")
		}
	})
}

func TestWorstSeverityRanksFindings(t *testing.T) {
	r := &DiscoveryResult{Findings: []Finding{
		{Code: "a", Severity: "INFO"},
		{Code: "b", Severity: "CRITICAL"},
		{Code: "c", Severity: "WARNING"},
	}}
	if got := r.WorstSeverity(); got != "CRITICAL" {
		t.Errorf("WorstSeverity = %q, want CRITICAL", got)
	}
	if got := (&DiscoveryResult{}).WorstSeverity(); got != "" {
		t.Errorf("WorstSeverity with no findings = %q, want empty", got)
	}
}

// Stale is what makes a monitor's silence readable.
//
// Without it, a monitor that has been unable to reach the transparency index
// for a week looks exactly like one that has found nothing for a week — and one
// of those means nobody is being told about certificates issued in their name.
func TestCTMonitorStaleness(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	hourly := 60

	fresh := &CTMonitor{
		IsEnabled: true, CheckIntervalMinutes: hourly,
		LastSuccessAt: timePtr(now.Add(-30 * time.Minute)),
	}
	if fresh.Stale(now) {
		t.Error("a monitor that answered half an hour ago reads as stale")
	}

	lapsed := &CTMonitor{
		IsEnabled: true, CheckIntervalMinutes: hourly,
		LastSuccessAt: timePtr(now.Add(-5 * time.Hour)),
	}
	if !lapsed.Stale(now) {
		t.Error("a monitor that has not answered in five hourly windows reads as healthy")
	}

	// A brand new monitor is not stale — it has not had a chance yet, and
	// flagging it would train people to ignore the flag.
	brandNew := &CTMonitor{IsEnabled: true, CheckIntervalMinutes: hourly, CreatedAt: now.Add(-5 * time.Minute)}
	if brandNew.Stale(now) {
		t.Error("a monitor created five minutes ago reads as stale")
	}

	// One created days ago that has never answered is exactly what this is for.
	neglected := &CTMonitor{IsEnabled: true, CheckIntervalMinutes: hourly, CreatedAt: now.Add(-72 * time.Hour)}
	if !neglected.Stale(now) {
		t.Error("a monitor that has never once answered reads as healthy")
	}

	// A disabled monitor is not stale: nobody expects it to be running.
	off := &CTMonitor{IsEnabled: false, CheckIntervalMinutes: hourly, CreatedAt: now.Add(-72 * time.Hour)}
	if off.Stale(now) {
		t.Error("a disabled monitor reads as stale")
	}
}

func timePtr(t time.Time) *time.Time { return &t }
