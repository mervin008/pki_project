package store

import (
	"context"
	"testing"
	"time"
)

// Certificate Transparency had no store test file at all, so none of the
// defect classes had ever been checked against it. Everything here runs against
// both implementations.

func aMonitor(t *testing.T, s Store, domain string) *CTMonitor {
	t.Helper()
	m := &CTMonitor{
		Domain:               domain,
		IsEnabled:            true,
		CheckIntervalMinutes: 360,
		IncludeSubdomains:    true,
	}
	if err := s.CreateCTMonitor(context.Background(), m); err != nil {
		t.Fatalf("CreateCTMonitor: %v", err)
	}
	return m
}

func TestCTMonitorRoundTrips(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		m := aMonitor(t, s, "example.test")

		got, err := s.GetCTMonitor(ctx, m.ID)
		if err != nil {
			t.Fatalf("GetCTMonitor: %v", err)
		}
		if got.Domain != "example.test" || !got.IsEnabled || got.CheckIntervalMinutes != 360 {
			t.Errorf("monitor read back as %+v", got)
		}
		if !got.IncludeSubdomains {
			t.Error("include_subdomains was dropped; the subdomain nobody registered " +
				"is the one worth finding")
		}

		got.IsEnabled = false
		got.CheckIntervalMinutes = 60
		if err := s.UpdateCTMonitor(ctx, got); err != nil {
			t.Fatalf("UpdateCTMonitor: %v", err)
		}
		again, err := s.GetCTMonitor(ctx, m.ID)
		if err != nil {
			t.Fatal(err)
		}
		if again.IsEnabled || again.CheckIntervalMinutes != 60 {
			t.Errorf("the edit did not survive: %+v", again)
		}

		if err := s.DeleteCTMonitor(ctx, m.ID); err != nil {
			t.Fatalf("DeleteCTMonitor: %v", err)
		}
		if _, err := s.GetCTMonitor(ctx, m.ID); err == nil {
			t.Error("a deleted monitor is still readable")
		}
	})
}

// Class A. Every management state the CT engine can write must be one the
// schema accepts — UpsertCloudCertificates had exactly this defect, writing an
// empty string over a column default and being refused by the CHECK.
func TestEveryCTManagementStateIsAccepted(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		m := aMonitor(t, s, "states.test")

		for i, state := range []string{DiscoveryManaged, DiscoveryUnmanaged, ""} {
			entry := int64(1000 + i)
			_, err := s.RecordCTCertificates(ctx, []*CTCertificate{{
				MonitorID: m.ID, EntryID: &entry, CommonName: "a.states.test",
				ManagementState: state, SANs: []string{"a.states.test"},
			}})
			if err != nil {
				t.Errorf("management state %q is written by this codebase and refused by the store: %v",
					state, err)
			}
		}
	})
}

// The entry id is what makes a re-check idempotent. A log is re-read from a
// position, so the same entries arrive again every time — recording them twice
// would turn one finding into one per check.
func TestRecordingTheSameCTEntryTwiceAddsItOnce(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		m := aMonitor(t, s, "idempotent.test")
		entry := int64(42)

		first, err := s.RecordCTCertificates(ctx, []*CTCertificate{{
			MonitorID: m.ID, EntryID: &entry, CommonName: "shop.idempotent.test",
			ManagementState: DiscoveryUnmanaged, SANs: []string{"shop.idempotent.test"},
		}})
		if err != nil {
			t.Fatalf("RecordCTCertificates: %v", err)
		}
		if len(first) != 1 {
			t.Fatalf("the first sighting added %d, want 1", len(first))
		}

		again, err := s.RecordCTCertificates(ctx, []*CTCertificate{{
			MonitorID: m.ID, EntryID: &entry, CommonName: "shop.idempotent.test",
			ManagementState: DiscoveryUnmanaged, SANs: []string{"shop.idempotent.test"},
		}})
		if err != nil {
			t.Fatalf("RecordCTCertificates: %v", err)
		}
		if len(again) != 0 {
			t.Errorf("re-reading the log reported %d new certificates; an alert built from "+
				"'everything the check saw' would fire every entry on every sweep", len(again))
		}

		all, total, err := s.ListCTCertificates(ctx, CTCertificateFilter{MonitorID: m.ID})
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 1 || total != 1 {
			t.Errorf("stored %d (total %d), want 1", len(all), total)
		}
	})
}

// Class B. Every field the engine sets must survive the round trip, and a slice
// and a pointer are where a writer quietly drops one.
func TestACTCertificateRoundTripsEveryField(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		m := aMonitor(t, s, "fields.test")

		entry := int64(7)
		loggedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		notBefore := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
		notAfter := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)

		if _, err := s.RecordCTCertificates(ctx, []*CTCertificate{{
			MonitorID: m.ID, EntryID: &entry, LoggedAt: &loggedAt,
			SerialNumber: "0a1b2c", IssuerDN: "CN=Some Public CA", CommonName: "shop.fields.test",
			SANs:      []string{"shop.fields.test", "www.fields.test"},
			NotBefore: &notBefore, NotAfter: &notAfter,
			ManagementState: DiscoveryUnmanaged, IsPrecertificate: true,
		}}); err != nil {
			t.Fatalf("RecordCTCertificates: %v", err)
		}

		got, _, err := s.ListCTCertificates(ctx, CTCertificateFilter{MonitorID: m.ID})
		if err != nil || len(got) != 1 {
			t.Fatalf("ListCTCertificates: %v (%d rows)", err, len(got))
		}
		c := got[0]

		if c.SerialNumber != "0a1b2c" || c.IssuerDN != "CN=Some Public CA" {
			t.Errorf("serial/issuer read back as %q / %q", c.SerialNumber, c.IssuerDN)
		}
		if len(c.SANs) != 2 {
			t.Errorf("SANs read back as %v — a jsonb column a writer dropped", c.SANs)
		}
		if !c.IsPrecertificate {
			t.Error("is_precertificate was dropped; a precertificate and its final entry " +
				"would then be counted as two findings")
		}
		if c.EntryID == nil || *c.EntryID != entry {
			t.Errorf("entry id read back as %v", c.EntryID)
		}
		if c.NotAfter == nil || !c.NotAfter.Equal(notAfter) {
			t.Errorf("not_after read back as %v, want %v", c.NotAfter, notAfter)
		}
	})
}

// Class D. The due query does interval arithmetic on a bound parameter, which
// is the shape that has shipped broken twice in this codebase — and it is not
// expressible in Go, so only a query that actually runs finds it.
func TestTheCTDueQueryRuns(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()

		stale := aMonitor(t, s, "stale.test")
		if err := s.MarkCTMonitorChecked(ctx, stale.ID, now.Add(-8*time.Hour),
			now.Add(-2*time.Hour), true, nil, 0, 0, ""); err != nil {
			t.Fatalf("MarkCTMonitorChecked: %v", err)
		}
		fresh := aMonitor(t, s, "fresh.test")
		if err := s.MarkCTMonitorChecked(ctx, fresh.ID, now.Add(-time.Minute),
			now.Add(time.Hour), true, nil, 0, 0, ""); err != nil {
			t.Fatalf("MarkCTMonitorChecked: %v", err)
		}

		due, err := s.GetDueCTMonitors(ctx, now)
		if err != nil {
			t.Fatalf("GetDueCTMonitors did not run: %v", err)
		}
		ids := map[string]bool{}
		for _, m := range due {
			ids[m.ID] = true
		}
		if !ids[stale.ID] {
			t.Error("a monitor whose next check has passed is not due")
		}
		if ids[fresh.ID] {
			t.Error("a monitor checked a minute ago is due again")
		}
	})
}

// A disabled monitor must not be checked. Switching one off and finding it
// still reading a log is the kind of thing that gets noticed on a bill.
func TestADisabledCTMonitorIsNotDue(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()

		m := aMonitor(t, s, "disabled.test")
		if err := s.MarkCTMonitorChecked(ctx, m.ID, now.Add(-8*time.Hour),
			now.Add(-2*time.Hour), true, nil, 0, 0, ""); err != nil {
			t.Fatal(err)
		}
		m.IsEnabled = false
		if err := s.UpdateCTMonitor(ctx, m); err != nil {
			t.Fatal(err)
		}

		due, err := s.GetDueCTMonitors(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range due {
			if d.ID == m.ID {
				t.Error("a disabled monitor is still due for a check")
			}
		}
	})
}

// The error from a failed check has to be recorded, or a monitor that has been
// failing for a week looks identical to one that is working.
func TestACTCheckErrorIsRecorded(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		m := aMonitor(t, s, "failing.test")

		if err := s.MarkCTMonitorChecked(ctx, m.ID, now, now.Add(time.Hour), false, nil, 0, 0,
			"the log returned HTTP 503"); err != nil {
			t.Fatalf("MarkCTMonitorChecked: %v", err)
		}
		got, err := s.GetCTMonitor(ctx, m.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.LastError == "" {
			t.Error("the reason a check failed was dropped; a monitor failing for a week " +
				"then looks exactly like one that is working")
		}
	})
}
