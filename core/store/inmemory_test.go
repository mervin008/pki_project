package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// newEmptyStore builds a MemoryStore with no sample data, so a test can assert
// exact counts rather than counts relative to whatever NewMemoryStore seeds.
func newEmptyStore() *MemoryStore {
	return &MemoryStore{
		certificates:  make(map[string]*Certificate),
		caAuthorities: make(map[string]*CAAuthority),
		caAccounts:    make(map[string]*CAAccount),
		targets:       make(map[string]*DeploymentTarget),
		policies:      make(map[string]*Policy),
		displayTokens: make(map[string]*DisplayToken),
		notifChannels: make(map[string]*NotificationChannel),
	}
}

func mustCreateCA(t *testing.T, s *MemoryStore, name, status string, expiresIn time.Duration) *CAAuthority {
	t.Helper()
	ca := &CAAuthority{
		Name:           name,
		CAType:         "ISSUING",
		Status:         status,
		NotAfter:       time.Now().Add(expiresIn),
		DaysRemaining:  int(expiresIn.Hours() / 24),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\n" + name + "\n-----END CERTIFICATE-----",
	}
	if err := s.CreateCAAuthority(context.Background(), ca); err != nil {
		t.Fatalf("CreateCAAuthority(%s): %v", name, err)
	}
	return ca
}

// ── Audit log filtering ─────────────────────────────────
//
// The reason this step exists: a CA expiry alert shares a table with every
// certificate issued that day, and until now there was no way to ask for one
// without walking the other.

func TestAuditLogFilterByAction(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	for i := 0; i < 40; i++ {
		if err := s.CreateAuditLog(ctx, &AuditLog{Action: "cert.issued", EntityType: "certificate"}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}
	if err := s.CreateAuditLog(ctx, &AuditLog{Action: "ca.expiry_alert", EntityType: "ca_authority"}); err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}

	// The unfiltered default page is 20 entries, and the alert is the 41st
	// oldest — so before filtering existed, this is exactly the alert that fell
	// off the dashboard.
	logs, total, err := s.ListAuditLogs(ctx, AuditLogFilter{Actions: []string{"ca.expiry_alert"}})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("want exactly the one alert, got %d entries", len(logs))
	}
	if logs[0].Action != "ca.expiry_alert" {
		t.Errorf("want ca.expiry_alert, got %s", logs[0].Action)
	}
	// The total describes the filtered set. Reporting 41 here would tell a
	// client paging through alerts that there are forty more to come.
	if total != 1 {
		t.Errorf("total should count the filtered set, want 1, got %d", total)
	}
}

func TestAuditLogFilterAcceptsSeveralActions(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	for _, action := range []string{"cert.issued", "ca.expiry_alert", "ca.health_changed", "cert.deleted"} {
		if err := s.CreateAuditLog(ctx, &AuditLog{Action: action, EntityType: "x"}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}

	logs, total, err := s.ListAuditLogs(ctx, AuditLogFilter{
		Actions: []string{"ca.expiry_alert", "ca.health_changed"},
	})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 2 || total != 2 {
		t.Fatalf("want 2 entries and total 2, got %d and %d", len(logs), total)
	}
	for _, l := range logs {
		if l.Action != "ca.expiry_alert" && l.Action != "ca.health_changed" {
			t.Errorf("unexpected action in a filtered result: %s", l.Action)
		}
	}
}

func TestAuditLogFilterByEntityAndSince(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	caID := "ca-1"
	otherID := "ca-2"
	for _, id := range []string{caID, otherID, caID} {
		entity := id
		if err := s.CreateAuditLog(ctx, &AuditLog{
			Action: "ca.expiry_alert", EntityType: "ca_authority", EntityID: &entity,
		}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}

	logs, _, err := s.ListAuditLogs(ctx, AuditLogFilter{EntityType: "ca_authority", EntityID: caID})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("want the 2 entries for %s, got %d", caID, len(logs))
	}

	// Everything was written just now, so a lower bound in the future must
	// exclude all of it — proving Since is applied rather than ignored.
	logs, total, err := s.ListAuditLogs(ctx, AuditLogFilter{Since: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 0 || total != 0 {
		t.Errorf("a Since in the future should match nothing, got %d entries (total %d)", len(logs), total)
	}
}

func TestAuditLogPaginationDefaultsAndBounds(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	for i := 0; i < 120; i++ {
		if err := s.CreateAuditLog(ctx, &AuditLog{Action: "cert.issued", EntityType: "certificate"}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}

	// Zero limit means the shared default of 50, matching PostgresStore.
	logs, total, err := s.ListAuditLogs(ctx, AuditLogFilter{})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 50 || total != 120 {
		t.Fatalf("want 50 of 120, got %d of %d", len(logs), total)
	}

	// An offset past the end is an empty page, not an error and not a panic.
	logs, total, err = s.ListAuditLogs(ctx, AuditLogFilter{Limit: 10, Offset: 5000})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 0 || total != 120 {
		t.Errorf("want an empty page with total 120, got %d of %d", len(logs), total)
	}
}

// TestListAuditLogsDoesNotShareBackingMemory is the regression test for the
// bug this step was partly written to fix.
//
// The old implementation returned m.auditLogs[offset:end] — a window onto the
// live slice. A caller holding it read memory that CreateAuditLog would go on
// to write through. Under -race, with a concurrent writer, that is a reported
// data race; without the race detector it is a dashboard that occasionally
// shows one event's action against another's timestamp.
func TestListAuditLogsDoesNotShareBackingMemory(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	for i := 0; i < 10; i++ {
		if err := s.CreateAuditLog(ctx, &AuditLog{Action: fmt.Sprintf("action.%d", i), EntityType: "x"}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}

	logs, _, err := s.ListAuditLogs(ctx, AuditLogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = s.CreateAuditLog(ctx, &AuditLog{Action: "cert.issued", EntityType: "certificate"})
		}
	}()

	// Read every returned entry while the writer runs. This is what the SSE
	// snapshot path does.
	for i := 0; i < 200; i++ {
		for _, l := range logs {
			_ = l.Action + l.EntityType
		}
	}
	wg.Wait()

	// Mutating what a read returned must not reach the store.
	logs[0].Action = "tampered"
	fresh, _, err := s.ListAuditLogs(ctx, AuditLogFilter{Actions: []string{"tampered"}})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(fresh) != 0 {
		t.Error("a caller mutating a returned audit entry changed the stored record")
	}
}

// ── CA filtering ────────────────────────────────────────

func TestCAFilterByStatus(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	mustCreateCA(t, s, "healthy-ca", "HEALTHY", 800*24*time.Hour)
	mustCreateCA(t, s, "critical-ca", "CRITICAL", 10*24*time.Hour)

	cas, err := s.ListCAAuthorities(ctx, CAFilter{Status: "CRITICAL"})
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	if len(cas) != 1 || cas[0].Name != "critical-ca" {
		t.Fatalf("want just critical-ca, got %d results", len(cas))
	}
}

// TestCAFilterExpiringWindowUsesNotAfter pins the decision that the window is
// evaluated against not_after rather than the cached days_remaining column.
//
// days_remaining is written by the health sweep and is stale by however long it
// has been since the last one. Here it claims 900 days while the certificate
// actually expires in 5 — the shape of a CA whose sweep has not run since it
// was registered, which is precisely when a dashboard must not be reassuring.
func TestCAFilterExpiringWindowUsesNotAfter(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	stale := &CAAuthority{
		Name:          "stale-counter-ca",
		Status:        "HEALTHY",
		NotAfter:      time.Now().Add(5 * 24 * time.Hour),
		DaysRemaining: 900,
	}
	if err := s.CreateCAAuthority(ctx, stale); err != nil {
		t.Fatalf("CreateCAAuthority: %v", err)
	}
	mustCreateCA(t, s, "genuinely-fine-ca", "HEALTHY", 900*24*time.Hour)

	cas, err := s.ListCAAuthorities(ctx, CAFilter{ExpiringWithinDays: 30})
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	if len(cas) != 1 || cas[0].Name != "stale-counter-ca" {
		t.Fatalf("the window must follow not_after, not the cached counter; got %d results", len(cas))
	}
}

func TestCAFilterUrgencySortPutsTheWorstFirst(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	// Names chosen so alphabetical order is the reverse of urgency order: an
	// implementation that ignored Sort would still pass a weaker test.
	mustCreateCA(t, s, "aaa-plenty-of-time", "HEALTHY", 900*24*time.Hour)
	mustCreateCA(t, s, "mmm-middling", "WARNING", 100*24*time.Hour)
	mustCreateCA(t, s, "zzz-about-to-expire", "CRITICAL", 2*24*time.Hour)

	cas, err := s.ListCAAuthorities(ctx, CAFilter{Sort: CASortUrgency})
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	want := []string{"zzz-about-to-expire", "mmm-middling", "aaa-plenty-of-time"}
	for i, name := range want {
		if cas[i].Name != name {
			t.Errorf("urgency position %d: want %s, got %s", i, name, cas[i].Name)
		}
	}

	// The default remains alphabetical, for the inventory view.
	cas, err = s.ListCAAuthorities(ctx, CAFilter{})
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	if cas[0].Name != "aaa-plenty-of-time" {
		t.Errorf("default sort should be by name, got %s first", cas[0].Name)
	}
}

func TestCAListOmitsPEMUnlessAsked(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	mustCreateCA(t, s, "some-ca", "HEALTHY", 500*24*time.Hour)

	cas, err := s.ListCAAuthorities(ctx, CAFilter{})
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	if cas[0].CertificatePEM != "" {
		t.Error("the PEM should be absent by default; it is kilobytes per CA and no dashboard renders it")
	}

	cas, err = s.ListCAAuthorities(ctx, CAFilter{IncludePEM: true})
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	if cas[0].CertificatePEM == "" {
		t.Error("IncludePEM must return the PEM — the health sweep re-parses it every run")
	}
}

// TestUpdateCAAuthorityKeepsTheStoredPEM guards the trap that omitting the PEM
// from list results would otherwise create.
//
// The health sweep's shape is list, mutate, write back. A caller that listed
// without the PEM holds a record whose PEM is blank; if the update wrote that
// through, the only copy of the CA certificate would be gone and the next sweep
// would report the CA as UNKNOWN rather than as expiring — the failure this
// whole phase exists to prevent, caused by the monitoring itself.
func TestUpdateCAAuthorityKeepsTheStoredPEM(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	original := mustCreateCA(t, s, "some-ca", "HEALTHY", 500*24*time.Hour)

	listed, err := s.ListCAAuthorities(ctx, CAFilter{})
	if err != nil {
		t.Fatalf("ListCAAuthorities: %v", err)
	}
	ca := listed[0]
	if ca.CertificatePEM != "" {
		t.Fatal("precondition: the listed record should have no PEM")
	}

	ca.Status = "WARNING"
	if err := s.UpdateCAAuthority(ctx, ca); err != nil {
		t.Fatalf("UpdateCAAuthority: %v", err)
	}

	after, err := s.GetCAAuthority(ctx, ca.ID)
	if err != nil {
		t.Fatalf("GetCAAuthority: %v", err)
	}
	if after.CertificatePEM != original.CertificatePEM {
		t.Error("writing back a record listed without the PEM destroyed the stored certificate")
	}
	if after.Status != "WARNING" {
		t.Error("the update did not take effect")
	}
}

func TestUpdateCAAuthorityPersistsThresholdsAndTags(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	ca := mustCreateCA(t, s, "some-ca", "HEALTHY", 500*24*time.Hour)

	ca.AlertThresholds = `[180,90,30]`
	ca.Tags = `["production"]`
	if err := s.UpdateCAAuthority(ctx, ca); err != nil {
		t.Fatalf("UpdateCAAuthority: %v", err)
	}

	after, err := s.GetCAAuthority(ctx, ca.ID)
	if err != nil {
		t.Fatalf("GetCAAuthority: %v", err)
	}
	// Previously unwritable through the API at all — thresholds could only be
	// set by editing the database directly.
	if after.AlertThresholds != `[180,90,30]` {
		t.Errorf("alert thresholds not persisted, got %q", after.AlertThresholds)
	}
	if after.Tags != `["production"]` {
		t.Errorf("tags not persisted, got %q", after.Tags)
	}
}

// TestHealthSweepAndSnapshotDoNotRace reproduces the production pairing: the CA
// monitor reading and writing every authority while the event stream reads the
// same records to build a snapshot. Meaningful under -race.
func TestHealthSweepAndSnapshotDoNotRace(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	for i := 0; i < 8; i++ {
		mustCreateCA(t, s, fmt.Sprintf("ca-%d", i), "HEALTHY", time.Duration(i+1)*100*24*time.Hour)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // the health sweep
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cas, err := s.ListCAAuthorities(ctx, CAFilter{IncludePEM: true})
			if err != nil {
				return
			}
			for _, ca := range cas {
				ca.Status = "WARNING"
				ca.DaysRemaining = i
				_ = s.UpdateCAAuthority(ctx, ca)
			}
		}
	}()

	go func() { // the event stream snapshot
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cas, err := s.ListCAAuthorities(ctx, CAFilter{Sort: CASortUrgency})
			if err != nil {
				return
			}
			for _, ca := range cas {
				_ = ca.Name + ca.Status
				_ = ca.DaysRemaining
			}
			if _, err := s.GetDashboardStats(ctx); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// ── Dashboard statistics ────────────────────────────────

// TestDashboardCABucketsPartitionTheEstate is the property that makes the
// numbers trustworthy: every CA is counted once and the buckets sum to the
// total. The two store implementations previously disagreed here, one folding
// UNKNOWN into CriticalCAs and the other dropping it.
func TestDashboardCABucketsPartitionTheEstate(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()
	for _, status := range []string{"HEALTHY", "HEALTHY", "WARNING", "CRITICAL", "EXPIRED", "UNKNOWN", ""} {
		mustCreateCA(t, s, "ca-"+status+fmt.Sprint(len(status)), status, 100*24*time.Hour)
	}

	stats, err := s.GetDashboardStats(ctx)
	if err != nil {
		t.Fatalf("GetDashboardStats: %v", err)
	}

	sum := stats.HealthyCAs + stats.WarningCAs + stats.CriticalCAs + stats.ExpiredCAs + stats.UnknownCAs
	if sum != stats.TotalCAs {
		t.Errorf("buckets sum to %d but the total is %d — a dashboard whose figures do not add up is one nobody acts on", sum, stats.TotalCAs)
	}
	if stats.HealthyCAs != 2 {
		t.Errorf("healthy: want 2, got %d", stats.HealthyCAs)
	}
	if stats.ExpiredCAs != 1 {
		t.Errorf("expired must be its own bucket: want 1, got %d", stats.ExpiredCAs)
	}
	if stats.CriticalCAs != 1 {
		t.Errorf("critical must not absorb expired or unknown: want 1, got %d", stats.CriticalCAs)
	}
	// "UNKNOWN" and "" both land here: a CA nobody can assess is not healthy,
	// and hiding it is how a green dashboard covers an unmonitored CA.
	if stats.UnknownCAs != 2 {
		t.Errorf("unknown: want 2, got %d", stats.UnknownCAs)
	}
}

// TestExpiredCertificatesAreCountedAsExpired covers a bug in the in-memory
// stats: an expired certificate has days_remaining 0, which matched the
// "expiring soon" branch first, so ExpiredCerts was always zero and the
// dashboard reported an outage as an upcoming task.
func TestExpiredCertificatesAreCountedAsExpired(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	past := time.Now().Add(-24 * time.Hour)
	soon := time.Now().Add(10 * 24 * time.Hour)
	later := time.Now().Add(300 * 24 * time.Hour)

	for _, c := range []*Certificate{
		{CommonName: "expired.example.com", Status: "EXPIRED", NotAfter: &past, DaysRemaining: 0},
		{CommonName: "soon.example.com", Status: "ISSUED", NotAfter: &soon, DaysRemaining: 10},
		{CommonName: "fine.example.com", Status: "ISSUED", NotAfter: &later, DaysRemaining: 300},
	} {
		cert := c
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		// CreateCertificate recomputes DaysRemaining from NotAfter, which
		// leaves the expired record at 0 as intended.
	}

	stats, err := s.GetDashboardStats(ctx)
	if err != nil {
		t.Fatalf("GetDashboardStats: %v", err)
	}
	if stats.ExpiredCerts != 1 {
		t.Errorf("expired certificates: want 1, got %d", stats.ExpiredCerts)
	}
	if stats.ExpiringSoonCerts != 1 {
		t.Errorf("expiring soon: want 1, got %d", stats.ExpiringSoonCerts)
	}
	if stats.HealthyCerts != 1 {
		t.Errorf("healthy: want 1, got %d", stats.HealthyCerts)
	}
}

// ── Certificate private keys ────────────────────────────

// TestUpdateCertificateKeepsTheStoredPrivateKey covers the more damaging half
// of the private-key gap. No read path populates PrivateKeyEncrypted, so an
// ordinary update carries nil — which must leave the stored key alone.
func TestUpdateCertificateKeepsTheStoredPrivateKey(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	sealed := "sealed-key-v1"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := &Certificate{
		CommonName:          "app.example.com",
		Status:              "ISSUED",
		NotAfter:            &notAfter,
		PrivateKeyEncrypted: &sealed,
	}
	if err := s.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	read, err := s.GetCertificate(ctx, cert.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	read.PrivateKeyEncrypted = nil // what every read path produces
	read.Status = "EXPIRING"
	if err := s.UpdateCertificate(ctx, read); err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}

	key, err := s.GetCertificatePrivateKey(ctx, cert.ID)
	if err != nil {
		t.Fatalf("GetCertificatePrivateKey: %v", err)
	}
	if key != sealed {
		t.Errorf("an ordinary update erased the stored private key: got %q", key)
	}
}

// TestRenewalReplacesTheStoredPrivateKey is the other half: when renewal does
// rotate the key, the new one must land. Storing a new certificate against the
// old key produces a record the dashboard shows as healthy and which cannot
// terminate TLS.
func TestRenewalReplacesTheStoredPrivateKey(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	oldKey := "sealed-key-v1"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := &Certificate{CommonName: "app.example.com", Status: "ISSUED", NotAfter: &notAfter, PrivateKeyEncrypted: &oldKey}
	if err := s.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	newKey := "sealed-key-v2"
	cert.PrivateKeyEncrypted = &newKey
	cert.RenewalCount++
	if err := s.UpdateCertificate(ctx, cert); err != nil {
		t.Fatalf("UpdateCertificate: %v", err)
	}

	key, err := s.GetCertificatePrivateKey(ctx, cert.ID)
	if err != nil {
		t.Fatalf("GetCertificatePrivateKey: %v", err)
	}
	if key != newKey {
		t.Errorf("the rotated key was not stored: want %q, got %q", newKey, key)
	}
}

func TestGetCertificatePrivateKeyReportsAbsenceDistinctlyFromError(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := &Certificate{CommonName: "imported.example.com", Status: "ISSUED", NotAfter: &notAfter}
	if err := s.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	// A certificate with no key is the normal case for imported, discovered,
	// and CSR-based records, and must not read as a failure.
	key, err := s.GetCertificatePrivateKey(ctx, cert.ID)
	if err != nil {
		t.Fatalf("a keyless certificate should not be an error: %v", err)
	}
	if key != "" {
		t.Errorf("want no key, got %q", key)
	}

	if _, err := s.GetCertificatePrivateKey(ctx, "no-such-certificate"); err == nil {
		t.Error("a missing certificate should be an error, distinct from a certificate with no key")
	}
}

// TestListCertificatesHonoursEveryFilterField covers fields the in-memory store
// silently ignored while PostgresStore applied them — so a filtered view
// behaved one way in development and another in production.
func TestListCertificatesHonoursEveryFilterField(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	accountA, accountB := "account-a", "account-b"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	for i := 0; i < 60; i++ {
		account := accountA
		if i%2 == 1 {
			account = accountB
		}
		cert := &Certificate{
			CommonName:  fmt.Sprintf("host-%02d.example.com", i),
			Status:      "ISSUED",
			Environment: "production",
			NotAfter:    &notAfter,
			CAAccountID: &account,
		}
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
	}

	certs, total, err := s.ListCertificates(ctx, CertificateFilter{CAAccountID: accountA})
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if total != 30 {
		t.Errorf("CAAccountID filter: want 30 matches, got %d", total)
	}
	// The default page is 50, so 30 matches arrive whole.
	if len(certs) != 30 {
		t.Errorf("want 30 rows, got %d", len(certs))
	}

	certs, total, err = s.ListCertificates(ctx, CertificateFilter{Limit: 10, Offset: 5})
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 10 {
		t.Errorf("limit ignored: want 10 rows, got %d", len(certs))
	}
	if total != 60 {
		t.Errorf("total should describe the filtered set before paging: want 60, got %d", total)
	}
}

// ── Notification channels ───────────────────────────────

func TestNotificationChannelAccepts(t *testing.T) {
	cases := []struct {
		name    string
		channel NotificationChannel
		topic   string
		sev     string
		want    bool
	}{
		{
			name:    "threshold admits equal severity",
			channel: NotificationChannel{IsEnabled: true, SeverityThreshold: "WARNING"},
			topic:   "ca.expiry_alert", sev: "WARNING", want: true,
		},
		{
			name:    "threshold admits higher severity",
			channel: NotificationChannel{IsEnabled: true, SeverityThreshold: "WARNING"},
			topic:   "ca.expiry_alert", sev: "CRITICAL", want: true,
		},
		{
			name:    "threshold rejects lower severity",
			channel: NotificationChannel{IsEnabled: true, SeverityThreshold: "WARNING"},
			topic:   "cert.issued", sev: "INFO", want: false,
		},
		{
			name:    "a disabled channel accepts nothing",
			channel: NotificationChannel{IsEnabled: false, SeverityThreshold: "INFO"},
			topic:   "ca.expiry_alert", sev: "CRITICAL", want: false,
		},
		{
			name:    "no topics means every topic",
			channel: NotificationChannel{IsEnabled: true, SeverityThreshold: "INFO", Topics: []string{}},
			topic:   "anything.at.all", sev: "INFO", want: true,
		},
		{
			name:    "a topic list excludes what it omits",
			channel: NotificationChannel{IsEnabled: true, SeverityThreshold: "INFO", Topics: []string{"ca.expiry_alert"}},
			topic:   "cert.issued", sev: "CRITICAL", want: false,
		},
		{
			name:    "a topic list admits what it names",
			channel: NotificationChannel{IsEnabled: true, SeverityThreshold: "INFO", Topics: []string{"ca.expiry_alert"}},
			topic:   "ca.expiry_alert", sev: "INFO", want: true,
		},
		{
			// Delivering an alert whose severity was spelled unexpectedly is
			// the better of the two mistakes.
			name:    "an unrecognised severity is treated as critical",
			channel: NotificationChannel{IsEnabled: true, SeverityThreshold: "CRITICAL"},
			topic:   "ca.expiry_alert", sev: "SEV1", want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := tc.channel
			if got := ch.Accepts(tc.topic, tc.sev); got != tc.want {
				t.Errorf("Accepts(%q, %q) = %v, want %v", tc.topic, tc.sev, got, tc.want)
			}
		})
	}
}

func TestNotificationChannelCRUD(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	ch := &NotificationChannel{
		Name:              "pki-team-slack",
		ChannelType:       "slack",
		ConfigEncrypted:   "sealed-webhook-url",
		IsEnabled:         true,
		SeverityThreshold: "WARNING",
		Topics:            []string{"ca.expiry_alert"},
	}
	if err := s.CreateNotificationChannel(ctx, ch); err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	if ch.ID == "" {
		t.Fatal("create did not assign an ID")
	}

	// The name is what makes "mute the team channel" an answerable request, so
	// it has to stay unique.
	dup := &NotificationChannel{Name: "pki-team-slack", ChannelType: "webhook"}
	if err := s.CreateNotificationChannel(ctx, dup); err == nil {
		t.Error("a duplicate channel name should be refused")
	}

	ch.SeverityThreshold = "CRITICAL"
	if err := s.UpdateNotificationChannel(ctx, ch); err != nil {
		t.Fatalf("UpdateNotificationChannel: %v", err)
	}
	got, err := s.GetNotificationChannel(ctx, ch.ID)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	if got.SeverityThreshold != "CRITICAL" {
		t.Errorf("update did not take: got %q", got.SeverityThreshold)
	}

	if err := s.DeleteNotificationChannel(ctx, ch.ID); err != nil {
		t.Fatalf("DeleteNotificationChannel: %v", err)
	}
	if _, err := s.GetNotificationChannel(ctx, ch.ID); err == nil {
		t.Error("the channel should be gone after delete")
	}
}

// TestUpdateNotificationChannelDoesNotRewindDelivery pins the reason
// MarkNotificationChannelSent is a separate method: the dispatcher records
// deliveries concurrently with whoever is editing the channel, and an edit that
// carried a stale last_sent_at would erase the evidence that alerts are
// actually going out.
func TestUpdateNotificationChannelDoesNotRewindDelivery(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	ch := &NotificationChannel{Name: "ops", ChannelType: "webhook", IsEnabled: true, SeverityThreshold: "INFO"}
	if err := s.CreateNotificationChannel(ctx, ch); err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}

	sentAt := time.Now()
	if err := s.MarkNotificationChannelSent(ctx, ch.ID, sentAt); err != nil {
		t.Fatalf("MarkNotificationChannelSent: %v", err)
	}

	// `ch` is the caller's stale copy, from before the delivery.
	ch.IsEnabled = false
	if err := s.UpdateNotificationChannel(ctx, ch); err != nil {
		t.Fatalf("UpdateNotificationChannel: %v", err)
	}

	got, err := s.GetNotificationChannel(ctx, ch.ID)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	if got.LastSentAt == nil || !got.LastSentAt.Equal(sentAt) {
		t.Error("an edit rewound the delivery record")
	}
	if got.IsEnabled {
		t.Error("the edit itself did not take effect")
	}
}

func TestNotificationChannelTopicsAreNeverNil(t *testing.T) {
	ctx := context.Background()
	s := newEmptyStore()

	// A nil slice marshals to JSON null, which fails the jsonb array
	// constraint and reads back as ambiguous.
	ch := &NotificationChannel{Name: "everything", ChannelType: "email", IsEnabled: true, SeverityThreshold: "INFO"}
	if err := s.CreateNotificationChannel(ctx, ch); err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	got, err := s.GetNotificationChannel(ctx, ch.ID)
	if err != nil {
		t.Fatalf("GetNotificationChannel: %v", err)
	}
	if got.Topics == nil {
		t.Error("topics should normalise to an empty slice, not nil")
	}
}

// TestNewMemoryStoreSeedsNoCredentials guards the rule that sample data may
// include anything except a credential.
func TestNewMemoryStoreSeedsNoCredentials(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	tokens, err := s.ListDisplayTokens(ctx)
	if err != nil {
		t.Fatalf("ListDisplayTokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("the sample data seeds %d display tokens; a seeded credential is one someone forgets to remove", len(tokens))
	}

	channels, err := s.ListNotificationChannels(ctx)
	if err != nil {
		t.Fatalf("ListNotificationChannels: %v", err)
	}
	if len(channels) != 0 {
		t.Errorf("the sample data seeds %d notification channels", len(channels))
	}
}
