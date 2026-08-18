package discovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// The finding only a repeated scan can produce.
//
// A certificate rotating on an endpoint CertPilot does not manage means
// something out there renewed it without going through any of this — so
// somebody knows how to replace it, and finding out who is the whole point.
func TestARotatedCertificateOnAnUnmanagedEndpointIsAWarning(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	first := ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	target, swap := startSwappableTLSServer(t, first)

	st := newEmptyStore()
	scanner := newTestScanner(st)

	if _, _, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{target}}); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// The same endpoint, serving something else.
	swap(ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(120*24*time.Hour)))

	_, results, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{target}})
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	finding := findingWithCode(results[0], FindingCertificateChanged)
	if finding == nil {
		t.Fatalf("no certificate_changed finding: %+v", results[0].Findings)
	}
	if finding.Severity != "WARNING" {
		t.Errorf("severity = %q, want WARNING for a rotation on an unmanaged endpoint", finding.Severity)
	}
	if !strings.Contains(finding.Detail, "outside this system") {
		t.Errorf("the finding does not say what the change means: %q", finding.Detail)
	}
}

// The same rotation on a managed endpoint is a renewal, and unremarkable. A
// system that alerted on its own renewals would train people to ignore the
// alert that matters.
func TestARotatedCertificateOnAManagedEndpointIsInformational(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	first := ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	target, swap := startSwappableTLSServer(t, first)

	st := newEmptyStore()
	scanner := newTestScanner(st)
	if _, _, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{target}}); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	second := ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(120*24*time.Hour))
	swap(second)

	// The replacement is in inventory: CertPilot renewed it.
	if err := st.CreateCertificate(context.Background(), &store.Certificate{
		FingerprintSHA256: fingerprintOf(second.cert),
		CommonName:        "localhost",
		Status:            "ISSUED",
	}); err != nil {
		t.Fatalf("seeding inventory: %v", err)
	}

	_, results, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{target}})
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	finding := findingWithCode(results[0], FindingCertificateChanged)
	if finding == nil {
		t.Fatalf("the change was not noticed at all: %+v", results[0].Findings)
	}
	if finding.Severity != "INFO" {
		t.Errorf("severity = %q, want INFO — this is a renewal CertPilot knows about", finding.Severity)
	}
}

// An endpoint that used to answer and no longer does is a finding. Either it
// moved and the scan no longer covers it, or it is down; both are worth
// knowing, and neither is visible on a first scan.
func TestAnEndpointThatStopsAnsweringIsReported(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	leaf := ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	srv, closeServer := startClosableTLSServer(t, leaf)

	st := newEmptyStore()
	scanner := newTestScanner(st)
	if _, _, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{srv}}); err != nil {
		t.Fatalf("first scan: %v", err)
	}

	closeServer()

	_, results, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{srv}})
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if results[0].Reachable {
		t.Fatal("the endpoint still answered after the server was closed")
	}

	finding := findingWithCode(results[0], FindingEndpointDisappeared)
	if finding == nil {
		t.Fatalf("no endpoint_disappeared finding: %+v", results[0].Findings)
	}
	if !strings.Contains(finding.Detail, "localhost") {
		t.Errorf("the finding does not name what used to be there: %q", finding.Detail)
	}
}

// A first scan must not report an estate as a hundred changes. Every endpoint
// is new the first time, and a run whose findings are all "this is new" is one
// nobody reads a second time.
func TestAFirstScanReportsNoChanges(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	_, results, err := newTestScanner(newEmptyStore()).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, code := range []string{FindingCertificateChanged, FindingEndpointDisappeared, FindingEndpointAppeared} {
		if findingWithCode(results[0], code) != nil {
			t.Errorf("a first scan reported %q", code)
		}
	}
}

// An unchanged endpoint produces no change findings either. A scan that
// reported every endpoint every night would be a scan nobody opens.
func TestAnUnchangedEndpointIsQuiet(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	st := newEmptyStore()
	scanner := newTestScanner(st)
	if _, _, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}}); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	_, results, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if f := findingWithCode(results[0], FindingCertificateChanged); f != nil {
		t.Errorf("an unchanged endpoint reported a change: %q", f.Detail)
	}
}

// The outstanding-work list is a question about now, not a history. Without
// this, a nightly schedule turns one unmanaged certificate into thirty findings
// and the number stops meaning anything.
func TestLatestPerEndpointCollapsesRepeatedScans(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	st := newEmptyStore()
	scanner := newTestScanner(st)
	for i := 0; i < 3; i++ {
		if _, _, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}}); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
	}

	all, total, err := st.ListDiscoveryResults(context.Background(), store.DiscoveryResultFilter{})
	if err != nil {
		t.Fatalf("ListDiscoveryResults: %v", err)
	}
	if total != 3 {
		t.Fatalf("history holds %d results, want 3 — each scan is still its own record", total)
	}
	_ = all

	latest, latestTotal, err := st.ListDiscoveryResults(context.Background(),
		store.DiscoveryResultFilter{LatestPerEndpoint: true})
	if err != nil {
		t.Fatalf("ListDiscoveryResults(latest): %v", err)
	}
	if latestTotal != 1 || len(latest) != 1 {
		t.Fatalf("latest gave %d results (total %d), want 1", len(latest), latestTotal)
	}
}

// Collapsing happens before filtering, not after.
//
// The other order answers "the most recent time this endpoint was unmanaged",
// which keeps reporting an endpoint that has since been adopted — work that is
// already done, asked for again every night.
func TestLatestCollapsesBeforeFiltering(t *testing.T) {
	st := newEmptyStore()
	ctx := context.Background()

	scan := &store.DiscoveryScan{ScanType: store.ScanTypeNetwork}
	if err := st.CreateDiscoveryScan(ctx, scan); err != nil {
		t.Fatalf("CreateDiscoveryScan: %v", err)
	}

	// The same endpoint, unmanaged then managed.
	older := &store.DiscoveryResult{
		ScanID: scan.ID, Host: "10.0.0.1", Port: 443, Reachable: true,
		ManagementState: store.DiscoveryUnmanaged, TrustState: store.TrustPublic,
		ScannedAt: time.Now().Add(-2 * time.Hour),
	}
	newer := &store.DiscoveryResult{
		ScanID: scan.ID, Host: "10.0.0.1", Port: 443, Reachable: true,
		ManagementState: store.DiscoveryManaged, TrustState: store.TrustPublic,
		ScannedAt: time.Now(),
	}
	if err := st.CreateDiscoveryResults(ctx, []*store.DiscoveryResult{older, newer}); err != nil {
		t.Fatalf("CreateDiscoveryResults: %v", err)
	}

	_, total, err := st.ListDiscoveryResults(ctx, store.DiscoveryResultFilter{
		ManagementState: store.DiscoveryUnmanaged, LatestPerEndpoint: true,
	})
	if err != nil {
		t.Fatalf("ListDiscoveryResults: %v", err)
	}
	if total != 0 {
		t.Errorf("an endpoint that is now managed is still listed as outstanding work (total = %d)", total)
	}
}

func findingWithCode(r *store.DiscoveryResult, code string) *store.Finding {
	for i := range r.Findings {
		if r.Findings[i].Code == code {
			return &r.Findings[i]
		}
	}
	return nil
}
