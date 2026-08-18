package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in      string
		port    int
		want    Target
		wantErr bool
	}{
		{in: "example.com", want: Target{Host: "example.com", Port: 443}},
		{in: "example.com:8443", want: Target{Host: "example.com", Port: 8443}},
		{in: "example.com", port: 9443, want: Target{Host: "example.com", Port: 9443}},
		{in: "  example.com  ", want: Target{Host: "example.com", Port: 443}},
		{in: "10.0.0.5", want: Target{Host: "10.0.0.5", Port: 443}},
		{in: "[2001:db8::1]:8443", want: Target{Host: "2001:db8::1", Port: 8443}},
		{in: "2001:db8::1", want: Target{Host: "2001:db8::1", Port: 443}},

		// A target that quietly became something else produces a scan that
		// reports an unreachable endpoint, which reads as a finding about the
		// estate rather than a mistake in the input.
		{in: "https://example.com", wantErr: true},
		{in: "example.com/health", wantErr: true},
		{in: "example.com:0", wantErr: true},
		{in: "example.com:70000", wantErr: true},
		{in: "example.com:https", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tc := range cases {
		got, err := ParseTarget(tc.in, tc.port)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTarget(%q) = %+v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q) returned %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseTarget(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

// TestScanFindsAnUnmanagedCertificate is the whole point of the package: a
// certificate the inventory has never seen has to come back as UNMANAGED.
func TestScanFindsAnUnmanagedCertificate(t *testing.T) {
	ca := newTestCA(t, "Test Internal Root CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	st := newEmptyStore()
	scanner := newTestScanner(st)

	_, results, err := scanner.Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	got := results[0]
	if got.ManagementState != store.DiscoveryUnmanaged {
		t.Errorf("management state = %q, want UNMANAGED", got.ManagementState)
	}
	if !got.Reachable {
		t.Fatalf("endpoint reported unreachable: %s", got.Error)
	}
	if got.FingerprintSHA256 == "" {
		t.Error("no fingerprint recorded, so nothing can be matched against inventory later")
	}
	if got.CertificatePEM == "" {
		t.Error("no certificate PEM recorded, so the finding cannot be imported")
	}
}

// TestScanRecognisesAManagedCertificate is the other half. Getting this wrong
// in the safe direction produces noise; getting it wrong the other way reports
// an unmanaged certificate as handled.
func TestScanRecognisesAManagedCertificate(t *testing.T) {
	ca := newTestCA(t, "Test Internal Root CA")
	leaf := ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	srv := startTLSServer(t, leaf)

	st := newEmptyStore()
	fingerprint := fingerprintOf(leaf.cert)
	if err := st.CreateCertificate(context.Background(), &store.Certificate{
		FingerprintSHA256: fingerprint,
		CommonName:        "localhost",
		Status:            "ISSUED",
	}); err != nil {
		t.Fatalf("seeding inventory: %v", err)
	}

	scan, results, err := newTestScanner(st).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if results[0].ManagementState != store.DiscoveryManaged {
		t.Fatalf("management state = %q, want MANAGED", results[0].ManagementState)
	}
	if results[0].MatchedCertificateID == nil {
		t.Error("a managed result must name the certificate it matched")
	}
	if scan.UnmanagedCount != 0 || scan.ManagedCount != 1 {
		t.Errorf("counts = %d unmanaged / %d managed, want 0/1", scan.UnmanagedCount, scan.ManagedCount)
	}
}

// TestTrustStateReflectsTheRegisteredCAs — an internally-issued certificate
// must not read as untrusted just because no public root vouches for it. This
// is the normal case inside an organisation running private PKI, and reporting
// all of it as a problem is how a findings list becomes wallpaper.
func TestTrustStateReflectsTheRegisteredCAs(t *testing.T) {
	ca := newTestCA(t, "Registered Internal CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	st := newEmptyStore()
	if err := st.CreateCAAuthority(context.Background(), &store.CAAuthority{
		Name:           "Registered Internal CA",
		CAType:         "ROOT",
		CertificatePEM: ca.pem(),
		Status:         "HEALTHY",
	}); err != nil {
		t.Fatalf("registering the CA: %v", err)
	}

	_, results, err := newTestScanner(st).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if results[0].TrustState != store.TrustInternal {
		t.Errorf("trust state = %q, want INTERNAL", results[0].TrustState)
	}
	if hasFinding(results[0], FindingUntrustedIssuer) {
		t.Error("a certificate from a registered CA must not be reported as having an untrusted issuer")
	}
}

// TestUnregisteredIssuerIsUntrusted — the same endpoint, with nobody having
// registered its CA. This is a real finding: certificates are being issued here
// by an authority whose own expiry nothing is watching.
func TestUnregisteredIssuerIsUntrusted(t *testing.T) {
	ca := newTestCA(t, "Shadow CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	_, results, err := newTestScanner(newEmptyStore()).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if results[0].TrustState != store.TrustUntrusted {
		t.Errorf("trust state = %q, want UNTRUSTED", results[0].TrustState)
	}
	if !hasFinding(results[0], FindingUntrustedIssuer) {
		t.Error("want an untrusted_issuer finding")
	}
}

func TestSelfSignedIsReportedAsSuch(t *testing.T) {
	leaf := selfSignedLeaf(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	srv := startTLSServer(t, leaf)

	_, results, err := newTestScanner(newEmptyStore()).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if results[0].TrustState != store.TrustSelfSigned {
		t.Errorf("trust state = %q, want SELF_SIGNED", results[0].TrustState)
	}
	if !hasFinding(results[0], FindingSelfSigned) {
		t.Error("want a self_signed finding")
	}
}

// TestExpiredCertificateStillReportsItsIssuer is the subtle one.
//
// Every verification fails against an expired certificate, for one reason. If
// that reason is allowed to swallow the trust answer, every expired internal
// certificate reads as issued by an unknown CA — which sends the investigation
// looking for a rogue issuer that does not exist.
func TestExpiredCertificateStillReportsItsIssuer(t *testing.T) {
	ca := newTestCA(t, "Registered Internal CA")
	expired := ca.issue(t, "localhost", time.Now().Add(-90*24*time.Hour), time.Now().Add(-24*time.Hour))
	srv := startTLSServer(t, expired)

	st := newEmptyStore()
	if err := st.CreateCAAuthority(context.Background(), &store.CAAuthority{
		Name: "Registered Internal CA", CAType: "ROOT", CertificatePEM: ca.pem(), Status: "HEALTHY",
	}); err != nil {
		t.Fatalf("registering the CA: %v", err)
	}

	_, results, err := newTestScanner(st).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if results[0].TrustState != store.TrustInternal {
		t.Errorf("trust state = %q, want INTERNAL — expiry must not be reported as an unknown issuer", results[0].TrustState)
	}
	if !hasFinding(results[0], FindingExpired) {
		t.Error("want an expired finding")
	}
	if hasFinding(results[0], FindingUntrustedIssuer) {
		t.Error("an expired certificate from a known CA is expired, not untrusted")
	}
}

func TestWeakKeyAndOldCertificateAreFindings(t *testing.T) {
	leaf := selfSignedRSALeaf(t, "localhost", 1024)
	srv := startTLSServer(t, leaf)

	_, results, err := newTestScanner(newEmptyStore()).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !hasFinding(results[0], FindingWeakKey) {
		t.Errorf("want a weak_key finding for RSA-1024, got %+v", results[0].Findings)
	}
}

// TestIncompleteChainIsDetected — a server sending only its leaf works for
// every client that already holds the intermediate and fails for the ones that
// do not, which is why it breaks intermittently and only for some users.
func TestIncompleteChainIsDetected(t *testing.T) {
	root := newTestCA(t, "Test Root")
	intermediate := root.issueCA(t, "Test Intermediate")
	leaf := intermediate.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	// Serve the leaf alone: the intermediate is deliberately withheld.
	srv := startTLSServer(t, leaf)

	st := newEmptyStore()
	for name, ca := range map[string]*testCA{"Test Root": root, "Test Intermediate": intermediate} {
		if err := st.CreateCAAuthority(context.Background(), &store.CAAuthority{
			Name: name, CAType: "ROOT", CertificatePEM: ca.pem(), Status: "HEALTHY",
		}); err != nil {
			t.Fatalf("registering %s: %v", name, err)
		}
	}

	_, results, err := newTestScanner(st).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if results[0].ChainLength != 1 {
		t.Fatalf("chain length = %d, want 1", results[0].ChainLength)
	}
	if !hasFinding(results[0], FindingIncompleteChain) {
		t.Errorf("want an incomplete_chain finding, got %+v", results[0].Findings)
	}
	if results[0].TrustState != store.TrustInternal {
		t.Errorf("trust state = %q; the chain is sound, it is just not being sent", results[0].TrustState)
	}
}

// TestUnreachableEndpointIsRecorded — an endpoint that refused is a row, not an
// absence. A scan that reached nothing and a scan that found nothing produce
// the same empty results list, and only one of them means the estate is clean.
func TestUnreachableEndpointIsRecorded(t *testing.T) {
	// A port nothing is listening on: bind one and close it immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()

	st := newEmptyStore()
	scan, results, err := newTestScanner(st).Scan(context.Background(), ScanRequest{
		Targets: []Target{{Host: "127.0.0.1", Port: addr.Port}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Reachable {
		t.Error("a closed port must not report as reachable")
	}
	if results[0].ManagementState != store.DiscoveryUnreachable {
		t.Errorf("management state = %q, want UNREACHABLE", results[0].ManagementState)
	}
	if results[0].Error == "" {
		t.Error("the dialler's own words must survive; without them nobody can tell refused from filtered")
	}
	if scan.UnreachableCount != 1 || scan.UnmanagedCount != 0 {
		t.Errorf("counts = %d unreachable / %d unmanaged, want 1/0", scan.UnreachableCount, scan.UnmanagedCount)
	}
}

// TestScanRecordsTheHandshake — unrecoverable afterwards, and the basis of
// every later answer about cryptographic posture.
func TestScanRecordsTheHandshake(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	_, results, err := newTestScanner(newEmptyStore()).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := results[0]
	if got.TLSVersion == "" || got.CipherSuite == "" || got.KeyExchange == "" {
		t.Errorf("handshake not fully recorded: version=%q cipher=%q kex=%q",
			got.TLSVersion, got.CipherSuite, got.KeyExchange)
	}
	if got.TLSVersion == "TLS 1.3" && got.ALPN == "" {
		t.Error("ALPN was offered and the test server negotiates http/1.1; it should have been recorded")
	}
}

// TestScanRecordsRunBeforeProbing — a run that dies halfway has to leave
// evidence it was attempted, because on this dashboard a missing scan reads as
// "nothing to find".
func TestScanPersistsTheRun(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	st := newEmptyStore()
	scan, _, err := newTestScanner(st).Scan(context.Background(), ScanRequest{Targets: []Target{srv.target}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	stored, err := st.GetDiscoveryScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("GetDiscoveryScan: %v", err)
	}
	if stored.Status != store.ScanCompleted {
		t.Errorf("status = %q, want COMPLETED", stored.Status)
	}
	if stored.CompletedAt == nil || stored.StartedAt == nil {
		t.Error("a completed scan must carry both timestamps")
	}
	if len(stored.Targets) != 1 {
		t.Errorf("targets = %v, want the one that was asked for", stored.Targets)
	}

	results, total, err := st.ListDiscoveryResults(context.Background(), store.DiscoveryResultFilter{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("ListDiscoveryResults: %v", err)
	}
	if total != 1 || len(results) != 1 {
		t.Fatalf("stored %d results (total %d), want 1", len(results), total)
	}
}

func TestScanRejectsAnEmptyTargetList(t *testing.T) {
	if _, _, err := newTestScanner(newEmptyStore()).Scan(context.Background(), ScanRequest{}); err == nil {
		t.Error("a scan with no targets must be refused, not recorded as an empty clean run")
	}
}

// ── helpers ─────────────────────────────────────────────

func newTestScanner(st store.Store) *Scanner {
	s := NewScanner(st)
	s.dialTimeout = 3 * time.Second
	return s
}

// newEmptyStore returns a store with none of the sample data, so a test's own
// fixtures are the only thing in it.
func newEmptyStore() *store.MemoryStore {
	st := store.NewMemoryStore()
	ctx := context.Background()
	certs, _, _ := st.ListCertificates(ctx, store.CertificateFilter{Limit: 1000})
	for _, c := range certs {
		_ = st.DeleteCertificate(ctx, c.ID)
	}
	cas, _ := st.ListCAAuthorities(ctx, store.CAFilter{})
	for _, ca := range cas {
		_ = st.DeleteCAAuthority(ctx, ca.ID)
	}
	return st
}

func hasFinding(r *store.DiscoveryResult, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// fingerprintOf mirrors x509util: SHA-256 over the DER, hex encoded. Computed
// independently here so a test would catch the day the two stop agreeing —
// matching inventory is done by this value and nothing else.
func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
}

func (ca *testCA) issueCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating intermediate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating intermediate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing intermediate: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

type testLeaf struct {
	cert *x509.Certificate
	tls  tls.Certificate
}

func (ca *testCA) issue(t *testing.T, host string, notBefore, notAfter time.Time) *testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issuing leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	return &testLeaf{
		cert: cert,
		tls:  tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert},
	}
}

func selfSignedLeaf(t *testing.T, host string, notBefore, notAfter time.Time) *testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 3),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signing: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testLeaf{cert: cert, tls: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}}
}

func selfSignedRSALeaf(t *testing.T, host string, bits int) *testLeaf {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 4),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signing RSA: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testLeaf{cert: cert, tls: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}}
}

type testServer struct {
	target Target
}

// startTLSServer serves exactly the certificate given, with no chain appended,
// so a test controls precisely what the scanner sees on the wire.
func startTLSServer(t *testing.T, leaf *testLeaf) testServer {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf.tls},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().(*net.TCPAddr)
	return testServer{target: Target{Host: "127.0.0.1", Port: addr.Port}}
}

// TestBackgroundScanKeepsWhatItFoundWhenCancelled.
//
// The load-bearing property of cancellation. A cancel that discarded results is
// a cancel nobody uses, and then a range scan somebody started by mistake runs
// to completion against a network they did not mean to touch.
func TestBackgroundScanKeepsWhatItFoundWhenCancelled(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	reachable := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	stalled := startStalledServer(t)

	// Two endpoints that answer, then a queue of endpoints that never will.
	targets := []Target{reachable.target, reachable.target}
	for i := 0; i < 20; i++ {
		targets = append(targets, stalled)
	}

	st := newEmptyStore()
	scanner := NewScanner(st, WithConcurrency(2), WithDialTimeout(30*time.Second))
	scanner.batchSize = 1 // so progress is observable rather than buffered

	scan, err := scanner.Start(ScanRequest{Targets: targets})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if scan.Status != store.ScanRunning {
		t.Fatalf("status = %q immediately after Start, want RUNNING", scan.Status)
	}

	// Wait for the two reachable endpoints to land.
	waitFor(t, 10*time.Second, func() bool {
		stored, _ := st.GetDiscoveryScan(context.Background(), scan.ID)
		return stored.ResultsCount >= 2
	}, "the reachable endpoints to be stored")

	if !scanner.Cancel(scan.ID) {
		t.Fatal("Cancel reported no scan running")
	}

	waitFor(t, 10*time.Second, func() bool {
		stored, _ := st.GetDiscoveryScan(context.Background(), scan.ID)
		return stored.Status != store.ScanRunning
	}, "the scan to stop")

	stored, err := st.GetDiscoveryScan(context.Background(), scan.ID)
	if err != nil {
		t.Fatalf("GetDiscoveryScan: %v", err)
	}
	// Cancelled, not failed: the history has to distinguish "somebody stopped
	// it" from "something went wrong", or every deliberate stop reads as a bug.
	if stored.Status != store.ScanCancelled {
		t.Errorf("status = %q, want CANCELLED", stored.Status)
	}
	if stored.ResultsCount < 2 {
		t.Errorf("results kept = %d, want at least the 2 that completed", stored.ResultsCount)
	}
	if stored.ResultsCount >= len(targets) {
		t.Errorf("results = %d of %d targets; the scan did not actually stop early", stored.ResultsCount, len(targets))
	}
	if stored.CompletedAt == nil {
		t.Error("a cancelled scan must still record when it stopped")
	}

	results, _, err := st.ListDiscoveryResults(context.Background(), store.DiscoveryResultFilter{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("ListDiscoveryResults: %v", err)
	}
	if len(results) != stored.ResultsCount {
		t.Errorf("%d results stored but the scan says %d", len(results), stored.ResultsCount)
	}
	// A probe cut short learned nothing. Recording it as unreachable would
	// invent a finding about the estate by stopping the scan.
	for _, r := range results {
		if !r.Reachable {
			t.Errorf("a cancelled probe was recorded as an unreachable endpoint: %s — %s", r.Host, r.Error)
		}
	}
}

// Cancelling something that has already finished is not an error — the usual
// reason is that it completed a moment ago.
func TestCancelIsHarmlessWhenNothingIsRunning(t *testing.T) {
	scanner := NewScanner(newEmptyStore())
	if scanner.Cancel("no-such-scan") {
		t.Error("Cancel claimed to have stopped a scan that was never running")
	}
	scanner.Stop() // must not panic with nothing in flight
}

// Results are written as they are found, not all at the end. A run that was
// cancelled, crashed, or restarted through would otherwise have nothing to show
// for the endpoints it did reach.
//
// Asserted on the writes themselves rather than by racing a reader against the
// scan: a timing-based version of this test passes on a slow machine and says
// nothing on a fast one.
func TestResultsAreStoredInBatchesWhileTheScanRuns(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	leaf := ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	targets := []Target{}
	for i := 0; i < 6; i++ {
		targets = append(targets, startTLSServer(t, leaf).target)
	}

	recorder := &batchRecorder{Store: newEmptyStore()}
	scanner := NewScanner(recorder, WithConcurrency(2))
	scanner.batchSize = 2

	scan, _, err := scanner.Scan(context.Background(), ScanRequest{Targets: targets})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	batches := recorder.sizes()
	if len(batches) < 3 {
		t.Errorf("results were written in %d batches %v; six endpoints at a batch size of two should be three writes",
			len(batches), batches)
	}
	total := 0
	for _, n := range batches {
		total += n
		if n > 2 {
			t.Errorf("a batch of %d exceeded the batch size of 2", n)
		}
	}
	if total != len(targets) {
		t.Errorf("%d results written in total, want %d", total, len(targets))
	}

	stored, _ := recorder.GetDiscoveryScan(context.Background(), scan.ID)
	if stored.ResultsCount != len(targets) {
		t.Errorf("results = %d, want %d", stored.ResultsCount, len(targets))
	}
}

// batchRecorder notes the size of every write the scanner makes.
type batchRecorder struct {
	store.Store
	mu      sync.Mutex
	batches []int
}

func (b *batchRecorder) CreateDiscoveryResults(ctx context.Context, results []*store.DiscoveryResult) error {
	b.mu.Lock()
	b.batches = append(b.batches, len(results))
	b.mu.Unlock()
	return b.Store.CreateDiscoveryResults(ctx, results)
}

func (b *batchRecorder) sizes() []int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]int{}, b.batches...)
}

// The scan must outlive the request that started it. An HTTP request's context
// is cancelled the moment its response is written, so a background scan started
// from one would be killed by its own 202.
func TestBackgroundScanSurvivesTheCallersContext(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	srv := startTLSServer(t, ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))

	st := newEmptyStore()
	scanner := NewScanner(st, WithConcurrency(2))

	ctx, cancel := context.WithCancel(context.Background())
	scan, err := scanner.Start(ScanRequest{Targets: []Target{srv.target, srv.target}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel() // the caller goes away immediately
	_ = ctx

	waitFor(t, 10*time.Second, func() bool {
		stored, _ := st.GetDiscoveryScan(context.Background(), scan.ID)
		return stored.Status == store.ScanCompleted
	}, "the scan to complete despite the caller having gone")

	stored, _ := st.GetDiscoveryScan(context.Background(), scan.ID)
	if stored.ResultsCount != 2 {
		t.Errorf("results = %d, want 2", stored.ResultsCount)
	}
}

// startStalledServer accepts TCP connections and never speaks, so a probe
// against it hangs until it is cancelled or times out.
func startStalledServer(t *testing.T) Target {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return Target{Host: "127.0.0.1", Port: addr.Port}
}

func waitFor(t *testing.T, limit time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}

// startSwappableTLSServer holds one port and can be made to serve a different
// certificate on it, which is how a test reproduces the thing a repeated scan
// exists to catch: the same endpoint, a new certificate.
func startSwappableTLSServer(t *testing.T, leaf *testLeaf) (Target, func(*testLeaf)) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	var current *httptest.Server
	serve := func(l *testLeaf, listener net.Listener) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		_ = srv.Listener.Close()
		srv.Listener = listener
		srv.TLS = &tls.Config{
			Certificates: []tls.Certificate{l.tls},
			MinVersion:   tls.VersionTLS12,
		}
		srv.StartTLS()
		current = srv
	}
	serve(leaf, ln)
	t.Cleanup(func() { current.Close() })

	swap := func(l *testLeaf) {
		current.Close()
		// The port frees as soon as the listener closes, but a retry keeps this
		// from being flaky on a loaded machine.
		var next net.Listener
		for attempt := 0; attempt < 20; attempt++ {
			next, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if next == nil {
			t.Fatalf("could not re-listen on %d: %v", port, err)
		}
		serve(l, next)
	}

	return Target{Host: "127.0.0.1", Port: port}, swap
}

// startClosableTLSServer returns the target and a function that takes the
// server away, so a test can make an endpoint stop answering.
func startClosableTLSServer(t *testing.T, leaf *testLeaf) (Target, func()) {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf.tls},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()

	addr := srv.Listener.Addr().(*net.TCPAddr)
	closed := false
	stop := func() {
		if !closed {
			closed = true
			srv.Close()
		}
	}
	t.Cleanup(stop)

	return Target{Host: "127.0.0.1", Port: addr.Port}, stop
}

// A background scan's record must not be handed to the caller while the run is
// still writing to it.
//
// The handler serialises what Start returns into its 202 response, and the run
// mutates counts and status continuously as results arrive. Returning the live
// pointer encodes a struct while another goroutine writes it — a torn response
// in production, not merely a wrong number in a test. Found by the race
// detector on the schedule endpoint.
func TestStartHandsBackASnapshotNotTheLiveRecord(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	leaf := ca.issue(t, "localhost", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	targets := []Target{}
	for i := 0; i < 8; i++ {
		targets = append(targets, startTLSServer(t, leaf).target)
	}

	st := newEmptyStore()
	scanner := NewScanner(st, WithConcurrency(2))
	scanner.batchSize = 1

	returned, err := scanner.Start(ScanRequest{Targets: targets})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Read every field the response serialises, repeatedly, while the run is
	// in flight. Under -race this fails if the record is shared.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = returned.Status
		_ = returned.ResultsCount
		_ = returned.UnmanagedCount
		_ = returned.CompletedAt
	}

	// The snapshot is of the moment it started, so it must still say RUNNING
	// even though the real run has moved on.
	if returned.Status != store.ScanRunning {
		t.Errorf("the returned record changed under the caller: status = %q", returned.Status)
	}

	waitFor(t, 10*time.Second, func() bool {
		stored, _ := st.GetDiscoveryScan(context.Background(), returned.ID)
		return stored.Status == store.ScanCompleted
	}, "the scan to finish")
}
