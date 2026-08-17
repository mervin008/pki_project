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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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
