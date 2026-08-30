package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"golang.org/x/crypto/ocsp"
)

// A two-level hierarchy, because the question this answers only means something
// for an intermediate: "has the authority above me revoked me".
type hierarchy struct {
	rootCert  *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	interCert *x509.Certificate
	rootPEM   string
	interPEM  string
}

func buildHierarchy(t *testing.T) *hierarchy {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Example Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(730 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := x509.ParseCertificate(interDER)

	encode := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return &hierarchy{
		rootCert: rootCert, rootKey: rootKey, interCert: interCert,
		rootPEM: encode(rootDER), interPEM: encode(interDER),
	}
}

// ocspResponder serves a signed answer about the intermediate.
func (h *hierarchy) ocspResponder(t *testing.T, template ocsp.Response) *httptest.Server {
	t.Helper()
	template.SerialNumber = h.interCert.SerialNumber
	if template.ThisUpdate.IsZero() {
		template.ThisUpdate = time.Now().Add(-time.Minute)
	}
	if template.NextUpdate.IsZero() {
		template.NextUpdate = time.Now().Add(time.Hour)
	}
	der, err := ocsp.CreateResponse(h.rootCert, h.rootCert, template, h.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}))
	t.Cleanup(server.Close)
	return server
}

// storeWithHierarchy persists both authorities and returns the intermediate.
func (h *hierarchy) storeWithHierarchy(t *testing.T, st store.Store, responderURL string) *store.CAAuthority {
	t.Helper()
	ctx := context.Background()

	root := &store.CAAuthority{
		Name: "Example Root CA", CAType: "ROOT", SubjectDN: "CN=Example Root CA",
		IssuerDN: "CN=Example Root CA", NotBefore: h.rootCert.NotBefore, NotAfter: h.rootCert.NotAfter,
		KeyType: "ECDSA", KeySize: 256, FingerprintSHA256: "root-fp",
		CertificatePEM: h.rootPEM, Status: "HEALTHY",
	}
	if err := st.CreateCAAuthority(ctx, root); err != nil {
		t.Fatal(err)
	}

	inter := &store.CAAuthority{
		Name: "Example Issuing CA", CAType: "ISSUING", SubjectDN: "CN=Example Issuing CA",
		IssuerDN: "CN=Example Root CA", NotBefore: h.interCert.NotBefore, NotAfter: h.interCert.NotAfter,
		KeyType: "ECDSA", KeySize: 256, FingerprintSHA256: "inter-fp",
		CertificatePEM: h.interPEM, ParentCAID: &root.ID,
		OCSPResponderURL: responderURL, Status: "HEALTHY",
	}
	if err := st.CreateCAAuthority(ctx, inter); err != nil {
		t.Fatal(err)
	}
	return inter
}

// The finding this exists for. An intermediate revoked by its parent makes
// every certificate it ever signed untrustworthy, and nothing here could see it
// before — the old check reported the responder as healthy and stopped.
func TestARevokedIntermediateIsReportedCritical(t *testing.T) {
	h := buildHierarchy(t)
	revokedAt := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	server := h.ocspResponder(t, ocsp.Response{
		Status: ocsp.Revoked, RevokedAt: revokedAt, RevocationReason: ocsp.KeyCompromise,
	})

	st := store.NewMemoryStore()
	t.Cleanup(st.Close)
	inter := h.storeWithHierarchy(t, st, server.URL)

	m := NewCAMonitor(st, nil)
	if err := m.CheckCA(context.Background(), inter); err != nil {
		t.Fatal(err)
	}

	if inter.OCSPStatus != "REVOKED" {
		t.Errorf("ocsp status = %q, want REVOKED", inter.OCSPStatus)
	}
	// Two years of remaining life, and it is still critical. Expiry arithmetic
	// must not overrule a revocation.
	if inter.Status != "CRITICAL" {
		t.Errorf("a revoked CA with two years left = %q, want CRITICAL", inter.Status)
	}
	if inter.OCSPRevokedAt == nil || !inter.OCSPRevokedAt.Equal(revokedAt) {
		t.Errorf("revoked at = %v, want %v", inter.OCSPRevokedAt, revokedAt)
	}
	if !inter.IsOCSPResponsive {
		t.Error("a verified answer was obtained, so the responder is responsive")
	}
}

func TestAGoodAnswerIsRecorded(t *testing.T) {
	h := buildHierarchy(t)
	server := h.ocspResponder(t, ocsp.Response{Status: ocsp.Good})

	st := store.NewMemoryStore()
	t.Cleanup(st.Close)
	inter := h.storeWithHierarchy(t, st, server.URL)

	m := NewCAMonitor(st, nil)
	if err := m.CheckCA(context.Background(), inter); err != nil {
		t.Fatal(err)
	}

	if inter.OCSPStatus != "GOOD" {
		t.Errorf("ocsp status = %q, want GOOD", inter.OCSPStatus)
	}
	if inter.Status != "HEALTHY" {
		t.Errorf("status = %q, want HEALTHY", inter.Status)
	}
	if inter.OCSPLastError != "" {
		t.Errorf("a verified answer should leave no error, got %q", inter.OCSPLastError)
	}
}

// The exact case the old check passed. A web server that knows nothing about
// OCSP used to report the responder as healthy, because the test was
// "status code under 500" against a request with no OCSP in it.
func TestACaptivePortalIsNotAHealthyResponder(t *testing.T) {
	h := buildHierarchy(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Sign in to continue</body></html>"))
	}))
	t.Cleanup(server.Close)

	st := store.NewMemoryStore()
	t.Cleanup(st.Close)
	inter := h.storeWithHierarchy(t, st, server.URL)

	m := NewCAMonitor(st, nil)
	if err := m.CheckCA(context.Background(), inter); err != nil {
		t.Fatal(err)
	}

	if inter.IsOCSPResponsive {
		t.Error("a web server that cannot answer an OCSP request is not a responder")
	}
	if inter.OCSPLastError == "" {
		t.Error("the reason must be recorded; 'not responsive' alone does not tell an operator what to fix")
	}
}

// A responder going down must not un-revoke a CA. Clearing the status on a
// network blip is how a critical finding disappears overnight.
func TestAnUnreachableResponderKeepsThePreviousAnswer(t *testing.T) {
	h := buildHierarchy(t)
	revoked := h.ocspResponder(t, ocsp.Response{Status: ocsp.Revoked, RevokedAt: time.Now().Add(-time.Hour)})

	st := store.NewMemoryStore()
	t.Cleanup(st.Close)
	inter := h.storeWithHierarchy(t, st, revoked.URL)

	m := NewCAMonitor(st, nil)
	if err := m.CheckCA(context.Background(), inter); err != nil {
		t.Fatal(err)
	}
	if inter.OCSPStatus != "REVOKED" {
		t.Fatalf("setup: ocsp status = %q, want REVOKED", inter.OCSPStatus)
	}

	// The responder goes away.
	inter.OCSPResponderURL = "http://127.0.0.1:1/ocsp"
	if err := m.CheckCA(context.Background(), inter); err != nil {
		t.Fatal(err)
	}

	if inter.OCSPStatus != "REVOKED" {
		t.Errorf("an unreachable responder must not clear a revocation, got %q", inter.OCSPStatus)
	}
	// The half that was missing, and that live testing caught. CheckCA
	// recomputes the status from expiry on every sweep, so a revocation
	// recorded once must be re-applied every time — otherwise a CA with two
	// years of life left goes quietly back to HEALTHY the moment its responder
	// blips, while ocsp_status still reads REVOKED and the row disagrees with
	// itself.
	if inter.Status != "CRITICAL" {
		t.Errorf("a known-revoked CA must stay CRITICAL when the responder is unreachable, got %q", inter.Status)
	}
	if inter.IsOCSPResponsive {
		t.Error("an unreachable responder is not responsive")
	}
	if inter.OCSPLastError == "" {
		t.Error("the reason the check failed must be recorded")
	}
}

// A CA with no parent stored cannot be asked about, and the error must say so
// rather than reporting the responder as broken.
func TestAMissingParentIsExplained(t *testing.T) {
	h := buildHierarchy(t)
	server := h.ocspResponder(t, ocsp.Response{Status: ocsp.Good})

	st := store.NewMemoryStore()
	t.Cleanup(st.Close)

	orphan := &store.CAAuthority{
		Name: "Orphaned Issuing CA", CAType: "ISSUING",
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
		// PEM present, but no parent row to verify against.
		CertificatePEM: h.interPEM, OCSPResponderURL: server.URL, Status: "HEALTHY",
	}
	if err := st.CreateCAAuthority(context.Background(), orphan); err != nil {
		t.Fatal(err)
	}

	m := NewCAMonitor(st, nil)
	if err := m.CheckCA(context.Background(), orphan); err != nil {
		t.Fatal(err)
	}

	// Treated as self-signed, so the signature check fails — and that failure
	// is reported rather than silently passing.
	if orphan.IsOCSPResponsive {
		t.Error("a response that cannot be verified must not count as a healthy responder")
	}
}
