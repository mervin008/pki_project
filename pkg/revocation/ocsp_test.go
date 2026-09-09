package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &authority{cert: cert, key: key}
}

// issue signs a leaf, which is what the responder will be asked about.
func (ca *authority) issue(t *testing.T, name string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// responder serves whatever bytes the test gives it.
func responder(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func serveDER(der []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	}
}

// signResponse produces a real OCSP response, signed by signer.
func signResponse(t *testing.T, template ocsp.Response, issuer *x509.Certificate, signer *authority, signerCert *x509.Certificate) []byte {
	t.Helper()
	if template.ThisUpdate.IsZero() {
		template.ThisUpdate = time.Now().Add(-time.Minute)
	}
	if template.NextUpdate.IsZero() {
		template.NextUpdate = time.Now().Add(time.Hour)
	}
	der, err := ocsp.CreateResponse(issuer, signerCert, template, signer.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestAGoodResponseVerifies(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	leaf := ca.issue(t, "app.example.test", 42)

	der := signResponse(t, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
	}, ca.cert, ca, ca.cert)
	server := responder(t, serveDER(der))

	result, err := CheckOCSP(context.Background(), server.Client(), leaf, ca.cert, server.URL)
	if err != nil {
		t.Fatalf("a correctly signed response must verify: %v", err)
	}
	if result.Status != StatusGood {
		t.Errorf("status = %q, want GOOD", result.Status)
	}
}

// The answer that matters. A revoked issuing CA makes everything below it
// untrustworthy, and nothing in CertPilot could see it before.
func TestARevokedResponseIsReported(t *testing.T) {
	ca := newCA(t, "Root CA")
	intermediate := ca.issue(t, "Issuing CA", 7)
	revokedAt := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	der := signResponse(t, ocsp.Response{
		Status:           ocsp.Revoked,
		SerialNumber:     intermediate.SerialNumber,
		RevokedAt:        revokedAt,
		RevocationReason: ocsp.KeyCompromise,
	}, ca.cert, ca, ca.cert)
	server := responder(t, serveDER(der))

	result, err := CheckOCSP(context.Background(), server.Client(), intermediate, ca.cert, server.URL)
	if err != nil {
		t.Fatalf("a revoked answer is still a valid answer: %v", err)
	}
	if result.Status != StatusRevoked {
		t.Fatalf("status = %q, want REVOKED", result.Status)
	}
	if result.RevokedAt == nil || !result.RevokedAt.Equal(revokedAt) {
		t.Errorf("revoked at = %v, want %v", result.RevokedAt, revokedAt)
	}
	if result.RevocationReason != ocsp.KeyCompromise {
		t.Errorf("reason = %d, want %d (keyCompromise)", result.RevocationReason, ocsp.KeyCompromise)
	}
}

// The whole reason this package exists. Something answered, and it was not the
// CA — which is a more serious finding than nothing answering at all.
func TestAResponseSignedByTheWrongKeyIsRefused(t *testing.T) {
	real := newCA(t, "Issuing CA")
	impostor := newCA(t, "Issuing CA") // same name, different key
	leaf := real.issue(t, "app.example.test", 42)

	der := signResponse(t, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
	}, impostor.cert, impostor, impostor.cert)
	server := responder(t, serveDER(der))

	if _, err := CheckOCSP(context.Background(), server.Client(), leaf, real.cert, server.URL); err == nil {
		t.Fatal("a response signed by a key the issuer did not authorise must be refused")
	}
}

// A signed, valid response about some other certificate must not be accepted as
// an answer about this one. Parsing without binding to the subject would.
func TestAResponseAboutAnotherCertificateIsRefused(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	asked := ca.issue(t, "app.example.test", 42)
	other := ca.issue(t, "other.example.test", 43)

	der := signResponse(t, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: other.SerialNumber,
	}, ca.cert, ca, ca.cert)
	server := responder(t, serveDER(der))

	if _, err := CheckOCSP(context.Background(), server.Client(), asked, ca.cert, server.URL); err == nil {
		t.Fatal("a response about a different serial must not answer for this certificate")
	}
}

// A signature stays valid long after the statement stops being true. Without a
// freshness check, a "good" response captured before a revocation is convincing
// for ever.
func TestAStaleResponseIsRefused(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	leaf := ca.issue(t, "app.example.test", 42)

	der := signResponse(t, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-48 * time.Hour),
		NextUpdate:   time.Now().Add(-24 * time.Hour),
	}, ca.cert, ca, ca.cert)
	server := responder(t, serveDER(der))

	result, err := CheckOCSP(context.Background(), server.Client(), leaf, ca.cert, server.URL)
	if !errors.Is(err, ErrStale) {
		t.Fatalf("an expired response must be refused as stale, got %v", err)
	}
	// The status is still returned, so a caller can log what the stale answer
	// said rather than only that it was stale.
	if result == nil || result.Status != StatusGood {
		t.Error("a stale response should still report what it claimed")
	}
}

// A responder that omits nextUpdate is generating answers on demand, which RFC
// 6960 permits. Treating that as staleness would break every such responder.
func TestAResponseWithoutNextUpdateIsAccepted(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	leaf := ca.issue(t, "app.example.test", 42)

	der := signResponse(t, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Time{},
	}, ca.cert, ca, ca.cert)
	server := responder(t, serveDER(der))

	if _, err := CheckOCSP(context.Background(), server.Client(), leaf, ca.cert, server.URL); err != nil {
		t.Fatalf("a responder that omits nextUpdate must still be believed: %v", err)
	}
}

// The behaviour this replaced. The old check was a GET with no request in it
// and a `status < 500` test, so a captive portal, a proxy error page, or any
// web server at all reported the responder as healthy.
func TestAnHTMLErrorPageIsNotAnAnswer(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	leaf := ca.issue(t, "app.example.test", 42)

	server := responder(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Sign in to the guest network</body></html>"))
	})

	if _, err := CheckOCSP(context.Background(), server.Client(), leaf, ca.cert, server.URL); err == nil {
		t.Fatal("an HTML page must not be accepted as an OCSP response")
	}
}

func TestANonOKStatusIsAnError(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	leaf := ca.issue(t, "app.example.test", 42)

	server := responder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	if _, err := CheckOCSP(context.Background(), server.Client(), leaf, ca.cert, server.URL); err == nil {
		t.Fatal("HTTP 400 from a responder is not a good answer — the old check treated it as one")
	}
}

// The request must be a real OCSP request, POSTed. The old code sent a bare GET
// with an empty body, which is why any web server passed.
func TestTheRequestIsAWellFormedOCSPPost(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	leaf := ca.issue(t, "app.example.test", 42)

	var method, contentType string
	var parsed *ocsp.Request
	server := responder(t, func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		parsed, _ = ocsp.ParseRequest(body)

		der := signResponse(t, ocsp.Response{Status: ocsp.Good, SerialNumber: leaf.SerialNumber}, ca.cert, ca, ca.cert)
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(der)
	})

	if _, err := CheckOCSP(context.Background(), server.Client(), leaf, ca.cert, server.URL); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if contentType != "application/ocsp-request" {
		t.Errorf("content type = %q, want application/ocsp-request", contentType)
	}
	if parsed == nil {
		t.Fatal("the responder did not receive a parseable OCSP request")
	}
	if parsed.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("asked about serial %v, want %v", parsed.SerialNumber, leaf.SerialNumber)
	}
}

func TestNoResponderURLIsItsOwnError(t *testing.T) {
	ca := newCA(t, "Issuing CA")
	leaf := ca.issue(t, "app.example.test", 42)

	if _, err := CheckOCSP(context.Background(), nil, leaf, ca.cert, ""); !errors.Is(err, ErrNoResponderURL) {
		t.Fatalf("expected ErrNoResponderURL, got %v", err)
	}
}
