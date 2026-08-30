// Package revocation asks a certificate authority whether a certificate is
// still valid, and believes the answer only when it is signed.
//
// The distinction matters more than it sounds. Reaching an OCSP responder and
// getting an HTTP 200 says a web server is running at that address; it says
// nothing whatever about the certificate. A responder that has been replaced,
// a captive portal, a proxy returning a friendly error page, or a plain
// misconfiguration all produce a perfectly good HTTP response. Only the
// signature over the response ties the answer to the CA that is entitled to
// give it.
package revocation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Status is what the responder said about the certificate.
type Status string

const (
	// StatusGood means the responder affirmatively said the certificate is not
	// revoked. It is not the same as "we could not find out".
	StatusGood Status = "GOOD"
	// StatusRevoked means the CA has revoked it. For a CA certificate this is
	// the most serious thing this package can report: everything below it in
	// the hierarchy is untrustworthy from that moment.
	StatusRevoked Status = "REVOKED"
	// StatusUnknown means the responder does not know about this certificate.
	// Usually a responder that does not serve this issuer, which is a
	// configuration error rather than good news.
	StatusUnknown Status = "UNKNOWN"
)

// maxResponseSize bounds what will be read from a responder.
//
// An OCSP response for one certificate is a few kilobytes. Anything remotely
// near this is not one, and reading an unbounded body from a host named in a
// certificate's AIA extension is a way to be told how much memory to allocate
// by whoever issued the certificate.
const maxResponseSize = 1 << 20

// ErrNoResponderURL reports that there is nowhere to ask.
var ErrNoResponderURL = errors.New("revocation: the certificate names no OCSP responder")

// Result is a verified answer.
type Result struct {
	Status Status
	// ProducedAt, ThisUpdate and NextUpdate are the responder's own account of
	// how current this answer is. NextUpdate is zero when the responder omits
	// it, which RFC 6960 permits and means newer information is always
	// available — so it is not treated as staleness.
	ProducedAt time.Time
	ThisUpdate time.Time
	NextUpdate time.Time
	// RevokedAt and RevocationReason are set only when Status is REVOKED.
	RevokedAt        *time.Time
	RevocationReason int
	// SignedByDelegate records that the response was signed by a delegated
	// responder certificate rather than by the issuing CA itself. Both are
	// legitimate; an operator reading a surprising answer wants to know which.
	SignedByDelegate bool
}

// CheckOCSP asks responderURL whether subject is revoked, and verifies the
// answer against issuer.
//
// The verification is the point. ocsp.ParseResponseForCert checks three things
// that a bare fetch cannot: that the response is signed by the issuer or by a
// responder the issuer delegated to with the OCSPSigning extended key usage,
// that the signature is valid, and that the response is about the certificate
// that was asked about rather than some other one.
func CheckOCSP(ctx context.Context, client *http.Client, subject, issuer *x509.Certificate, responderURL string) (*Result, error) {
	if responderURL == "" {
		return nil, ErrNoResponderURL
	}
	if subject == nil || issuer == nil {
		return nil, errors.New("revocation: both the certificate and its issuer are needed to ask about revocation")
	}
	if client == nil {
		client = http.DefaultClient
	}

	// SHA-1, and deliberately.
	//
	// This hash identifies the issuer by name and public key inside the
	// request; it is not a signature and nothing is authenticated by it. RFC
	// 6960 defines SHA-1 here and responders index their databases by it, so a
	// SHA-256 request is widely answered with "unauthorized" or "unknown" —
	// which would look exactly like a revocation problem. The security of the
	// exchange rests entirely on the signature over the *response*.
	request, err := ocsp.CreateRequest(subject, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, fmt.Errorf("revocation: could not build an OCSP request: %w", err)
	}

	// POST rather than GET. The base64-in-the-path GET form of RFC 6960 exists
	// for cacheability and is limited to 255 bytes of request; POST is accepted
	// by every responder and has no such limit. The old check here was a GET
	// with no request in it at all, which any HTTP server answers.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responderURL, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("revocation: could not reach the OCSP responder at %s: %w", responderURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("revocation: the OCSP responder at %s answered HTTP %d", responderURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("revocation: could not read the OCSP response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, fmt.Errorf("revocation: the OCSP responder at %s returned more than %d bytes, which is not an OCSP response",
			responderURL, maxResponseSize)
	}

	parsed, err := ocsp.ParseResponseForCert(body, subject, issuer)
	if err != nil {
		// Deliberately not softened into "responder unavailable". A response
		// that does not verify is a more serious finding than no response at
		// all: something answered, and it was not the CA.
		return nil, fmt.Errorf("revocation: the OCSP response from %s did not verify against the issuing CA: %w",
			responderURL, err)
	}

	result := &Result{
		ProducedAt: parsed.ProducedAt,
		ThisUpdate: parsed.ThisUpdate,
		NextUpdate: parsed.NextUpdate,
		// A delegated responder carries its own certificate in the response.
		// ParseResponseForCert has already checked it chains to the issuer and
		// carries the OCSPSigning EKU; this only records which happened.
		SignedByDelegate: parsed.Certificate != nil,
	}

	switch parsed.Status {
	case ocsp.Good:
		result.Status = StatusGood
	case ocsp.Revoked:
		result.Status = StatusRevoked
		revokedAt := parsed.RevokedAt
		result.RevokedAt = &revokedAt
		result.RevocationReason = parsed.RevocationReason
	default:
		result.Status = StatusUnknown
	}

	// Freshness, last, so the status above is available to a caller that wants
	// to log what a stale response said.
	if err := result.checkFreshness(time.Now()); err != nil {
		return result, err
	}
	return result, nil
}

// ErrStale reports a response the responder itself says is out of date.
var ErrStale = errors.New("revocation: the OCSP response is no longer current")

// checkFreshness rejects a response outside its own validity window.
//
// Without this, a signed "good" response captured before a certificate was
// revoked stays convincing for ever — the signature keeps verifying long after
// the statement stops being true. It is the same failure as trusting an expired
// certificate because the signature on it is still valid.
func (r *Result) checkFreshness(now time.Time) error {
	// A small tolerance for clock skew between here and the responder, in the
	// same spirit as the leeway on token expiry. Without it a responder whose
	// clock is a few seconds ahead produces an answer that is not yet valid.
	const skew = 5 * time.Minute

	if r.ThisUpdate.IsZero() {
		return fmt.Errorf("%w: it carries no thisUpdate, so there is no way to tell how old it is", ErrStale)
	}
	if r.ThisUpdate.After(now.Add(skew)) {
		return fmt.Errorf("%w: it claims to have been produced at %s, which is in the future",
			ErrStale, r.ThisUpdate.Format(time.RFC3339))
	}
	// A zero NextUpdate is not staleness. RFC 6960 says its absence means newer
	// information is always available, which is what a responder generating
	// answers on demand does.
	if !r.NextUpdate.IsZero() && r.NextUpdate.Before(now.Add(-skew)) {
		return fmt.Errorf("%w: it expired at %s and the responder has not published a newer one",
			ErrStale, r.NextUpdate.Format(time.RFC3339))
	}
	return nil
}
