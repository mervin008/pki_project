package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ARI implements RFC 9773, ACME Renewal Information.
//
// The CA publishes a window during which it would like each certificate
// replaced. Honouring it matters for two reasons. Routinely, it lets the CA
// spread renewal load and keeps clients from clustering at a fixed offset from
// expiry. In an incident, it is the mechanism by which a CA facing mass
// revocation can pull renewal windows forward and have the ecosystem respond
// over hours instead of a scramble — provided clients are actually listening.
//
// Support is not universally advertised, so every call degrades to "no advice"
// rather than an error: a CA without a renewalInfo endpoint is a normal CA.

// RenewalInfo is the CA's renewal guidance for one certificate.
type RenewalInfo struct {
	// Start and End bound the suggested renewal window.
	Start time.Time
	End   time.Time
	// ExplanationURL is set when the CA wants to explain an unusual window.
	ExplanationURL string
	// RetryAfter is how long the CA asks clients to wait before polling again.
	RetryAfter time.Duration
}

// RenewNow reports whether the current time falls inside the suggested window.
func (r *RenewalInfo) RenewNow() bool {
	if r == nil {
		return false
	}
	now := time.Now()
	return !now.Before(r.Start) && now.Before(r.End)
}

// SelectRenewalTime picks a uniformly random instant inside the suggested
// window.
//
// Picking randomly is the point of the window, not an implementation detail:
// if every client renewed at window start, ARI would move the thundering herd
// rather than disperse it. A window already underway yields a time between now
// and the end, so a client that wakes up late does not wait for the next one.
func (r *RenewalInfo) SelectRenewalTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	start, end := r.Start, r.End
	if now := time.Now(); start.Before(now) {
		start = now
	}
	if !end.After(start) {
		return start
	}

	spread := end.Sub(start)
	return start.Add(time.Duration(rand.Int63n(int64(spread))))
}

// ariClient fetches renewal information, caching the endpoint discovered from
// each ACME directory.
type ariClient struct {
	httpClient *http.Client

	mu        sync.RWMutex
	endpoints map[string]string // directory URL -> renewalInfo URL ("" means unsupported)
}

func newARIClient(httpClient *http.Client) *ariClient {
	return &ariClient{
		httpClient: httpClient,
		endpoints:  make(map[string]string),
	}
}

// errARIUnsupported reports that a CA does not publish renewal information.
var errARIUnsupported = errors.New("CA does not support ACME Renewal Information")

// Fetch retrieves renewal information for a certificate.
//
// It returns errARIUnsupported when the CA has no renewalInfo endpoint or does
// not recognise the certificate, which callers should treat as "fall back to
// lead-time renewal", not as a failure.
func (a *ariClient) Fetch(ctx context.Context, directoryURL string, cert *x509.Certificate) (*RenewalInfo, error) {
	endpoint, err := a.renewalInfoEndpoint(ctx, directoryURL)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, errARIUnsupported
	}

	certID, err := ARICertID(cert)
	if err != nil {
		return nil, err
	}

	url := strings.TrimSuffix(endpoint, "/") + "/" + certID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("renewal info request failed: %w", err)
	}
	defer resp.Body.Close()

	// 404 means this CA did not issue the certificate, or has forgotten it.
	if resp.StatusCode == http.StatusNotFound {
		return nil, errARIUnsupported
	}
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("renewal info returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	var payload struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to decode renewal info: %w", err)
	}

	if payload.SuggestedWindow.Start.IsZero() || payload.SuggestedWindow.End.IsZero() {
		return nil, fmt.Errorf("renewal info response omitted the suggested window")
	}

	info := &RenewalInfo{
		Start:          payload.SuggestedWindow.Start,
		End:            payload.SuggestedWindow.End,
		ExplanationURL: payload.ExplanationURL,
		RetryAfter:     parseRetryAfter(resp.Header.Get("Retry-After")),
	}

	return info, nil
}

// renewalInfoEndpoint reads the renewalInfo field from the ACME directory.
//
// This is fetched directly rather than through the acme package, whose
// Directory type predates RFC 9773 and drops the field.
func (a *ariClient) renewalInfoEndpoint(ctx context.Context, directoryURL string) (string, error) {
	a.mu.RLock()
	endpoint, ok := a.endpoints[directoryURL]
	a.mu.RUnlock()
	if ok {
		return endpoint, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch ACME directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ACME directory returned status %d", resp.StatusCode)
	}

	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return "", fmt.Errorf("failed to decode ACME directory: %w", err)
	}

	a.mu.Lock()
	a.endpoints[directoryURL] = dir.RenewalInfo
	a.mu.Unlock()

	return dir.RenewalInfo, nil
}

// ARICertID builds the certificate identifier RFC 9773 uses to address a
// certificate: the base64url encodings of the Authority Key Identifier and the
// serial number, joined by a dot.
func ARICertID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("certificate is nil")
	}
	if len(cert.AuthorityKeyId) == 0 {
		// Self-signed and some private-CA certificates omit the AKI, and
		// without it there is no way to name the certificate to the CA.
		return "", fmt.Errorf("certificate has no Authority Key Identifier extension, which RFC 9773 requires")
	}

	aki := base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId)
	serial := base64.RawURLEncoding.EncodeToString(derIntegerBytes(cert.SerialNumber))

	return aki + "." + serial, nil
}

// derIntegerBytes renders a serial number as the content octets of a DER
// INTEGER: big-endian, minimal length, with a leading zero byte when the top
// bit would otherwise mark the value negative.
func derIntegerBytes(serial *big.Int) []byte {
	if serial == nil || serial.Sign() == 0 {
		return []byte{0}
	}

	b := serial.Bytes()
	if b[0]&0x80 != 0 {
		return append([]byte{0x00}, b...)
	}
	return b
}

// parseRetryAfter handles both forms the header may take: delta-seconds or an
// HTTP date.
func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}

	if t, err := http.ParseTime(value); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}

	return 0
}
