package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxResponseBytes bounds what is read from Vault.
//
// A CA chain is a few kilobytes and a CRL is not fetched here, so anything
// approaching this is a misconfiguration pointing at something that is not
// Vault. Reading it all into memory first would be the expensive way to find
// that out.
const maxResponseBytes = 8 << 20

// response is the envelope Vault wraps every reply in.
type response struct {
	Data     json.RawMessage `json:"data"`
	Auth     *authInfo       `json:"auth"`
	Warnings []string        `json:"warnings"`
}

// apiError is a non-2xx reply from Vault.
//
// It carries the status because the status is what decides retry behaviour,
// and the messages because Vault's are unusually good — the CA-expiry refusal
// this gateway translates is one of them.
type apiError struct {
	Status   int
	Path     string
	Messages []string
}

func (e *apiError) Error() string {
	if len(e.Messages) == 0 {
		return fmt.Sprintf("Vault returned %d for %s", e.Status, e.Path)
	}
	return fmt.Sprintf("Vault returned %d for %s: %s", e.Status, e.Path, strings.Join(e.Messages, "; "))
}

// message joins the messages Vault gave, for matching against known refusals.
func (e *apiError) message() string { return strings.ToLower(strings.Join(e.Messages, " ")) }

func asAPIError(err error) (*apiError, bool) {
	var ve *apiError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}

// transports caches one HTTP client per distinct TLS configuration.
//
// Building a transport per request would mean a fresh TLS handshake for every
// certificate issued — and on a fleet renewing thousands, the handshakes cost
// more than the issuance.
type transports struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

func newTransports() *transports {
	return &transports{clients: map[string]*http.Client{}}
}

func (t *transports) get(cfg *Config) (*http.Client, error) {
	key := fmt.Sprintf("%t|%d|%s", cfg.TLSSkipVerify, cfg.RequestTimeoutSeconds, cfg.CACertPEM)

	t.mu.Lock()
	defer t.mu.Unlock()
	if client, ok := t.clients[key]; ok {
		return client, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSSkipVerify {
		// Deliberately explicit rather than reached through a helper. This is
		// the line that decides whether the Vault token is protected, and it
		// should be visible to anyone reading the file.
		tlsCfg.InsecureSkipVerify = true
	}
	if strings.TrimSpace(cfg.CACertPEM) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, fmt.Errorf("ca_cert_pem does not contain a certificate")
		}
		tlsCfg.RootCAs = pool
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	client := &http.Client{Transport: transport, Timeout: cfg.RequestTimeout()}
	t.clients[key] = client
	return client, nil
}

// send performs one HTTP call to Vault and returns the raw reply.
//
// Separate from the decoding because Vault does not have one reply shape.
// Reading a path returns its contents wrapped in `data`; sys/health returns
// Vault's own state at the top level; a login returns it under `auth`.
func (p *Provider) send(
	ctx context.Context, cfg *Config, method, path, token string, body any,
) ([]byte, error) {
	client, err := p.transports.get(cfg)
	if err != nil {
		return nil, err
	}

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, cfg.Address+path, payload)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", cfg.Namespace)
	}
	req.Header.Set("User-Agent", "certpilot-vault-gateway/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach Vault at %s: %w", cfg.Address, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("could not read Vault's reply to %s: %w", path, err)
	}
	if resp.StatusCode >= 300 {
		return raw, &apiError{Status: resp.StatusCode, Path: path, Messages: decodeErrors(raw)}
	}
	return raw, nil
}

// request performs one call whose reply is wrapped in Vault's data envelope.
//
// out may be nil when the reply is not needed. Warnings are returned rather
// than logged here, because whether a warning matters depends on the caller —
// "TTL truncated" is noise on a health check and the whole story on an issue.
func (p *Provider) request(
	ctx context.Context, cfg *Config, method, path, token string, body any, out any,
) (warnings []string, err error) {
	raw, err := p.send(ctx, cfg, method, path, token, body)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}

	var envelope response
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("Vault's reply to %s is not JSON — is %s really a Vault? %w", path, cfg.Address, err)
	}
	if out != nil && len(envelope.Data) > 0 {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return envelope.Warnings, fmt.Errorf("could not read the data Vault returned from %s: %w", path, err)
		}
	}
	if auth, ok := out.(*authInfo); ok && envelope.Auth != nil {
		*auth = *envelope.Auth
	}
	return envelope.Warnings, nil
}

// requestTop performs a call whose reply is not wrapped in a data envelope.
//
// sys/health is Vault reporting on itself rather than returning the contents
// of a path, so its fields sit at the top level. Reading it through the
// envelope decoded nothing at all and left a zero value behind — which meant a
// Vault that was up, unsealed and answering was reported as not initialized,
// and every CA account pointed at a real Vault failed validation. A fake that
// wraps every reply the same way cannot catch this.
func (p *Provider) requestTop(
	ctx context.Context, cfg *Config, method, path, token string, out any,
) error {
	raw, err := p.send(ctx, cfg, method, path, token, nil)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("could not read Vault's reply to %s: %w", path, err)
	}
	return nil
}

// call performs an authenticated request, obtaining a token first.
//
// A cached token that Vault refuses is discarded and the call is retried once
// with a fresh login. Without this the gateway works perfectly until the token
// reaches its TTL — typically weeks later, unattended, at renewal time.
func (p *Provider) call(
	ctx context.Context, cfg *Config, method, path string, body any, out any,
) ([]string, error) {
	token, fresh, err := p.token(ctx, cfg)
	if err != nil {
		return nil, err
	}

	warnings, err := p.request(ctx, cfg, method, path, token, body, out)
	if err == nil {
		return warnings, nil
	}

	ve, ok := asAPIError(err)
	if !ok || ve.Status != http.StatusForbidden || fresh || !canReauthenticate(cfg) {
		return warnings, err
	}

	p.tokens.forget(cfg.identity())
	token, _, err = p.token(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return p.request(ctx, cfg, method, path, token, body, out)
}

// canReauthenticate reports whether this gateway can obtain a new token
// without an operator. A token supplied in the configuration cannot be
// replaced by anything the gateway knows.
func canReauthenticate(cfg *Config) bool {
	return cfg.AuthMethod == AuthAppRole || cfg.AuthMethod == AuthKubernetes
}

// decodeErrors pulls the messages out of Vault's error shape, falling back to
// the raw body when it is not the expected shape — which is what a proxy or a
// login page in front of Vault returns.
func decodeErrors(raw []byte) []string {
	var body struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && len(body.Errors) > 0 {
		return body.Errors
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil
	}
	if len(text) > 400 {
		text = text[:400] + "…"
	}
	return []string{text}
}

// deadline applies the configured per-request bound on top of whatever the
// caller allowed, so one wedged Vault cannot hold a gRPC handler open for the
// core's whole call timeout.
func deadline(ctx context.Context, cfg *Config) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, cfg.RequestTimeout()+5*time.Second)
}
