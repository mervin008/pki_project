package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/pkg/webhooksig"
)

// TypeWebhook is the generic HTTP deployer.
const TypeWebhook = "webhook"

// DeployEvent is the value of the event header on a deployment delivery, so a
// receiver that also takes alerts can route the two apart without parsing.
const DeployEvent = "cert.deploy"

// reservedHeaders are set by CertPilot and may not come from config. Keyed in
// canonical form, so the lookup and the check agree — the notification webhook
// shipped this check comparing a canonicalised name against a raw constant,
// which matched nothing and silently permitted exactly what it existed to
// prevent.
var reservedHeaders = map[string]bool{
	http.CanonicalHeaderKey(webhooksig.SignatureHeader): true,
	http.CanonicalHeaderKey(webhooksig.TimestampHeader): true,
	http.CanonicalHeaderKey(webhooksig.EventHeader):     true,
	"Content-Type": true,
}

// webhookDeployerConfig is the sealed configuration for a webhook target.
type webhookDeployerConfig struct {
	URL string `json:"url"`
	// SigningSecret is mandatory here, unlike on a notification webhook. See
	// newWebhookDeployer.
	SigningSecret string `json:"signing_secret"`
	// Headers are sent verbatim, for receivers that need an API key or a tenant
	// identifier. Sealed with the rest of the configuration.
	Headers map[string]string `json:"headers,omitempty"`
	// IncludePrivateKey ships the certificate's private key to the receiver.
	// Off unless asked for, explicitly, per target.
	IncludePrivateKey bool `json:"include_private_key,omitempty"`
	// AllowInsecureHTTP permits a plain-http destination.
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
}

// WebhookPayload is the JSON body posted to a deployment receiver.
//
// A stable, documented shape. This is a public integration point — the escape
// hatch that lets CertPilot deploy to anything anybody can write fifteen lines
// of HTTP handler for — and a receiver that has to guess at the schema breaks
// the first time an unrelated field is added.
type WebhookPayload struct {
	Event             string         `json:"event"`
	CertificateID     string         `json:"certificate_id"`
	CommonName        string         `json:"common_name"`
	SANs              []string       `json:"sans,omitempty"`
	SerialNumber      string         `json:"serial_number,omitempty"`
	FingerprintSHA256 string         `json:"fingerprint_sha256"`
	NotBefore         string         `json:"not_before,omitempty"`
	NotAfter          string         `json:"not_after,omitempty"`
	CertificatePEM    string         `json:"certificate_pem"`
	ChainPEM          string         `json:"chain_pem,omitempty"`
	PrivateKeyPEM     string         `json:"private_key_pem,omitempty"`
	Options           map[string]any `json:"options,omitempty"`
	Timestamp         string         `json:"timestamp"`
	Source            string         `json:"source"`
}

type webhookDeployer struct {
	cfg    webhookDeployerConfig
	client *http.Client
}

// newWebhookDeployer validates a webhook target.
//
// Two rules here are stricter than the notification webhook's, and both follow
// from what this endpoint can do rather than from what it carries.
//
// **A signing secret is mandatory.** An unsigned alert webhook means a receiver
// might act on a fabricated alert, which is a nuisance. An unsigned deployment
// webhook means anyone who can reach the receiver can install a certificate on
// whatever it feeds — their certificate, their key, your hostname. Signing is
// what makes the receiver able to tell CertPilot from anybody else on the
// network, and there is no configuration in which not having it is reasonable.
//
// **Private keys do not travel over plaintext HTTP off the machine.** http is
// permitted at all only for receivers on a trusted network that cannot offer
// TLS; sending key material that way puts the key on the wire in the clear, for
// the length of the network. The exception is a loopback address, where there
// is no wire — that is the local-agent case, and refusing it would rule out the
// one deployment topology where plaintext is genuinely harmless.
func newWebhookDeployer(config map[string]any) (Deployer, error) {
	cfg := webhookDeployerConfig{
		URL:               configString(config, "url"),
		SigningSecret:     configString(config, "signing_secret"),
		Headers:           configStringMap(config, "headers"),
		IncludePrivateKey: configBool(config, "include_private_key"),
		AllowInsecureHTTP: configBool(config, "allow_insecure_http"),
	}

	if cfg.URL == "" {
		return nil, missingField(TypeWebhook, "url", "the receiver that installs the certificate")
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("url is not valid: %w", err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("url has no host")
	}

	loopback := isLoopbackHost(parsed.Hostname())
	switch parsed.Scheme {
	case "https":
	case "http":
		if !cfg.AllowInsecureHTTP {
			return nil, fmt.Errorf(
				"url must be https; set allow_insecure_http if the receiver is on a trusted network and cannot offer TLS")
		}
		if cfg.IncludePrivateKey && !loopback {
			return nil, fmt.Errorf(
				"include_private_key cannot be combined with a plain-http url to %s: the private key would cross the network in the clear. Use https, or a receiver on this host",
				parsed.Hostname())
		}
	default:
		return nil, fmt.Errorf("url scheme %q is not supported; use https", parsed.Scheme)
	}

	if cfg.SigningSecret == "" {
		return nil, missingField(TypeWebhook, "signing_secret",
			"a shared secret of at least 16 characters. Without it the receiver cannot tell a certificate from CertPilot apart from one sent by anybody else who can reach it")
	}
	if len(cfg.SigningSecret) < 16 {
		return nil, fmt.Errorf("signing_secret should be at least 16 characters; a short one is not worth the false confidence")
	}

	// Rejected rather than silently dropped: an operator who set the signature
	// header by hand believes their receiver is verifying something.
	for _, name := range sortedKeys(cfg.Headers) {
		if reservedHeaders[http.CanonicalHeaderKey(name)] {
			return nil, fmt.Errorf("header %q is set by CertPilot and cannot be overridden", name)
		}
		if strings.ContainsAny(cfg.Headers[name], "\r\n") {
			return nil, fmt.Errorf("header %q contains a line break", name)
		}
	}

	return &webhookDeployer{cfg: cfg, client: defaultClient()}, nil
}

// isLoopbackHost reports whether a host refers to this machine.
//
// Names are matched literally rather than resolved: a DNS lookup at
// configuration time says nothing about what the name will resolve to when the
// deployment actually runs, and treating "internal.example.com" as loopback
// because it happens to point at 127.0.0.1 today is how a private key ends up
// on the wire tomorrow.
func isLoopbackHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

func (w *webhookDeployer) Type() string { return TypeWebhook }

// Describe names the receiver without its query string, which is where an
// endpoint's own token is usually hidden.
func (w *webhookDeployer) Describe() string {
	if parsed, err := url.Parse(w.cfg.URL); err == nil {
		return parsed.Scheme + "://" + parsed.Host + parsed.Path
	}
	return w.cfg.URL
}

func (w *webhookDeployer) NeedsPrivateKey() bool { return w.cfg.IncludePrivateKey }

func (w *webhookDeployer) Deploy(ctx context.Context, b Bundle) (string, error) {
	payload := WebhookPayload{
		Event:             DeployEvent,
		CertificateID:     b.CertificateID,
		CommonName:        b.CommonName,
		SANs:              b.SANs,
		SerialNumber:      b.SerialNumber,
		FingerprintSHA256: b.FingerprintSHA256,
		CertificatePEM:    b.CertificatePEM,
		ChainPEM:          b.ChainPEM,
		Options:           b.Options,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
		Source:            "certpilot",
	}
	if !b.NotBefore.IsZero() {
		payload.NotBefore = b.NotBefore.UTC().Format(time.RFC3339)
	}
	if !b.NotAfter.IsZero() {
		payload.NotAfter = b.NotAfter.UTC().Format(time.RFC3339)
	}
	// Only when the target asked for it. The executor will not have fetched a
	// key otherwise, but the check is here too: this is the last line before
	// key material becomes an HTTP body, and it should not depend on a caller
	// elsewhere having got it right.
	if w.cfg.IncludePrivateKey {
		payload.PrivateKeyPEM = b.PrivateKeyPEM
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("could not encode the deployment payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhooksig.EventHeader, DeployEvent)
	for name, value := range w.cfg.Headers {
		req.Header.Set(name, value)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set(webhooksig.TimestampHeader, ts)
	req.Header.Set(webhooksig.SignatureHeader, webhooksig.Sign(w.cfg.SigningSecret, ts, body))

	resp, err := w.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", w.Describe(), err)
	}
	defer resp.Body.Close()

	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	summary := strings.Join(strings.Fields(string(detail)), " ")
	if len(summary) > 200 {
		summary = summary[:200] + "…"
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if summary == "" {
			summary = "no detail"
		}
		return "", fmt.Errorf("%s returned %d: %s", w.Describe(), resp.StatusCode, summary)
	}

	// Named, not congratulated. What was sent where, so the attempt log is
	// something a person can check rather than a reassurance.
	out := fmt.Sprintf("%s accepted %s (%s)", w.Describe(), shortFingerprint(b.FingerprintSHA256), b.CommonName)
	if summary != "" {
		out += ": " + summary
	}
	return out, nil
}

// shortFingerprint renders enough of a fingerprint to compare by eye.
func shortFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "…"
}
