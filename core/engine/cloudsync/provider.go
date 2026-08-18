// Package cloudsync inventories certificates that are stored rather than
// served.
//
// This is the third place certificates hide, and the one the other two cannot
// reach. A network scan finds what is being served on addresses somebody
// thought to give it. Certificate Transparency finds what a publicly-trusted CA
// issued. Neither finds a certificate sitting in ACM, in a Key Vault, in a GCP
// load balancer, or in a Kubernetes secret — attached to an address nobody
// scanned, or attached to nothing at all.
//
// The finding this package exists for is not "here is another certificate". It
// is that **cloud certificate stores do not renew everything in them, and
// everybody believes they do**:
//
//   - An ACM certificate that was imported is never renewed by AWS. AWS says so
//     plainly, in a field almost nobody reads: RenewalEligibility INELIGIBLE.
//   - A GCP SELF_MANAGED SSL certificate was uploaded once and is renewed by
//     nobody. Its MANAGED neighbour in the same list is renewed by Google.
//   - A Key Vault certificate whose issuer is "Unknown" was imported as a PFX
//     and has no issuance policy that could renew it.
//   - A Kubernetes kubernetes.io/tls secret with no cert-manager owner was
//     created by hand by somebody who may well have left.
//
// On each provider's own console, all four look exactly like the ones that do
// renew themselves.
package cloudsync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Asset is one certificate an inventory holds, in the provider's own terms.
//
// Deliberately not a store model: a provider reports what it knows, and
// deciding what that means — managed or not, renewed or not, worth an alert or
// not — happens in one place afterwards, so four providers cannot drift into
// four different definitions of the same verdict.
type Asset struct {
	// ResourceID is the provider's own identifier: an ARN, a Key Vault
	// certificate id, a GCP self-link, a namespace/name. It has to be stable
	// across syncs, because it is what makes the second sync an update.
	ResourceID string
	Name       string
	// Location is region, vault, or cluster — the first thing somebody needs in
	// order to go and look at it.
	Location string

	// CertificatePEM is the leaf. Providers that do not return the certificate
	// body leave it empty, and the record is then built from metadata alone —
	// which is worth saying out loud, because without the certificate there is
	// no fingerprint and therefore no reliable verdict.
	CertificatePEM string

	// RenewalMode is the provider's own word — "IMPORTED", "SELF_MANAGED",
	// "AutoRenew", "cert-manager". Kept verbatim rather than reduced to a
	// boolean, because that word is what somebody has to go and find in their
	// own console.
	RenewalMode string
	// WillRenew is whether the provider itself renews this. Nil means the
	// provider did not say, which is not the same as no.
	WillRenew *bool

	// Attached reports whether anything is using it. Nil means the provider
	// could not be asked — a Key Vault has no notion of attachment at all — and
	// that is deliberately distinct from false, which means nothing is using it
	// and nobody will notice when it expires.
	Attached   *bool
	AttachedTo []string

	// Disabled marks an asset the provider itself has switched off.
	Disabled bool
}

// Provider enumerates one place certificates are stored.
type Provider interface {
	// Type is the stored provider identifier, e.g. "aws_acm".
	Type() string
	// Describe names this connection on screen and in errors — an account id, a
	// vault URL, a cluster address. Never a credential.
	Describe() string
	// Scopes names what Inventory will enumerate, in the provider's own words.
	//
	// Recorded on every successful sync and shown next to the results. A cloud
	// account has several places a certificate can sit, and a tool that covers
	// one of them while presenting itself as covering the provider commits this
	// product's original sin in a new place: a short list that reads as a small
	// estate when it is really a narrow search.
	Scopes() []string
	// Inventory returns everything the connection can see.
	//
	// An error means nothing was learned. Returning a partial list with a nil
	// error would be the worst possible outcome — it is indistinguishable from
	// an account that really does hold only those certificates.
	Inventory(ctx context.Context) ([]Asset, error)
}

// Providers lists the supported provider identifiers.
func Providers() []string {
	return []string{"aws_acm", "azure_key_vault", "gcp", "kubernetes"}
}

// ValidateConfig checks a provider configuration and returns it as the JSON
// that will be sealed.
//
// Validation happens before the credentials are encrypted, so a typo is a 400
// at creation rather than a sync failure six hours later that reads like an
// outage.
func ValidateConfig(providerType string, config map[string]any) ([]byte, error) {
	if _, err := build(providerType, config); err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

// Build constructs a provider from its sealed-and-opened configuration.
func Build(providerType string, rawConfig []byte) (Provider, error) {
	var config map[string]any
	if len(rawConfig) > 0 {
		if err := json.Unmarshal(rawConfig, &config); err != nil {
			return nil, fmt.Errorf("stored configuration for this %s connection is not valid JSON: %w", providerType, err)
		}
	}
	return build(providerType, config)
}

func build(providerType string, config map[string]any) (Provider, error) {
	switch providerType {
	case "aws_acm":
		return newACM(config)
	case "azure_key_vault":
		return newKeyVault(config)
	case "gcp":
		return newGCP(config)
	case "kubernetes":
		return newKubernetes(config)
	default:
		return nil, fmt.Errorf("unknown cloud provider %q; supported: %s",
			providerType, strings.Join(Providers(), ", "))
	}
}

// ── configuration helpers ───────────────────────────────────

func configString(config map[string]any, key string) string {
	if config == nil {
		return ""
	}
	v, ok := config[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func configBool(config map[string]any, key string) bool {
	if config == nil {
		return false
	}
	b, _ := config[key].(bool)
	return b
}

func configStrings(config map[string]any, key string) []string {
	if config == nil {
		return nil
	}
	raw, ok := config[key]
	if !ok || raw == nil {
		return nil
	}
	out := []string{}
	switch v := raw.(type) {
	case []string:
		out = append(out, v...)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case string:
		for _, s := range strings.Split(v, ",") {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	sort.Strings(out)
	return out
}

// missingField builds the one error message worth reading: which field, for
// which provider, and what it is for.
func missingField(provider, field, purpose string) error {
	return fmt.Errorf("a %s connection needs %q (%s)", provider, field, purpose)
}

// ── HTTP helpers ────────────────────────────────────────────

// defaultHTTPTimeout bounds one API call. Cloud control planes are usually
// fast; one that is not must not hold a sync open indefinitely, because a sync
// that never finishes is a connection that silently stops watching.
const defaultHTTPTimeout = 30 * time.Second

func defaultClient() *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout}
}

// doJSON performs a request and decodes a JSON body, turning a non-2xx into an
// error carrying the provider's own words.
//
// The provider's words matter more than a status code here. "The security token
// included in the request is expired" tells somebody what to do; "403" starts
// an investigation.
func doJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return fmt.Errorf("%s did not answer within the time allowed; nothing was read from it", req.URL.Host)
		}
		return fmt.Errorf("calling %s: %w", req.URL.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s answered %d: %s", req.URL.Host, resp.StatusCode, readableBody(resp.Body))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		// Reported rather than swallowed into an empty result: "the API changed
		// shape" and "this account holds no certificates" are opposite
		// conclusions and only one of them is an all-clear.
		return fmt.Errorf("%s returned something that is not the expected JSON: %w", req.URL.Host, err)
	}
	return nil
}
