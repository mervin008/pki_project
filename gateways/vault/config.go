package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Authentication methods this gateway can use to reach Vault.
const (
	AuthToken      = "token"
	AuthAppRole    = "approle"
	AuthKubernetes = "kubernetes"
)

// Defaults that match a stock Vault installation.
const (
	DefaultMount           = "pki"
	DefaultAppRoleMount    = "approle"
	DefaultKubernetesMount = "kubernetes"
	// DefaultKubernetesJWTPath is where the kubelet projects a pod's service
	// account token. Reading it is how a gateway running in the cluster proves
	// which workload it is without holding a secret of its own.
	DefaultKubernetesJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultRequestTimeout    = 30 * time.Second
)

// Config is the per-CA-account configuration the core sends with each request.
//
// It arrives as the provider_config JSON field, is stored encrypted by the
// core, and is decrypted only to populate one call. It carries a Vault
// credential, so it is never logged.
type Config struct {
	// Address is the Vault API endpoint, e.g. https://vault.internal:8200.
	Address string `json:"address"`
	// Namespace selects a Vault Enterprise namespace. Empty on Community.
	Namespace string `json:"namespace,omitempty"`
	// Mount is the path the PKI secrets engine is mounted at.
	Mount string `json:"mount,omitempty"`
	// Role is the PKI role that constrains what may be issued. Required,
	// because issuing without one means issuing without constraints.
	Role string `json:"role"`
	// IssuerRef pins issuance to one issuer by name or ID. When empty, Vault
	// uses the mount's default issuer — which moves when the default is
	// changed, so pin it if you care which CA signs.
	IssuerRef string `json:"issuer_ref,omitempty"`

	// AuthMethod is token, approle, or kubernetes. Inferred from whichever
	// credential fields are present when empty.
	AuthMethod string `json:"auth_method,omitempty"`

	// Token is a Vault token supplied directly. Convenient, and the weakest
	// option for unattended work: it cannot be renewed past its maximum TTL,
	// and when it expires every renewal in the estate stops at once.
	Token string `json:"token,omitempty"`

	// RoleID and SecretID are AppRole credentials. The gateway logs in with
	// them and keeps the resulting token alive.
	RoleID       string `json:"role_id,omitempty"`
	SecretID     string `json:"secret_id,omitempty"`
	AppRoleMount string `json:"approle_mount,omitempty"`

	// KubernetesRole is the Vault role bound to this gateway's service
	// account. The credential is the projected token, so there is no secret in
	// this configuration at all — the best of the three.
	KubernetesRole    string `json:"kubernetes_role,omitempty"`
	KubernetesMount   string `json:"kubernetes_mount,omitempty"`
	KubernetesJWTPath string `json:"kubernetes_jwt_path,omitempty"`

	// CACertPEM verifies Vault's own TLS certificate, for the ordinary case of
	// a Vault fronted by an internal CA.
	CACertPEM string `json:"ca_cert_pem,omitempty"`
	// TLSSkipVerify disables that verification.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`

	// TTL is the requested validity, as a Go duration string ("720h"). The
	// role's own ttl applies when empty, and the role's max_ttl caps it either
	// way.
	TTL string `json:"ttl,omitempty"`

	// RequestTimeoutSeconds bounds one call to Vault.
	RequestTimeoutSeconds int `json:"request_timeout_seconds,omitempty"`
}

// ParseConfig decodes the provider_config JSON and applies defaults.
//
// defaultAddress and defaultNamespace come from the gateway's own flags, so a
// deployment that talks to one Vault does not repeat its address in every CA
// account.
func ParseConfig(raw, defaultAddress, defaultNamespace string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), cfg); err != nil {
			return nil, fmt.Errorf("invalid provider configuration JSON: %w", err)
		}
	}

	cfg.Address = strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if cfg.Address == "" {
		cfg.Address = strings.TrimRight(strings.TrimSpace(defaultAddress), "/")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = strings.TrimSpace(defaultNamespace)
	}
	cfg.Namespace = strings.Trim(cfg.Namespace, "/")

	cfg.Mount = strings.Trim(strings.TrimSpace(cfg.Mount), "/")
	if cfg.Mount == "" {
		cfg.Mount = DefaultMount
	}
	cfg.Role = strings.TrimSpace(cfg.Role)
	cfg.IssuerRef = strings.TrimSpace(cfg.IssuerRef)

	cfg.AuthMethod = strings.ToLower(strings.TrimSpace(cfg.AuthMethod))
	if cfg.AuthMethod == "" {
		cfg.AuthMethod = inferAuthMethod(cfg)
	}
	if cfg.AppRoleMount = strings.Trim(strings.TrimSpace(cfg.AppRoleMount), "/"); cfg.AppRoleMount == "" {
		cfg.AppRoleMount = DefaultAppRoleMount
	}
	if cfg.KubernetesMount = strings.Trim(strings.TrimSpace(cfg.KubernetesMount), "/"); cfg.KubernetesMount == "" {
		cfg.KubernetesMount = DefaultKubernetesMount
	}
	if cfg.KubernetesJWTPath = strings.TrimSpace(cfg.KubernetesJWTPath); cfg.KubernetesJWTPath == "" {
		cfg.KubernetesJWTPath = DefaultKubernetesJWTPath
	}

	return cfg, nil
}

// inferAuthMethod picks a method from whichever credential was supplied.
//
// Order matters only when a configuration contains more than one, which is
// itself a mistake; Validate reports it rather than letting this choice decide
// quietly which credential is live.
func inferAuthMethod(cfg *Config) string {
	switch {
	case cfg.RoleID != "" || cfg.SecretID != "":
		return AuthAppRole
	case cfg.KubernetesRole != "":
		return AuthKubernetes
	default:
		return AuthToken
	}
}

// Validate reports configuration problems as messages an operator can act on.
func (c *Config) Validate() (errs []string, warnings []string) {
	switch {
	case c.Address == "":
		errs = append(errs, "address is required: the Vault API endpoint, e.g. https://vault.internal:8200")
	default:
		if err := checkAddress(c.Address); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if c.Role == "" {
		errs = append(errs,
			"role is required: the PKI role that constrains which names and key types may be issued. Issuing without a role means issuing without constraints")
	}

	switch c.AuthMethod {
	case AuthToken:
		if c.Token == "" {
			errs = append(errs, "token is required when auth_method is token")
		}
		warnings = append(warnings,
			"auth_method is token: a static token cannot outlive its maximum TTL, and when it expires every renewal through this account fails at once. approle or kubernetes survive unattended")
	case AuthAppRole:
		if c.RoleID == "" {
			errs = append(errs, "role_id is required when auth_method is approle")
		}
		if c.SecretID == "" {
			errs = append(errs, "secret_id is required when auth_method is approle")
		}
	case AuthKubernetes:
		if c.KubernetesRole == "" {
			errs = append(errs, "kubernetes_role is required when auth_method is kubernetes")
		}
	default:
		errs = append(errs, fmt.Sprintf(
			"unsupported auth_method %q (supported: token, approle, kubernetes)", c.AuthMethod))
	}

	// More than one credential is not a preference to be resolved silently.
	// Whichever this gateway picked, the other is a live credential sitting in
	// a configuration where nobody is watching it expire or rotate.
	supplied := []string{}
	if c.Token != "" {
		supplied = append(supplied, "token")
	}
	if c.RoleID != "" || c.SecretID != "" {
		supplied = append(supplied, "role_id/secret_id")
	}
	if c.KubernetesRole != "" {
		supplied = append(supplied, "kubernetes_role")
	}
	if len(supplied) > 1 {
		warnings = append(warnings, fmt.Sprintf(
			"credentials for more than one auth method are present (%s); only %s is used",
			strings.Join(supplied, ", "), c.AuthMethod))
	}

	if c.TLSSkipVerify {
		if c.CACertPEM != "" {
			errs = append(errs,
				"ca_cert_pem and tls_skip_verify are both set: one supplies the CA that verifies Vault, the other says not to verify it. Remove tls_skip_verify")
		} else {
			warnings = append(warnings,
				"tls_skip_verify is set: anything that can intercept this connection can take the Vault credential and return a certificate from a CA of its choosing")
		}
	}

	if c.TTL != "" {
		if _, err := time.ParseDuration(c.TTL); err != nil {
			errs = append(errs, fmt.Sprintf("ttl %q is not a duration; use a form like 720h or 90m", c.TTL))
		}
	}

	if c.IssuerRef == "" {
		warnings = append(warnings,
			"issuer_ref is not set, so this account signs with whichever issuer is currently the mount's default. Rotating the default silently changes which CA signs your certificates")
	}

	return errs, warnings
}

// checkAddress refuses an endpoint that would put a Vault token on the wire in
// clear text.
//
// Plain HTTP is allowed only against loopback, where `vault server -dev`
// listens and where there is no network to intercept.
func checkAddress(address string) error {
	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("address %q is not a URL: %v", address, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf(
			"address %q is plain HTTP: the Vault token, the CSR and the issued certificate would all cross the network in clear text. Use https (http is accepted only for 127.0.0.1, for a dev server)", address)
	case "":
		return fmt.Errorf("address %q has no scheme; it should start with https://", address)
	default:
		return fmt.Errorf("address %q has scheme %q; Vault speaks http and https", address, u.Scheme)
	}
}

func isLoopback(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

// RequestTimeout bounds one call to Vault.
func (c *Config) RequestTimeout() time.Duration {
	if c.RequestTimeoutSeconds > 0 {
		return time.Duration(c.RequestTimeoutSeconds) * time.Second
	}
	return DefaultRequestTimeout
}

// pkiPath builds a path under the PKI mount.
func (c *Config) pkiPath(parts ...string) string {
	return "/v1/" + c.Mount + "/" + strings.Join(parts, "/")
}

// issuancePath is where a certificate is asked for: pinned to one issuer when
// the account names one, and the mount's default issuer when it does not.
func (c *Config) issuancePath(verb string) string {
	if c.IssuerRef != "" {
		return c.pkiPath("issuer", url.PathEscape(c.IssuerRef), verb, url.PathEscape(c.Role))
	}
	return c.pkiPath(verb, url.PathEscape(c.Role))
}

// identity is the cache key for a Vault token obtained from this
// configuration.
//
// It covers everything that decides which token comes back and what it may do.
// Secrets are hashed rather than concatenated, so a cache key never has to be
// treated as a credential — and two accounts that differ only in their secret
// still get separate tokens, because the hash differs.
func (c *Config) identity() string {
	sum := sha256.New()
	for _, part := range []string{
		c.Address, c.Namespace, c.AuthMethod,
		c.Token, c.RoleID, c.SecretID, c.AppRoleMount,
		c.KubernetesRole, c.KubernetesMount, c.KubernetesJWTPath,
	} {
		sum.Write([]byte(part))
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}
