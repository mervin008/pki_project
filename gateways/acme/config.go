package acme

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/certpilot/certpilot/gateways/acme/solver"
)

// Well-known ACME directory endpoints, for operator convenience.
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ZeroSSLProduction     = "https://acme.zerossl.com/v2/DV90"
	BuypassProduction     = "https://api.buypass.com/acme/directory"
	GoogleTrustServices   = "https://dv.acme-v02.api.pki.goog/directory"
)

// DirectoryAliases maps short names to directory URLs so a CA account can be
// configured with "letsencrypt-staging" instead of a full URL.
var DirectoryAliases = map[string]string{
	"letsencrypt":         LetsEncryptProduction,
	"letsencrypt-staging": LetsEncryptStaging,
	"zerossl":             ZeroSSLProduction,
	"buypass":             BuypassProduction,
	"google":              GoogleTrustServices,
}

// Config is the per-CA-account configuration the core sends with each request.
//
// It arrives as the provider_config JSON field. The core stores it encrypted at
// rest and decrypts it only to populate this struct on the wire, which is why
// the gateway must never log it.
type Config struct {
	// DirectoryURL is the ACME directory endpoint, or an alias from
	// DirectoryAliases.
	DirectoryURL string `json:"directory_url"`
	// Email is the account contact address. Required by most CAs.
	Email string `json:"email"`
	// AccountKeyPEM is the ACME account key. When empty, the gateway uses a
	// key from its local state directory, creating one on first use.
	AccountKeyPEM string `json:"account_key_pem,omitempty"`
	// EABKeyID and EABHMACKey carry External Account Binding credentials,
	// required by ZeroSSL, Google Trust Services, and most commercial CAs.
	EABKeyID   string `json:"eab_key_id,omitempty"`
	EABHMACKey string `json:"eab_hmac_key,omitempty"`

	// Challenge selects how domain control is proven: "dns-01" or "http-01".
	// Defaults to dns-01 when a DNS provider is configured, http-01 otherwise.
	Challenge string `json:"challenge,omitempty"`

	// DNSProvider selects the dns-01 solver: "cloudflare" or "webhook".
	DNSProvider string `json:"dns_provider,omitempty"`
	// DNSConfig holds provider-specific solver settings.
	DNSConfig DNSConfig `json:"dns_config,omitempty"`

	// HTTP01BindAddr is where the http-01 challenge listener binds. Defaults
	// to the gateway's --http01-addr flag.
	HTTP01BindAddr string `json:"http01_bind_addr,omitempty"`

	// PropagationMinWaitSeconds and PropagationTimeoutSeconds tune how long to
	// wait for DNS records to settle before asking the CA to validate.
	PropagationMinWaitSeconds int `json:"propagation_min_wait_seconds,omitempty"`
	PropagationTimeoutSeconds int `json:"propagation_timeout_seconds,omitempty"`

	// OrderTimeoutSeconds bounds a full issuance. Defaults to 10 minutes.
	OrderTimeoutSeconds int `json:"order_timeout_seconds,omitempty"`
}

// DNSConfig holds credentials for the selected DNS provider.
type DNSConfig struct {
	// Cloudflare.
	APIToken string `json:"api_token,omitempty"`

	// Webhook.
	URL           string `json:"url,omitempty"`
	BearerToken   string `json:"bearer_token,omitempty"`
	SigningSecret string `json:"signing_secret,omitempty"`
}

// ParseConfig decodes the provider_config JSON and applies defaults.
func ParseConfig(raw string, defaultDirectory, defaultHTTP01Addr string) (*Config, error) {
	cfg := &Config{}

	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), cfg); err != nil {
			return nil, fmt.Errorf("invalid provider configuration JSON: %w", err)
		}
	}

	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = defaultDirectory
	}
	if alias, ok := DirectoryAliases[strings.ToLower(cfg.DirectoryURL)]; ok {
		cfg.DirectoryURL = alias
	}
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = LetsEncryptProduction
	}

	if cfg.HTTP01BindAddr == "" {
		cfg.HTTP01BindAddr = defaultHTTP01Addr
	}

	if cfg.Challenge == "" {
		if cfg.DNSProvider != "" {
			cfg.Challenge = solver.TypeDNS01
		} else {
			cfg.Challenge = solver.TypeHTTP01
		}
	}
	cfg.Challenge = strings.ToLower(cfg.Challenge)

	return cfg, nil
}

// Validate reports configuration problems as user-facing messages.
func (c *Config) Validate() (errs []string, warnings []string) {
	if c.DirectoryURL == "" {
		errs = append(errs, "directory_url is required")
	} else if !strings.HasPrefix(c.DirectoryURL, "https://") {
		// http:// is legitimate for a local Pebble or step-ca in testing, so
		// this is a warning rather than an error.
		warnings = append(warnings, "directory_url is not HTTPS; acceptable only for local testing")
	}

	if c.Email == "" {
		warnings = append(warnings, "email is empty; most CAs require a contact address and will reject registration")
	}

	switch c.Challenge {
	case solver.TypeDNS01:
		switch strings.ToLower(c.DNSProvider) {
		case "cloudflare":
			if c.DNSConfig.APIToken == "" {
				errs = append(errs, "dns_config.api_token is required for the cloudflare provider")
			}
		case "webhook":
			if c.DNSConfig.URL == "" {
				errs = append(errs, "dns_config.url is required for the webhook provider")
			}
			if c.DNSConfig.BearerToken == "" && c.DNSConfig.SigningSecret == "" {
				warnings = append(warnings, "webhook solver has neither bearer_token nor signing_secret; the receiver cannot verify requests")
			}
		case "":
			errs = append(errs, "dns_provider is required when challenge is dns-01 (supported: cloudflare, webhook)")
		default:
			errs = append(errs, fmt.Sprintf("unsupported dns_provider %q (supported: cloudflare, webhook)", c.DNSProvider))
		}
	case solver.TypeHTTP01:
		// Nothing required; the listener address has a default.
	default:
		errs = append(errs, fmt.Sprintf("unsupported challenge %q (supported: dns-01, http-01)", c.Challenge))
	}

	if (c.EABKeyID == "") != (c.EABHMACKey == "") {
		errs = append(errs, "eab_key_id and eab_hmac_key must be supplied together")
	}

	if requiresEAB(c.DirectoryURL) && c.EABKeyID == "" {
		errs = append(errs, "this CA requires External Account Binding; set eab_key_id and eab_hmac_key")
	}

	return errs, warnings
}

// Propagation converts the configured waits into solver options.
func (c *Config) Propagation() solver.PropagationOptions {
	opts := solver.DefaultPropagation()
	if c.PropagationMinWaitSeconds > 0 {
		opts.MinWait = time.Duration(c.PropagationMinWaitSeconds) * time.Second
	}
	if c.PropagationTimeoutSeconds > 0 {
		opts.Timeout = time.Duration(c.PropagationTimeoutSeconds) * time.Second
	}
	return opts
}

// OrderTimeout returns the bound on a single issuance.
func (c *Config) OrderTimeout() time.Duration {
	if c.OrderTimeoutSeconds > 0 {
		return time.Duration(c.OrderTimeoutSeconds) * time.Second
	}
	return 10 * time.Minute
}

// BuildSolvers constructs the solver set this configuration calls for.
//
// The caller owns the returned set and must Close it, because the http-01
// solver holds a listener.
func (c *Config) BuildSolvers() (*solver.Set, error) {
	switch c.Challenge {
	case solver.TypeDNS01:
		switch strings.ToLower(c.DNSProvider) {
		case "cloudflare":
			s, err := solver.NewCloudflare(c.DNSConfig.APIToken)
			if err != nil {
				return nil, err
			}
			return solver.NewSet(s), nil
		case "webhook":
			s, err := solver.NewWebhook(c.DNSConfig.URL, c.DNSConfig.BearerToken, c.DNSConfig.SigningSecret)
			if err != nil {
				return nil, err
			}
			return solver.NewSet(s), nil
		default:
			return nil, fmt.Errorf("unsupported dns_provider %q (supported: cloudflare, webhook)", c.DNSProvider)
		}

	case solver.TypeHTTP01:
		s, err := solver.NewHTTP01(c.HTTP01BindAddr)
		if err != nil {
			return nil, err
		}
		return solver.NewSet(s), nil

	default:
		return nil, fmt.Errorf("unsupported challenge %q (supported: dns-01, http-01)", c.Challenge)
	}
}

// requiresEAB reports whether a directory is known to mandate External Account
// Binding. Getting this wrong only costs a clearer error message, since the CA
// rejects the registration either way.
func requiresEAB(directoryURL string) bool {
	for _, prefix := range []string{
		"https://acme.zerossl.com",
		"https://dv.acme-v02.api.pki.goog",
		"https://acme.ssl.com",
	} {
		if strings.HasPrefix(directoryURL, prefix) {
			return true
		}
	}
	return false
}
