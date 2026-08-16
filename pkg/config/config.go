// Package config provides configuration loading for CertPilot components.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// CoreConfig is the main configuration for CertPilot Core.
type CoreConfig struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
	Supabase SupabaseConfig `yaml:"supabase"`
	Plugins  PluginsConfig  `yaml:"plugins"`
	PKI      PKIConfig      `yaml:"pki"`
	Renewal  RenewalConfig  `yaml:"renewal"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"` // development | production
	// AllowedOrigins lists the browser origins permitted to call the API.
	// A wildcard is rejected when credentials are in play, so this must name
	// the frontend explicitly.
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// IsProduction reports whether the server is running in production mode.
func (s ServerConfig) IsProduction() bool { return s.Mode == "production" }

// AuthConfig holds authentication settings.
//
// Two verification paths are supported. JWKSURL is the one to use: the core
// verifies asymmetrically signed tokens against the provider's published public
// keys and never holds anything capable of minting a token. JWTSecret is the
// legacy shared-secret path, which requires the core to hold a key that can
// forge admin tokens, and is kept only for existing Supabase projects that have
// not migrated to asymmetric signing keys.
type AuthConfig struct {
	// JWKSURL is the JSON Web Key Set endpoint of the identity provider.
	JWKSURL string `yaml:"jwks_url"`
	// Issuer and Audience are validated when set.
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	// JWTSecret enables legacy HS256 verification.
	JWTSecret string `yaml:"jwt_secret"`
	// RoleClaim names the claim inside app_metadata carrying the CertPilot
	// role. Defaults to "certpilot_role".
	RoleClaim string `yaml:"role_claim"`
	// AllowAnonymous disables authentication entirely. It is refused unless
	// the server is in development mode and bound to a loopback address, and
	// exists so a first-run evaluation does not require an identity provider.
	AllowAnonymous bool `yaml:"allow_anonymous"`
}

// SupabaseConfig holds Supabase connection details.
type SupabaseConfig struct {
	URL            string `yaml:"url"`
	AnonKey        string `yaml:"anon_key"`
	ServiceRoleKey string `yaml:"service_role_key"`
	JWTSecret      string `yaml:"jwt_secret"`
}

// PluginsConfig holds gateway plugin settings.
type PluginsConfig struct {
	DiscoveryMode string          `yaml:"discovery_mode"` // static | docker | kubernetes
	Gateways      []GatewayConfig `yaml:"gateways"`
	// TLS is the mutual-TLS material the core presents when dialing gateways.
	TLS GatewayTLSConfig `yaml:"tls"`
}

// GatewayTLSConfig holds the core's client identity for the gateway channel.
type GatewayTLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	// Insecure disables TLS on the gateway channel. The channel carries CSRs,
	// private keys, and CA credentials, so this is development-only.
	Insecure bool `yaml:"insecure"`
}

// GatewayConfig represents a single gateway registration.
type GatewayConfig struct {
	Name string `yaml:"name"`
	Addr string `yaml:"addr"`
	Type string `yaml:"type"`
	// ServerName overrides the name expected in this gateway's certificate,
	// for when it is dialed by IP or through a service alias.
	ServerName string `yaml:"server_name"`
}

// PKIConfig holds PKI monitoring settings.
type PKIConfig struct {
	CAHealthCheckInterval int `yaml:"ca_health_check_interval"` // minutes
	CRLOCSPCheckInterval  int `yaml:"crl_ocsp_check_interval"`  // minutes
}

// RenewalConfig holds certificate renewal settings.
type RenewalConfig struct {
	ScanInterval    int   `yaml:"scan_interval"` // minutes
	DefaultLeadDays int   `yaml:"default_lead_days"`
	RetryBackoff    []int `yaml:"retry_backoff"` // minutes
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // text | json
}

// GatewayPluginConfig is the configuration for a gateway plugin process.
type GatewayPluginConfig struct {
	Port     int    `yaml:"port"`
	CoreAddr string `yaml:"core_addr"` // Address of the CertPilot Core gRPC endpoint
}

// LoadCoreConfig loads the core configuration from a YAML file.
func LoadCoreConfig(path string) (*CoreConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	cfg := &CoreConfig{
		// Defaults
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           8080,
			Mode:           "development",
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Auth: AuthConfig{
			RoleClaim: "certpilot_role",
		},
		PKI: PKIConfig{
			CAHealthCheckInterval: 360,
			CRLOCSPCheckInterval:  60,
		},
		Renewal: RenewalConfig{
			ScanInterval:    60,
			DefaultLeadDays: 30,
			RetryBackoff:    []int{60, 240, 720, 1440},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}

	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Carry the legacy Supabase secret across so existing configs keep working.
	if cfg.Auth.JWTSecret == "" && cfg.Supabase.JWTSecret != "" {
		cfg.Auth.JWTSecret = cfg.Supabase.JWTSecret
	}
	if cfg.Auth.RoleClaim == "" {
		cfg.Auth.RoleClaim = "certpilot_role"
	}
	// Supabase publishes its JWKS at a predictable path, so a project URL is
	// enough to prefer asymmetric verification over the shared secret.
	if cfg.Auth.JWKSURL == "" && cfg.Supabase.URL != "" {
		cfg.Auth.JWKSURL = strings.TrimSuffix(cfg.Supabase.URL, "/") + "/auth/v1/.well-known/jwks.json"
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate rejects configurations that are unsafe to run.
//
// These checks exist because the dangerous settings here are all ones that look
// harmless in a development config and then travel to production unnoticed.
func (c *CoreConfig) Validate() error {
	if c.Server.IsProduction() {
		if c.Auth.AllowAnonymous {
			return fmt.Errorf("config: auth.allow_anonymous cannot be enabled in production mode")
		}
		if c.Auth.JWKSURL == "" && c.Auth.JWTSecret == "" {
			return fmt.Errorf("config: production mode requires auth.jwks_url or auth.jwt_secret")
		}
		if c.Plugins.TLS.Insecure {
			return fmt.Errorf("config: plugins.tls.insecure cannot be enabled in production mode; " +
				"the gateway channel carries private keys and CA credentials")
		}
		for _, origin := range c.Server.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("config: server.allowed_origins cannot contain \"*\" in production mode")
			}
		}
	}

	if c.Auth.AllowAnonymous && !isLoopback(c.Server.Host) {
		return fmt.Errorf("config: auth.allow_anonymous requires server.host to be a loopback address, got %q", c.Server.Host)
	}

	return nil
}

func isLoopback(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
