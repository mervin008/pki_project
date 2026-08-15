// Package config provides configuration loading for CertPilot components.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// CoreConfig is the main configuration for CertPilot Core.
type CoreConfig struct {
	Server    ServerConfig    `yaml:"server"`
	Supabase  SupabaseConfig  `yaml:"supabase"`
	Plugins   PluginsConfig   `yaml:"plugins"`
	PKI       PKIConfig       `yaml:"pki"`
	Renewal   RenewalConfig   `yaml:"renewal"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	Mode string `yaml:"mode"` // development | production
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
}

// GatewayConfig represents a single gateway registration.
type GatewayConfig struct {
	Name string `yaml:"name"`
	Addr string `yaml:"addr"`
	Type string `yaml:"type"`
}

// PKIConfig holds PKI monitoring settings.
type PKIConfig struct {
	CAHealthCheckInterval int `yaml:"ca_health_check_interval"` // minutes
	CRLOCSPCheckInterval  int `yaml:"crl_ocsp_check_interval"`  // minutes
}

// RenewalConfig holds certificate renewal settings.
type RenewalConfig struct {
	ScanInterval    int   `yaml:"scan_interval"`     // minutes
	DefaultLeadDays int   `yaml:"default_lead_days"`
	RetryBackoff    []int `yaml:"retry_backoff"`     // minutes
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
			Host: "0.0.0.0",
			Port: 8080,
			Mode: "development",
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

	return cfg, nil
}
