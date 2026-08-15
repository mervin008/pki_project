// Package policy implements policy validation and compliance rule enforcement for CertPilot.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/certpilot/certpilot/core/store"
)

// Violation represents a policy rule violation.
type Violation struct {
	PolicyName string `json:"policy_name"`
	RuleType   string `json:"rule_type"`
	Message    string `json:"message"`
	Severity   string `json:"severity"` // INFO, WARNING, BLOCK
}

// Engine evaluates policy rules against certificates or requests.
type Engine struct {
	store store.Store
}

// NewEngine creates a new policy engine.
func NewEngine(s store.Store) *Engine {
	return &Engine{store: s}
}

// EvaluateRequest checks if a certificate request conforms to all active policies.
func (e *Engine) EvaluateRequest(ctx context.Context, domains []string, keyType string, keySize int, validityDays int, caProviderType string) ([]Violation, error) {
	policies, err := e.store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}

	var violations []Violation

	for _, p := range policies {
		if !p.IsEnabled {
			continue
		}

		// Check if domain pattern matches any domain
		if p.DomainPattern != "" && !matchesDomainPattern(domains, p.DomainPattern) {
			continue
		}

		switch p.RuleType {
		case "key_size":
			var cfg struct {
				MinKeySize int `json:"min_key_size"`
			}
			if err := json.Unmarshal([]byte(p.RuleConfig), &cfg); err == nil && cfg.MinKeySize > 0 {
				if keyType == "RSA" && keySize < cfg.MinKeySize {
					violations = append(violations, Violation{
						PolicyName: p.Name,
						RuleType:   p.RuleType,
						Severity:   p.Severity,
						Message:    fmt.Sprintf("RSA key size %d is below minimum policy requirement of %d bits", keySize, cfg.MinKeySize),
					})
				}
			}

		case "max_lifetime":
			var cfg struct {
				MaxDays int `json:"max_days"`
			}
			if err := json.Unmarshal([]byte(p.RuleConfig), &cfg); err == nil && cfg.MaxDays > 0 {
				if validityDays > cfg.MaxDays {
					violations = append(violations, Violation{
						PolicyName: p.Name,
						RuleType:   p.RuleType,
						Severity:   p.Severity,
						Message:    fmt.Sprintf("Requested validity %d days exceeds maximum allowed %d days", validityDays, cfg.MaxDays),
					})
				}
			}

		case "ca_restriction":
			var cfg struct {
				AllowedProviders []string `json:"allowed_providers"`
			}
			if err := json.Unmarshal([]byte(p.RuleConfig), &cfg); err == nil && len(cfg.AllowedProviders) > 0 {
				allowed := false
				for _, ap := range cfg.AllowedProviders {
					if strings.EqualFold(ap, caProviderType) {
						allowed = true
						break
					}
				}
				if !allowed {
					violations = append(violations, Violation{
						PolicyName: p.Name,
						RuleType:   p.RuleType,
						Severity:   p.Severity,
						Message:    fmt.Sprintf("CA provider %s is not in the allowed list: %v", caProviderType, cfg.AllowedProviders),
					})
				}
			}
		}
	}

	return violations, nil
}

func matchesDomainPattern(domains []string, pattern string) bool {
	pattern = strings.ToLower(pattern)
	for _, d := range domains {
		d = strings.ToLower(d)
		if pattern == "*" || pattern == d {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(d, suffix) {
				return true
			}
		}
	}
	return false
}
