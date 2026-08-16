// Package solver implements ACME challenge solvers.
//
// A Solver publishes whatever proof of control a challenge type demands, waits
// for it to become observable, and then removes it. Solvers are selected per
// certificate request from the gateway configuration, so one ACME gateway can
// serve a DNS-01 zone for wildcards and an HTTP-01 endpoint for everything else.
package solver

import (
	"context"
	"fmt"
	"strings"
)

// Challenge types defined by RFC 8555.
const (
	TypeDNS01  = "dns-01"
	TypeHTTP01 = "http-01"
)

// Challenge carries everything a solver needs to publish proof of control.
type Challenge struct {
	// Type is the ACME challenge type, e.g. "dns-01".
	Type string
	// Domain is the identifier under validation, with any wildcard prefix
	// already stripped — "example.com" for a "*.example.com" request.
	Domain string
	// Token is the ACME challenge token.
	Token string
	// Value is what must be published: the TXT record contents for DNS-01,
	// or the response body for HTTP-01.
	Value string
}

// FQDN returns the DNS name that must carry the TXT record for a DNS-01
// challenge.
func (c Challenge) FQDN() string {
	return "_acme-challenge." + strings.TrimSuffix(c.Domain, ".")
}

// Solver publishes and retracts proof of domain control.
//
// Present must be idempotent: an ACME order covering both "example.com" and
// "*.example.com" produces two challenges for the same FQDN, and both records
// have to coexist.
type Solver interface {
	// Type reports which ACME challenge type this solver satisfies.
	Type() string
	// Present publishes the challenge response.
	Present(ctx context.Context, ch Challenge) error
	// CleanUp retracts it. It is called even when validation fails, and must
	// tolerate being called for a challenge that was never presented.
	CleanUp(ctx context.Context, ch Challenge) error
}

// Set holds the solvers available for one certificate request, indexed by
// challenge type.
type Set struct {
	solvers map[string]Solver
}

// NewSet builds a solver set. Later solvers override earlier ones of the same
// type.
func NewSet(solvers ...Solver) *Set {
	s := &Set{solvers: make(map[string]Solver, len(solvers))}
	for _, sol := range solvers {
		if sol != nil {
			s.solvers[sol.Type()] = sol
		}
	}
	return s
}

// For returns the solver registered for a challenge type.
func (s *Set) For(challengeType string) (Solver, bool) {
	if s == nil {
		return nil, false
	}
	sol, ok := s.solvers[challengeType]
	return sol, ok
}

// Types lists the challenge types this set can satisfy.
func (s *Set) Types() []string {
	if s == nil {
		return nil
	}
	types := make([]string, 0, len(s.solvers))
	// Prefer dns-01 in reported order: it is the only type that can satisfy a
	// wildcard, so it should be tried first when a CA offers a choice.
	for _, t := range []string{TypeDNS01, TypeHTTP01} {
		if _, ok := s.solvers[t]; ok {
			types = append(types, t)
		}
	}
	return types
}

// Empty reports whether the set can solve nothing.
func (s *Set) Empty() bool {
	return s == nil || len(s.solvers) == 0
}

// Close releases any resources held by solvers that own them, such as the
// HTTP-01 listener.
func (s *Set) Close() error {
	if s == nil {
		return nil
	}
	var errs []string
	for _, sol := range s.solvers {
		if c, ok := sol.(interface{ Close() error }); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("solver shutdown: %s", strings.Join(errs, "; "))
	}
	return nil
}

// BaseDomain strips a leading wildcard label. ACME validates "*.example.com"
// against the TXT record for "_acme-challenge.example.com", so the wildcard has
// to come off before the FQDN is built.
func BaseDomain(domain string) string {
	return strings.TrimPrefix(domain, "*.")
}
