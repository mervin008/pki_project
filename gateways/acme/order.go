package acme

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/gateways/acme/solver"
	"golang.org/x/crypto/acme"
)

// issuedCertificate is the result of a completed ACME order.
type issuedCertificate struct {
	// LeafPEM is the end-entity certificate.
	LeafPEM []byte
	// ChainPEM is the issuer chain, excluding the leaf.
	ChainPEM []byte
	// CertURL is the ACME certificate URL, retained so renewals and
	// revocations can refer to this exact issuance.
	CertURL string
}

// pendingChallenge pairs a challenge the CA offered with the solver payload.
type pendingChallenge struct {
	authzURI  string
	challenge *acme.Challenge
	payload   solver.Challenge
	solver    solver.Solver
}

// obtainCertificate runs a full RFC 8555 order: authorize every identifier,
// prove control, finalize with the CSR, and download the chain.
//
// Challenges are presented for all identifiers before any is accepted. A
// twenty-SAN certificate would otherwise pay the DNS propagation wait twenty
// times over, which at current certificate lifetimes is the difference between
// a renewal that fits in its window and one that does not.
func (p *Provider) obtainCertificate(ctx context.Context, cfg *Config, csrDER []byte, domains []string) (*issuedCertificate, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.OrderTimeout())
	defer cancel()

	client, err := p.newClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	solvers, err := cfg.BuildSolvers()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize challenge solver: %w", err)
	}
	defer func() {
		if err := solvers.Close(); err != nil {
			slog.Warn("solver shutdown reported an error", "error", err)
		}
	}()

	if hasWildcard(domains) {
		if _, ok := solvers.For(solver.TypeDNS01); !ok {
			return nil, fmt.Errorf("wildcard domains require the dns-01 challenge; configure dns_provider and set challenge to dns-01")
		}
	}

	slog.Info("starting ACME order",
		"directory", cfg.DirectoryURL,
		"domains", domains,
		"challenge", cfg.Challenge,
	)

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME order: %w", describeACMEError(err))
	}

	if order.Status == acme.StatusPending {
		if err := p.solveAuthorizations(ctx, client, cfg, solvers, order); err != nil {
			return nil, err
		}

		order, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			return nil, fmt.Errorf("order did not become ready: %w", describeACMEError(err))
		}
	}

	der, certURL, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize ACME order: %w", describeACMEError(err))
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("CA returned an empty certificate chain")
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[0]})

	var chain strings.Builder
	for _, block := range der[1:] {
		chain.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block}))
	}

	slog.Info("ACME order completed",
		"domains", domains,
		"chain_length", len(der),
		"cert_url", certURL,
	)

	return &issuedCertificate{
		LeafPEM:  leafPEM,
		ChainPEM: []byte(chain.String()),
		CertURL:  certURL,
	}, nil
}

// solveAuthorizations proves control of every identifier in the order.
func (p *Provider) solveAuthorizations(ctx context.Context, client *acme.Client, cfg *Config, solvers *solver.Set, order *acme.Order) error {
	var pending []pendingChallenge

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("failed to fetch authorization: %w", describeACMEError(err))
		}

		// A cached valid authorization means the CA already trusts us for this
		// identifier, which is common on renewal.
		if authz.Status == acme.StatusValid {
			slog.Debug("authorization already valid, skipping challenge", "domain", authz.Identifier.Value)
			continue
		}
		if authz.Status != acme.StatusPending {
			return fmt.Errorf("authorization for %s is in unexpected state %q", authz.Identifier.Value, authz.Status)
		}

		chal, sol, err := selectChallenge(authz, solvers, cfg.Challenge)
		if err != nil {
			return err
		}

		payload, err := buildChallengePayload(client, chal, authz.Identifier.Value)
		if err != nil {
			return err
		}

		pending = append(pending, pendingChallenge{
			authzURI:  authz.URI,
			challenge: chal,
			payload:   payload,
			solver:    sol,
		})
	}

	if len(pending) == 0 {
		return nil
	}

	// Cleanup runs for everything presented, including on the failure path —
	// a stale TXT record left in a zone is a real operational problem.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		for _, pc := range pending {
			if err := pc.solver.CleanUp(cleanupCtx, pc.payload); err != nil {
				slog.Warn("failed to clean up challenge",
					"domain", pc.payload.Domain, "type", pc.payload.Type, "error", err)
			}
		}
	}()

	for _, pc := range pending {
		if err := pc.solver.Present(ctx, pc.payload); err != nil {
			return fmt.Errorf("failed to present %s challenge for %s: %w", pc.payload.Type, pc.payload.Domain, err)
		}
	}

	waitForPropagation(ctx, cfg, pending)

	for _, pc := range pending {
		if _, err := client.Accept(ctx, pc.challenge); err != nil {
			return fmt.Errorf("CA rejected the %s challenge for %s: %w",
				pc.payload.Type, pc.payload.Domain, describeACMEError(err))
		}
	}

	for _, pc := range pending {
		if _, err := client.WaitAuthorization(ctx, pc.authzURI); err != nil {
			return fmt.Errorf("domain control validation failed for %s: %w",
				pc.payload.Domain, describeACMEError(err))
		}
		slog.Debug("authorization validated", "domain", pc.payload.Domain)
	}

	return nil
}

// waitForPropagation gives DNS records time to become visible. HTTP-01 needs no
// wait: the listener is already serving before the CA is told to look.
func waitForPropagation(ctx context.Context, cfg *Config, pending []pendingChallenge) {
	var dns []pendingChallenge
	for _, pc := range pending {
		if pc.payload.Type == solver.TypeDNS01 {
			dns = append(dns, pc)
		}
	}
	if len(dns) == 0 {
		return
	}

	opts := cfg.Propagation()
	slog.Info("waiting for dns-01 records to propagate", "records", len(dns), "min_wait", opts.MinWait)

	// The waits overlap, so a multi-SAN order costs roughly one propagation
	// delay rather than one per name.
	var wg sync.WaitGroup
	for _, pc := range dns {
		wg.Add(1)
		go func(pc pendingChallenge) {
			defer wg.Done()
			solver.WaitForTXT(ctx, pc.payload.FQDN(), pc.payload.Value, opts)
		}(pc)
	}
	wg.Wait()
}

// selectChallenge picks the challenge matching the configured type.
func selectChallenge(authz *acme.Authorization, solvers *solver.Set, preferred string) (*acme.Challenge, solver.Solver, error) {
	// Try the configured type first, then anything else the solver set covers,
	// so a CA that does not offer the preferred type still succeeds.
	order := append([]string{preferred}, solvers.Types()...)
	seen := make(map[string]bool, len(order))

	for _, want := range order {
		if seen[want] {
			continue
		}
		seen[want] = true

		sol, ok := solvers.For(want)
		if !ok {
			continue
		}
		for _, chal := range authz.Challenges {
			if chal.Type == want {
				return chal, sol, nil
			}
		}
	}

	offered := make([]string, 0, len(authz.Challenges))
	for _, chal := range authz.Challenges {
		offered = append(offered, chal.Type)
	}
	return nil, nil, fmt.Errorf(
		"no usable challenge for %s: CA offers [%s], this gateway is configured for [%s]",
		authz.Identifier.Value, strings.Join(offered, ", "), strings.Join(solvers.Types(), ", "))
}

// buildChallengePayload computes what the solver must publish.
func buildChallengePayload(client *acme.Client, chal *acme.Challenge, identifier string) (solver.Challenge, error) {
	payload := solver.Challenge{
		Type:   chal.Type,
		Domain: solver.BaseDomain(identifier),
		Token:  chal.Token,
	}

	switch chal.Type {
	case solver.TypeDNS01:
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return payload, fmt.Errorf("failed to compute dns-01 record for %s: %w", identifier, err)
		}
		payload.Value = value

	case solver.TypeHTTP01:
		value, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return payload, fmt.Errorf("failed to compute http-01 response for %s: %w", identifier, err)
		}
		payload.Value = value

	default:
		return payload, fmt.Errorf("unsupported challenge type %q", chal.Type)
	}

	return payload, nil
}

func hasWildcard(domains []string) bool {
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			return true
		}
	}
	return false
}

// describeACMEError unwraps ACME problem documents into something an operator
// can act on. The default rendering buries the useful detail.
func describeACMEError(err error) error {
	if err == nil {
		return nil
	}

	var acmeErr *acme.Error
	if errors.As(err, &acmeErr) {
		msg := acmeErr.Detail
		if msg == "" {
			msg = acmeErr.ProblemType
		}
		if len(acmeErr.Subproblems) > 0 {
			parts := make([]string, 0, len(acmeErr.Subproblems))
			for _, sp := range acmeErr.Subproblems {
				detail := sp.Detail
				if sp.Identifier != nil {
					detail = sp.Identifier.Value + ": " + detail
				}
				parts = append(parts, detail)
			}
			msg = msg + " (" + strings.Join(parts, "; ") + ")"
		}
		if retry, ok := acme.RateLimit(acmeErr); ok {
			msg = fmt.Sprintf("%s [rate limited, retry after %s]", msg, retry.Round(time.Second))
		}
		return fmt.Errorf("%s", msg)
	}

	var authzErr *acme.AuthorizationError
	if errors.As(err, &authzErr) {
		parts := make([]string, 0, len(authzErr.Errors))
		for _, e := range authzErr.Errors {
			parts = append(parts, e.Error())
		}
		if len(parts) == 0 {
			return fmt.Errorf("authorization failed for %s", authzErr.Identifier)
		}
		return fmt.Errorf("authorization failed for %s: %s", authzErr.Identifier, strings.Join(parts, "; "))
	}

	return err
}
