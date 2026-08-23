package solver

import (
	"context"
	"log/slog"
	"net"
	"time"
)

// PropagationOptions controls how long to wait for a DNS-01 record to become
// visible before handing the challenge to the CA.
type PropagationOptions struct {
	// MinWait is always observed, even if the record is already visible
	// locally. Authoritative nameservers within a provider do not update in
	// lockstep, and the CA may query a different one than we can see.
	MinWait time.Duration
	// Timeout bounds the total wait.
	Timeout time.Duration
	// PollInterval is how often to re-check.
	PollInterval time.Duration
}

// DefaultPropagation returns conservative defaults that work for most managed
// DNS providers.
func DefaultPropagation() PropagationOptions {
	return PropagationOptions{
		MinWait:      10 * time.Second,
		Timeout:      2 * time.Minute,
		PollInterval: 5 * time.Second,
	}
}

func (o PropagationOptions) withDefaults() PropagationOptions {
	d := DefaultPropagation()
	if o.MinWait <= 0 {
		o.MinWait = d.MinWait
	}
	if o.Timeout <= 0 {
		o.Timeout = d.Timeout
	}
	if o.PollInterval <= 0 {
		o.PollInterval = d.PollInterval
	}
	if o.Timeout < o.MinWait {
		o.Timeout = o.MinWait
	}
	return o
}

// WaitForTXT waits until a TXT record carrying value is observable at fqdn, or
// until the timeout expires.
//
// Observing the record is treated as an accelerator rather than a gate. The
// system resolver caches negative answers and is not the resolver the CA will
// use, so failing to see the record is not proof it is absent. After MinWait
// has elapsed the challenge proceeds regardless — letting the CA be the
// authority on whether validation succeeds, and letting it produce the real
// error if it does not.
func WaitForTXT(ctx context.Context, fqdn, value string, opts PropagationOptions) {
	opts = opts.withDefaults()

	start := time.Now()
	deadline := start.Add(opts.Timeout)
	resolver := net.DefaultResolver
	seen := false

	for {
		if !seen && lookupHasValue(ctx, resolver, fqdn, value) {
			seen = true
			slog.Debug("dns-01 TXT record observed", "fqdn", fqdn, "after", time.Since(start).Round(time.Second))
		}

		elapsed := time.Since(start)
		// Both conditions must hold: the minimum settle time has passed, and
		// either we have seen the record or we have run out of patience.
		if elapsed >= opts.MinWait && (seen || time.Now().After(deadline)) {
			if !seen {
				slog.Warn("dns-01 TXT record not observed locally; proceeding and letting the CA validate",
					"fqdn", fqdn, "waited", elapsed.Round(time.Second))
			}
			return
		}
		if time.Now().After(deadline) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(opts.PollInterval):
		}
	}
}

func lookupHasValue(ctx context.Context, r *net.Resolver, fqdn, value string) bool {
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	records, err := r.LookupTXT(lookupCtx, fqdn)
	if err != nil {
		return false
	}
	for _, rec := range records {
		if rec == value {
			return true
		}
	}
	return false
}
