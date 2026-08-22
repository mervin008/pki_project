package agent

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"time"
)

// Bounds on how the agent paces itself when the core is unreachable.
const (
	minBackoff = 15 * time.Second
	maxBackoff = 10 * time.Minute
)

// DefaultInventoryInterval is how often the host is scanned.
//
// Hours, not minutes. Certificate files change when somebody deploys, which is
// not often, and walking a production filesystem is the most intrusive thing
// this agent does. The heartbeat is what makes a dead agent visible quickly;
// the inventory does not need to.
const DefaultInventoryInterval = 6 * time.Hour

// Runner keeps one host reporting.
type Runner struct {
	client   *Client
	state    State
	interval time.Duration
	now      func() time.Time

	scanPaths      []string
	inventoryEvery time.Duration
	lastInventory  time.Time
}

// NewRunner creates a runner from a saved identity.
func NewRunner(client *Client, state State) *Runner {
	interval := time.Duration(state.HeartbeatIntervalSeconds) * time.Second
	if interval < 30*time.Second {
		interval = 5 * time.Minute
	}
	paths := state.ScanPaths
	if len(paths) == 0 {
		paths = DefaultScanPaths()
	}
	return &Runner{
		client:         client,
		state:          state,
		interval:       interval,
		now:            time.Now,
		scanPaths:      paths,
		inventoryEvery: DefaultInventoryInterval,
	}
}

// WithInventoryInterval overrides how often the host is scanned.
func (r *Runner) WithInventoryInterval(d time.Duration) *Runner {
	if d > 0 {
		r.inventoryEvery = d
	}
	return r
}

// ReportInventory scans this host and sends what it found.
//
// The certificates travel as PEM and are parsed centrally. That split is
// deliberate: this binary runs on hosts nobody upgrades for years, and parsing
// logic living on five hundred machines is parsing logic that cannot be fixed.
func (r *Runner) ReportInventory(ctx context.Context) (InventoryReport, error) {
	report := Scan(r.scanPaths)
	err := r.client.post(ctx, "/api/v1/agent/inventory", report, nil)
	if err == nil {
		r.lastInventory = r.now()
	}
	return report, err
}

type heartbeatResponse struct {
	AgentID    string `json:"agent_id"`
	ServerTime string `json:"server_time"`
}

// Heartbeat reports once.
func (r *Runner) Heartbeat(ctx context.Context) (time.Time, error) {
	var resp heartbeatResponse
	err := r.client.post(ctx, "/api/v1/agent/heartbeat", map[string]any{
		"version":          Version,
		"platform":         Platform(),
		"hostname":         Hostname(),
		"interval_seconds": int(r.interval.Seconds()),
	}, &resp)
	if err != nil {
		return time.Time{}, err
	}
	served, parseErr := time.Parse(time.RFC3339, resp.ServerTime)
	if parseErr != nil {
		return time.Time{}, nil
	}
	return served, nil
}

// Run reports until the context is cancelled or the credential is withdrawn.
//
// Returns ErrRevoked rather than retrying it. There is no amount of waiting
// that fixes a revoked credential, and an agent that kept trying would be a
// withdrawn credential knocking every five minutes for as long as the host
// stays up — visible in the core's logs as a security event that is really just
// this program being stubborn.
func (r *Runner) Run(ctx context.Context) error {
	slog.Info("agent reporting", "agent", r.state.AgentID, "server", r.state.Server,
		"name", r.state.Name, "interval", r.interval)

	failures := 0
	for {
		served, err := r.Heartbeat(ctx)
		switch {
		case err == nil:
			if failures > 0 {
				slog.Info("the core is reachable again", "after_failures", failures)
			}
			failures = 0
			r.warnOnDrift(served)
			r.inventoryIfDue(ctx)

		case errors.Is(err, ErrRevoked):
			slog.Error("this agent's credential has been revoked; stopping",
				"agent", r.state.AgentID)
			return ErrRevoked

		case errors.Is(err, ErrClockSkew):
			// Said as the actual problem. Without this the operator sees
			// "unauthorized" forever and goes looking at tokens and firewalls,
			// because a wrong clock is the last thing anybody suspects.
			failures++
			slog.Error("this host's clock is too far from the core's for its signatures to be accepted; fix the clock (NTP) — nothing else will make this work",
				"agent", r.state.AgentID)

		default:
			failures++
			slog.Warn("heartbeat failed", "attempt", failures, "error", err)
		}

		wait := r.interval
		if failures > 0 {
			wait = backoff(failures)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// warnOnDrift says something while the agent still works.
//
// A clock an hour out is fine today and stops the agent dead the moment it
// drifts past the tolerance. Half the window is early enough to fix it during
// working hours rather than during an incident.
func (r *Runner) warnOnDrift(served time.Time) {
	if served.IsZero() {
		return
	}
	drift := r.now().Sub(served)
	if drift < 0 {
		drift = -drift
	}
	if drift > driftWarnAt {
		slog.Warn("this host's clock differs from the core's; signatures will stop being accepted if it drifts further",
			"drift", drift.Round(time.Second), "tolerance", 2*driftWarnAt)
	}
}

// driftWarnAt is half the signing tolerance.
const driftWarnAt = 150 * time.Second

// backoff spaces out retries when the core cannot be reached.
//
// Jittered, because a core that restarts drops every agent's connection at the
// same instant, and a fleet that all returns on the same second turns an
// ordinary restart into a load spike at exactly the moment the process is
// warming up.
func backoff(failures int) time.Duration {
	d := time.Duration(float64(minBackoff) * math.Pow(2, float64(failures-1)))
	if d > maxBackoff || d <= 0 {
		d = maxBackoff
	}
	jitter := time.Duration(rand.Float64() * float64(d) * 0.3)
	return d + jitter
}

// inventoryIfDue scans the host when enough time has passed.
//
// Driven off a successful heartbeat rather than its own ticker, so an agent
// that cannot reach the core is not walking the filesystem every six hours to
// throw the result away.
func (r *Runner) inventoryIfDue(ctx context.Context) {
	if !r.lastInventory.IsZero() && r.now().Sub(r.lastInventory) < r.inventoryEvery {
		return
	}
	report, err := r.ReportInventory(ctx)
	if err != nil {
		slog.Warn("could not report this host's certificate inventory", "error", err)
		return
	}
	slog.Info("reported certificate inventory",
		"certificates", len(report.Certificates), "files_seen", report.FilesSeen,
		"unreadable", len(report.Errors))
}
