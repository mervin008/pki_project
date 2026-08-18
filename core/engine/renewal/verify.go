package renewal

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// Constants governing post-renewal verification.
const (
	// verifyTick is how often certificates awaiting verification are looked
	// for.
	verifyTick = 1 * time.Minute
	// VerifyGrace is how long after a renewal the first check waits.
	//
	// CertPilot does not deploy anything yet, so a renewal reaches the server
	// when a person or another system puts it there. Checking in the same
	// second would report every renewal as undeployed, which is true and
	// useless.
	VerifyGrace = 30 * time.Minute
	// verifyBatch bounds one pass.
	verifyBatch = 25
	// verifyProbeTimeout bounds one endpoint.
	verifyProbeTimeout = 10 * time.Second
	// verifyMaxAttempts is how many times an unresolved certificate is
	// rechecked before the verifier stops asking. It does not stop reporting:
	// the state stays on the record.
	verifyMaxAttempts = 6
)

// verifyBackoff is the interval after each unresolved attempt. Deployment
// happens on human timescales, so these widen quickly rather than probing an
// endpoint every minute for a day.
var verifyBackoff = []time.Duration{
	30 * time.Minute,
	1 * time.Hour,
	4 * time.Hour,
	12 * time.Hour,
	24 * time.Hour,
}

// Verifier answers the only question that matters after a renewal: is the thing
// in front of the users actually serving the new certificate?
//
// A renewal that stored a certificate the server never picked up is the failure
// this whole product exists to prevent, produced by this product. The inventory
// says ninety days remaining; the endpoint says twenty; the dashboard is green.
//
// The endpoints checked are the ones discovery has actually observed serving
// this certificate. Not the SANs — probing hostnames read out of certificate
// data would have CertPilot opening connections nobody asked for, to names that
// may not resolve to anything it should be touching. A certificate discovery
// has never seen is reported as unverifiable rather than guessed at.
type Verifier struct {
	store   store.Store
	scanner *discovery.Scanner
	broker  *events.Broker

	tick  time.Duration
	batch int
	now   func() time.Time

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// VerifyOption configures a Verifier.
type VerifyOption func(*Verifier)

// WithVerifyTick sets how often work is looked for.
func WithVerifyTick(d time.Duration) VerifyOption {
	return func(v *Verifier) {
		if d > 0 {
			v.tick = d
		}
	}
}

// NewVerifier creates a verifier.
func NewVerifier(s store.Store, scanner *discovery.Scanner, broker *events.Broker, opts ...VerifyOption) *Verifier {
	v := &Verifier{
		store:   s,
		scanner: scanner,
		broker:  broker,
		tick:    verifyTick,
		batch:   verifyBatch,
		now:     time.Now,
		stopCh:  make(chan struct{}),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Start begins the loop.
func (v *Verifier) Start() {
	if v == nil {
		return
	}
	v.mu.Lock()
	if v.started {
		v.mu.Unlock()
		return
	}
	v.started = true
	v.mu.Unlock()

	v.wg.Add(1)
	go v.run()
	slog.Info("post-renewal verification started", "tick", v.tick, "grace", VerifyGrace)
}

// Stop ends the loop. Safe to call twice, and on one that never started.
func (v *Verifier) Stop() {
	if v == nil {
		return
	}
	v.stopped.Do(func() { close(v.stopCh) })
	v.wg.Wait()
}

func (v *Verifier) run() {
	defer v.wg.Done()

	ticker := time.NewTicker(v.tick)
	defer ticker.Stop()

	v.VerifyDue(context.Background())
	for {
		select {
		case <-v.stopCh:
			return
		case <-ticker.C:
			v.VerifyDue(context.Background())
		}
	}
}

// VerifyDue checks every certificate whose grace period has elapsed. Exported
// so a test can drive it without a ticker.
func (v *Verifier) VerifyDue(ctx context.Context) {
	certs, err := v.store.GetCertificatesDueForVerification(ctx, v.now(), v.batch)
	if err != nil {
		slog.Error("could not read certificates awaiting verification", "error", err)
		return
	}
	for _, cert := range certs {
		select {
		case <-v.stopCh:
			return
		default:
		}
		v.Verify(ctx, cert)
	}
}

// Verify checks one certificate and records what it found.
func (v *Verifier) Verify(ctx context.Context, cert *store.Certificate) {
	now := v.now()
	attempts := cert.VerificationAttempts + 1

	endpoints, err := v.store.GetEndpointsServingCertificate(ctx, cert.ID, cert.PreviousFingerprint)
	if err != nil {
		slog.Warn("could not look up where a certificate is served", "certificate", cert.ID, "error", err)
		v.record(ctx, cert, store.VerificationUpdate{
			State:       cert.VerificationState,
			Detail:      cert.VerificationDetail,
			CheckedAt:   now,
			VerifyAfter: timePtr(now.Add(verifyBackoff[0])),
			Attempts:    cert.VerificationAttempts,
		})
		return
	}

	if len(endpoints) == 0 {
		// Said plainly and then dropped. "We cannot verify this" is a useful
		// sentence; rechecking a certificate nothing has ever observed, every
		// hour, forever, is not.
		v.record(ctx, cert, store.VerificationUpdate{
			State: store.VerificationNoEndpoints,
			Detail: "No scan has ever seen this certificate being served, so there is no endpoint to check it on. " +
				"Run a discovery scan that covers wherever it is deployed and this will start being verified.",
			CheckedAt:   now,
			VerifyAfter: nil,
			Attempts:    attempts,
		})
		return
	}

	result := v.probeAll(ctx, cert, endpoints)

	update := store.VerificationUpdate{
		State:     result.state,
		Detail:    result.detail,
		CheckedAt: now,
		Attempts:  attempts,
	}
	// A verified certificate is finished with. Anything else is rechecked
	// until the schedule runs out — a deployment that has not happened yet may
	// still happen, and a verifier that gave up after one look would report a
	// resolved problem forever.
	if result.state != store.VerificationVerified && attempts < verifyMaxAttempts {
		idx := min(attempts-1, len(verifyBackoff)-1)
		update.VerifyAfter = timePtr(now.Add(verifyBackoff[idx]))
	}
	v.record(ctx, cert, update)

	slog.Info("post-renewal verification complete",
		"certificate", cert.ID, "common_name", cert.CommonName,
		"state", result.state, "endpoints", len(endpoints), "attempt", attempts)

	// Announced on the first check that finds it stale, not on every one. The
	// second and third messages would say the same thing about the same
	// certificate to people who have already been told.
	if result.state == store.VerificationStale && cert.VerificationState != store.VerificationStale {
		v.announceStale(cert, result)
	}
}

// verifyResult is what one pass across a certificate's endpoints concluded.
type verifyResult struct {
	state  string
	detail string
	// stale names the endpoints still serving what this certificate replaced.
	stale []string
}

func (v *Verifier) probeAll(ctx context.Context, cert *store.Certificate, endpoints []string) verifyResult {
	var serving, stale, older, other, unreachable []string

	for _, endpoint := range endpoints {
		target, err := discovery.ParseTarget(endpoint, 443)
		if err != nil {
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, verifyProbeTimeout)
		probe := v.scanner.Probe(probeCtx, target)
		cancel()

		switch {
		case probe.Err != nil || len(probe.Chain) == 0:
			unreachable = append(unreachable, endpoint)
		case fingerprintOf(probe) == cert.FingerprintSHA256:
			serving = append(serving, endpoint)
		case cert.PreviousFingerprint != "" && fingerprintOf(probe) == cert.PreviousFingerprint:
			stale = append(stale, endpoint)
		case coversName(probe, cert.CommonName):
			// An older certificate for the same name. Not the one this renewal
			// replaced — two renewals without a deployment leaves the server
			// further back than that — but unmistakably still one of ours.
			//
			// Kept apart from the case below because the words are the whole
			// value here: telling somebody "something else is terminating TLS"
			// when the truth is "you are two renewals behind" sends them
			// hunting a rogue service that does not exist.
			older = append(older, endpoint)
		default:
			other = append(other, endpoint)
		}
	}

	switch {
	case len(stale) > 0:
		return verifyResult{
			state: store.VerificationStale,
			stale: stale,
			detail: fmt.Sprintf(
				"%s still serving the certificate this renewal replaced. The new certificate exists in CertPilot and has not reached the server, so what users get expires on the old schedule.",
				endpointList(stale)),
		}
	case len(older) > 0:
		return verifyResult{
			state: store.VerificationStale,
			stale: older,
			detail: fmt.Sprintf(
				"%s serving an older certificate for this name — not even the one the last renewal replaced. Renewals have been happening here and reaching nothing, so what users get expires on whatever schedule that older certificate has.",
				endpointList(older)),
		}
	case len(other) > 0:
		return verifyResult{
			state: store.VerificationStale,
			stale: other,
			detail: fmt.Sprintf(
				"%s serving a certificate for a different name entirely. Something other than this certificate is terminating TLS there.",
				endpointList(other)),
		}
	case len(serving) > 0 && len(unreachable) == 0:
		return verifyResult{
			state:  store.VerificationVerified,
			detail: fmt.Sprintf("%s serving the renewed certificate.", endpointList(serving)),
		}
	case len(serving) > 0:
		// Some answered with the new certificate and some did not answer at
		// all. Not verified: the ones that did not answer are exactly the ones
		// that might still be on the old certificate.
		return verifyResult{
			state: store.VerificationUnreachable,
			detail: fmt.Sprintf("%s serving the renewed certificate, but %s did not answer, so this is not confirmed everywhere.",
				endpointList(serving), endpointList(unreachable)),
		}
	default:
		return verifyResult{
			state: store.VerificationUnreachable,
			detail: fmt.Sprintf("%s did not answer, so whether the renewal reached them is unknown. That is not the same as confirming it did.",
				endpointList(unreachable)),
		}
	}
}

func (v *Verifier) record(ctx context.Context, cert *store.Certificate, update store.VerificationUpdate) {
	if err := v.store.UpdateCertificateVerification(ctx, cert.ID, update); err != nil {
		slog.Error("could not record a verification result", "certificate", cert.ID, "error", err)
	}
}

// announceStale publishes the finding this engine exists to produce.
//
// Named as the consequence rather than the observation. "Verification failed"
// is a fact about this checker; "the renewal succeeded and the server is still
// serving the old certificate, which expires on its own schedule" is the thing
// somebody has to act on — and it is the exact shape of outage a renewal engine
// is supposed to prevent.
func (v *Verifier) announceStale(cert *store.Certificate, result verifyResult) {
	if v.broker == nil {
		return
	}

	payload := map[string]any{
		"common_name":    cert.CommonName,
		"certificate_id": cert.ID,
		"endpoints":      result.stale,
		"detail":         result.detail,
		"days_remaining": cert.DaysRemaining,
	}
	if cert.NotAfter != nil {
		payload["not_after"] = cert.NotAfter.Format(time.RFC3339)
	}

	v.broker.Publish(events.Event{
		Topic:    events.TopicCertNotDeployed,
		Severity: events.SeverityCritical,
		EntityID: cert.ID,
		Payload:  payload,
	})
}

func fingerprintOf(probe *discovery.Probe) string {
	if probe == nil || len(probe.Chain) == 0 {
		return ""
	}
	return discovery.FingerprintSHA256(probe.Chain[0])
}

// endpointList renders endpoints the way somebody would have to go and look at
// them, bounded so one alert cannot become a wall of hostnames.
func endpointList(endpoints []string) string {
	switch len(endpoints) {
	case 0:
		return "no endpoints"
	case 1:
		return endpoints[0] + " is"
	}
	if len(endpoints) > 5 {
		return fmt.Sprintf("%s and %d more are", strings.Join(endpoints[:5], ", "), len(endpoints)-5)
	}
	return strings.Join(endpoints, ", ") + " are"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// coversName reports whether the certificate an endpoint presented is valid for
// the name this record is about.
//
// The question being answered is "is this still one of ours, just older?" — so
// it checks what the served certificate claims to be, not whether it verifies.
// An expired or untrusted certificate for the right name is still an older copy
// of this certificate, and it is the case most worth naming precisely.
func coversName(probe *discovery.Probe, commonName string) bool {
	if probe == nil || len(probe.Chain) == 0 || commonName == "" {
		return false
	}
	leaf := probe.Chain[0]
	if strings.EqualFold(leaf.Subject.CommonName, commonName) {
		return true
	}
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, commonName) {
			return true
		}
	}
	return leaf.VerifyHostname(commonName) == nil
}
