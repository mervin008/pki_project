package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// DeployedVerifyGrace is how long after a deployment the first check waits.
//
// Minutes rather than the half hour a renewal waits. That grace exists because
// deployment used to be a human being doing something later; once CertPilot has
// installed the certificate itself, the only remaining delay is the far side
// picking it up, which is a reload.
//
// Not zero, and the difference matters. A verification that runs the instant a
// deployer returns would report the reload it did not wait for, and the fix for
// a false STALE is the same as the fix for a real one — somebody's afternoon.
const DeployedVerifyGrace = 3 * time.Minute

// Rollout enqueues a certificate's deployments and reports what it did.
//
// One function for both triggers. A renewal and an operator pressing deploy
// differ in exactly one field — the reason — and everything that makes
// deployment safe has to apply identically to both. Two code paths would mean
// the automatic one eventually diverging from the one people test by hand.
type Rollout struct {
	Queued  int
	Already int
	// Skipped is bindings that are switched off, and OptedOut is bindings that
	// are on but do not deploy automatically. Kept apart because they are
	// different answers to "why did nothing happen here": one is a target
	// somebody disabled, the other is a switch nobody has turned on.
	Skipped  int
	OptedOut int
	Jobs     []*store.DeploymentJob
}

// Total is how many places this certificate is bound to.
func (r Rollout) Total() int { return r.Queued + r.Already + r.Skipped + r.OptedOut }

// EnqueueFor queues a deployment of one certificate to every place it belongs.
//
// Called directly by the renewal executor rather than driven off an event.
// The broker drops the oldest event on a slow consumer, which is the right
// policy for a wall display and precisely the wrong one here: a dropped event
// would be a certificate that renewed and silently never deployed, which is the
// exact failure this whole phase exists to prevent, produced by the machinery
// meant to prevent it.
func EnqueueFor(ctx context.Context, s store.Store, cert *store.Certificate,
	reason string, actor *string, actorEmail *string) (Rollout, error) {

	var out Rollout

	bindings, err := s.ListCertificateDeployments(ctx, cert.ID)
	if err != nil {
		return out, err
	}

	automatic := reason == store.DeployReasonRenewal
	now := time.Now()

	for _, binding := range bindings {
		switch {
		case !binding.IsEnabled:
			out.Skipped++
			continue
		case automatic && !binding.DeployOnRenewal:
			// Not an error and not silence. This place holds an older
			// certificate now, and will go on holding it until somebody
			// deploys by hand — which is worth saying in the summary rather
			// than discovering from an expiry alert.
			out.OptedOut++
			continue
		}

		job := &store.DeploymentJob{
			DeploymentID:  binding.ID,
			CertificateID: cert.ID,
			TargetID:      binding.TargetID,
			Reason:        reason,
			Status:        store.DeployPending,
			RunAfter:      now,
			// Provenance, not selection. What gets installed is the certificate
			// as it stands when the job runs; see the note on Bundle.
			Fingerprint: cert.FingerprintSHA256,
			NotAfter:    cert.NotAfter,
			TriggeredBy: actor,
			ActorEmail:  actorEmail,
		}

		created, err := s.EnqueueDeployment(ctx, job)
		if err != nil {
			return out, err
		}
		if created {
			out.Queued++
		} else {
			// A job was already outstanding for this place. Not a problem and
			// not a lost deployment: the outstanding one installs whatever the
			// certificate is when it runs, which is this one.
			out.Already++
		}
		out.Jobs = append(out.Jobs, job)
	}
	return out, nil
}

// Settled reports whether every place this certificate belongs is holding it,
// and brings its verification forward when they are.
//
// Called after a deployment succeeds. Until this existed, a renewal scheduled
// its check half an hour out because deployment was a person doing something
// later; now that CertPilot has installed the certificate itself, waiting the
// full half hour to look means the answer to "did it land" arrives long after
// anybody could have acted on it.
//
// The check is not moved *earlier* than it already is, only later-to-sooner. A
// certificate whose verification has already run and backed off is not dragged
// back to the front of the queue by an unrelated deployment.
func Settled(ctx context.Context, s store.Store, certificateID string) bool {
	cert, err := s.GetCertificate(ctx, certificateID)
	if err != nil {
		return false
	}
	bindings, err := s.ListCertificateDeployments(ctx, certificateID)
	if err != nil || len(bindings) == 0 {
		return false
	}

	for _, binding := range bindings {
		if !binding.IsEnabled {
			continue
		}
		if binding.DeployedFingerprint != cert.FingerprintSHA256 {
			return false
		}
	}

	verifyAt := time.Now().Add(DeployedVerifyGrace)
	if cert.VerifyAfter != nil && cert.VerifyAfter.Before(verifyAt) {
		return true
	}
	if err := s.UpdateCertificateVerification(ctx, certificateID, store.VerificationUpdate{
		State:       store.VerificationPending,
		CheckedAt:   time.Now(),
		VerifyAfter: &verifyAt,
	}); err != nil {
		slog.Warn("a certificate reached every place it belongs but its check could not be brought forward",
			"certificate", certificateID, "error", err)
		return true
	}

	slog.Info("a certificate is now at every place it is bound to; checking that it is being served",
		"common_name", cert.CommonName, "checking_in", DeployedVerifyGrace)
	return true
}

// RolloutMessage says what a trigger actually did, including what it did not do.
//
// "Queued" over an estate where three of five bindings are switched off and one
// does not deploy automatically is the kind of half-truth that gets believed —
// and the two silent cases have different fixes.
func RolloutMessage(commonName string, r Rollout) string {
	if r.Total() == 0 {
		return fmt.Sprintf(
			"%s is not bound to any deployment target, so nothing was queued and a renewal will reach nothing.",
			commonName)
	}

	parts := []string{}
	if r.Queued > 0 {
		parts = append(parts, fmt.Sprintf("queued for %s", placesText(r.Queued)))
	}
	if r.Already > 0 {
		parts = append(parts, fmt.Sprintf("%s already had a deployment outstanding", placesText(r.Already)))
	}
	if r.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%s switched off", placesText(r.Skipped)))
	}
	if r.OptedOut > 0 {
		parts = append(parts, fmt.Sprintf(
			"%s not set to deploy on renewal, and now hold an older certificate", placesText(r.OptedOut)))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Nothing was queued for %s.", commonName)
	}

	out := commonName + ": " + parts[0]
	for _, part := range parts[1:] {
		out += "; " + part
	}
	return out + "."
}

// placesText counts targets in words a person reads.
func placesText(n int) string {
	if n == 1 {
		return "1 target"
	}
	return fmt.Sprintf("%d targets", n)
}
