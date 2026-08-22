package deploy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// boundTo builds one certificate bound to n webhook targets.
func boundTo(t *testing.T, n int, onRenewal bool) (*store.MemoryStore, *store.Certificate) {
	t.Helper()
	st := store.NewMemoryStore()
	ctx := context.Background()

	pem := "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	cert := &store.Certificate{
		CommonName: "shop.example.com", FingerprintSHA256: "new",
		Status: "ISSUED", CertificatePEM: &pem, NotAfter: &notAfter,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("certificate: %v", err)
	}

	for i := 0; i < n; i++ {
		target := &store.DeploymentTarget{
			Name: string(rune('a'+i)) + "-lb", TargetType: TypeWebhook, IsEnabled: true,
		}
		if err := st.CreateDeploymentTarget(ctx, target); err != nil {
			t.Fatalf("target: %v", err)
		}
		if err := st.CreateCertificateDeployment(ctx, &store.CertificateDeployment{
			CertificateID: cert.ID, TargetID: target.ID,
			IsEnabled: true, DeployOnRenewal: onRenewal,
		}); err != nil {
			t.Fatalf("binding: %v", err)
		}
	}
	return st, cert
}

// TestARenewalReachesEveryPlaceTheCertificateBelongs.
func TestARenewalReachesEveryPlaceTheCertificateBelongs(t *testing.T) {
	st, cert := boundTo(t, 3, true)

	out, err := EnqueueFor(context.Background(), st, cert, store.DeployReasonRenewal, nil, nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if out.Queued != 3 || out.OptedOut != 0 {
		t.Fatalf("expected three jobs, got %+v", out)
	}
	for _, job := range out.Jobs {
		if job.Reason != store.DeployReasonRenewal {
			t.Fatalf("a renewal's jobs should say so, got %q", job.Reason)
		}
	}
}

// TestABindingThatDoesNotDeployOnRenewalIsSaidOutLoud.
//
// Migration 023 switched every pre-existing binding to manual so that an
// upgrade could not begin writing to production servers by itself. The cost of
// that is a switch nobody turns on, and it is paid in words: silence here would
// be a place quietly holding an older certificate for ever.
func TestABindingThatDoesNotDeployOnRenewalIsSaidOutLoud(t *testing.T) {
	st, cert := boundTo(t, 2, false)

	out, err := EnqueueFor(context.Background(), st, cert, store.DeployReasonRenewal, nil, nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if out.Queued != 0 || out.OptedOut != 2 {
		t.Fatalf("expected nothing queued and two opted out, got %+v", out)
	}
	message := RolloutMessage(cert.CommonName, out)
	if !strings.Contains(message, "not set to deploy on renewal") ||
		!strings.Contains(message, "older certificate") {
		t.Fatalf("the message should name the consequence: %q", message)
	}

	// The same bindings still deploy when somebody asks.
	manual, err := EnqueueFor(context.Background(), st, cert, store.DeployReasonManual, nil, nil)
	if err != nil {
		t.Fatalf("manual: %v", err)
	}
	if manual.Queued != 2 {
		t.Fatalf("a manual deploy should reach both, got %+v", manual)
	}
}

// TestOneFailingTargetStopsTheRolloutAndTheRestResume.
//
// The canary, and it needs no configuration to exist. One bad renewal must
// reach one listener rather than forty — and the other thirty-nine must start
// again by themselves the moment it clears, or the safety feature becomes an
// outage of its own.
func TestOneFailingTargetStopsTheRolloutAndTheRestResume(t *testing.T) {
	st, cert := boundTo(t, 5, true)
	ctx := context.Background()

	if _, err := EnqueueFor(ctx, st, cert, store.DeployReasonRenewal, nil, nil); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	now := time.Now()
	first, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, now)
	if err != nil || first == nil {
		t.Fatalf("expected a job to claim: %v", err)
	}

	// It fails, and goes back to PENDING with a retry — the queue never gives
	// up on a deployment, because the certificate expires either way.
	if err := st.CompleteDeploymentJob(ctx, first.ID, store.DeployPending,
		store.DeploymentAttempt{Number: 1, Error: "the receiver refused it"},
		now.Add(-time.Second), false); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Nothing else may start. Four targets are bound, ready, and deliberately
	// still holding what they had.
	//
	// The lease is negative so it has already expired on arrival, which is how
	// a failing job keeps coming back around. Claiming with a real lease would
	// hand out the retry once and then answer nil, and a test that accepted nil
	// would pass just as happily against a queue that had stopped entirely.
	retries := 0
	for i := 0; i < 4; i++ {
		job, err := st.ClaimDeploymentJob(ctx, "worker-2", -time.Second, now)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if job == nil {
			t.Fatal("the failing job should keep retrying; the queue never gives up on a deployment")
		}
		if job.ID != first.ID {
			t.Fatalf("a fresh target was deployed to while another was failing: %s", job.ID)
		}
		retries++
	}
	if retries != 4 {
		t.Fatalf("expected the failing job back every time, got %d", retries)
	}

	// It succeeds, and the rest go.
	if err := st.CompleteDeploymentJob(ctx, first.ID, store.DeploySucceeded,
		store.DeploymentAttempt{Number: 6, Detail: "installed"}, now, false); err != nil {
		t.Fatalf("complete: %v", err)
	}
	next, err := st.ClaimDeploymentJob(ctx, "worker-2", time.Minute, now)
	if err != nil || next == nil {
		t.Fatalf("the rest of the rollout should resume once the failure clears: %v", err)
	}
}

// TestVerificationIsBroughtForwardOnlyWhenEveryPlaceHasIt.
//
// A partial rollout verified early is a STALE nobody needed to see, and the fix
// for a false one costs the same afternoon as the fix for a real one.
func TestVerificationIsBroughtForwardOnlyWhenEveryPlaceHasIt(t *testing.T) {
	st, cert := boundTo(t, 2, true)
	ctx := context.Background()

	far := time.Now().Add(30 * time.Minute).UTC()
	if err := st.UpdateCertificateVerification(ctx, cert.ID, store.VerificationUpdate{
		State: store.VerificationPending, CheckedAt: time.Now(), VerifyAfter: &far,
	}); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	bindings, _ := st.ListCertificateDeployments(ctx, cert.ID)
	if err := st.RecordDeploymentOutcome(ctx, bindings[0].ID, store.DeploymentOutcome{
		Status: store.DeploymentDeployed, Fingerprint: cert.FingerprintSHA256, At: time.Now(),
	}); err != nil {
		t.Fatalf("outcome: %v", err)
	}

	if Settled(ctx, st, cert.ID) {
		t.Fatal("one of two places is not every place")
	}
	after, _ := st.GetCertificate(ctx, cert.ID)
	if after.VerifyAfter == nil || !after.VerifyAfter.Equal(far) {
		t.Fatalf("a partial rollout moved the check to %v", after.VerifyAfter)
	}

	if err := st.RecordDeploymentOutcome(ctx, bindings[1].ID, store.DeploymentOutcome{
		Status: store.DeploymentDeployed, Fingerprint: cert.FingerprintSHA256, At: time.Now(),
	}); err != nil {
		t.Fatalf("outcome: %v", err)
	}
	if !Settled(ctx, st, cert.ID) {
		t.Fatal("every place holds it now")
	}
	after, _ = st.GetCertificate(ctx, cert.ID)
	if after.VerifyAfter == nil || !after.VerifyAfter.Before(far) {
		t.Fatalf("the check should have been brought forward, got %v", after.VerifyAfter)
	}
}

// TestADisabledBindingIsNotAnOptedOutOne.
//
// Two different answers to "why did nothing happen here", with two different
// fixes: somebody switched the target off, or nobody has turned the automatic
// switch on. Folding them together would send half the readers to the wrong
// page.
func TestADisabledBindingIsNotAnOptedOutOne(t *testing.T) {
	st, cert := boundTo(t, 2, true)
	ctx := context.Background()

	bindings, _ := st.ListCertificateDeployments(ctx, cert.ID)
	bindings[0].IsEnabled = false
	if err := st.CreateCertificateDeployment(ctx, bindings[0]); err != nil {
		t.Fatalf("update: %v", err)
	}
	bindings[1].DeployOnRenewal = false
	if err := st.CreateCertificateDeployment(ctx, bindings[1]); err != nil {
		t.Fatalf("update: %v", err)
	}

	out, err := EnqueueFor(ctx, st, cert, store.DeployReasonRenewal, nil, nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if out.Skipped != 1 || out.OptedOut != 1 {
		t.Fatalf("expected one of each, got %+v", out)
	}
	message := RolloutMessage(cert.CommonName, out)
	if !strings.Contains(message, "switched off") ||
		!strings.Contains(message, "not set to deploy on renewal") {
		t.Fatalf("both reasons belong in the message: %q", message)
	}
}
