package deploy

import (
	"context"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// inWaves builds one certificate bound to targets in the given waves, named by
// their position so a test can say which one ran.
func inWaves(t *testing.T, waves ...int) (*store.MemoryStore, *store.Certificate, []string) {
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
		t.Fatal(err)
	}

	names := make([]string, 0, len(waves))
	for i, wave := range waves {
		target := &store.DeploymentTarget{
			Name:        string(rune('a'+i)) + "-lb",
			TargetType:  TypeWebhook,
			IsEnabled:   true,
			DeployOrder: wave,
		}
		if err := st.CreateDeploymentTarget(ctx, target); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateCertificateDeployment(ctx, &store.CertificateDeployment{
			CertificateID: cert.ID, TargetID: target.ID,
			IsEnabled: true, DeployOnRenewal: true,
		}); err != nil {
			t.Fatal(err)
		}
		names = append(names, target.ID)
	}
	return st, cert, names
}

func enqueueAll(t *testing.T, st *store.MemoryStore, cert *store.Certificate) Rollout {
	t.Helper()
	out, err := EnqueueFor(context.Background(), st, cert, store.DeployReasonRenewal, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The wave a target is in must reach the job, or nothing downstream can order
// anything. Read at enqueue rather than joined at claim time, so a rollout
// carries the plan as it stood when it began.
func TestAJobCarriesItsTargetsWave(t *testing.T) {
	st, cert, targets := inWaves(t, 2, 0, 1)
	out := enqueueAll(t, st, cert)

	if out.Queued != 3 {
		t.Fatalf("queued %d, want 3", out.Queued)
	}
	byTarget := map[string]int{}
	for _, job := range out.Jobs {
		byTarget[job.TargetID] = job.DeployOrder
	}
	for i, want := range []int{2, 0, 1} {
		if got := byTarget[targets[i]]; got != want {
			t.Errorf("target %d is in wave %d, job says %d", i, want, got)
		}
	}
}

// "Staging, then production." The later wave must not start while the earlier
// one is still outstanding — which is the whole feature.
func TestALaterWaveWaitsForAnEarlierOne(t *testing.T) {
	st, cert, targets := inWaves(t, 0, 1, 1)
	enqueueAll(t, st, cert)
	ctx := context.Background()

	first, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, time.Now())
	if err != nil || first == nil {
		t.Fatalf("the first wave must be claimable: %v", err)
	}
	if first.TargetID != targets[0] {
		t.Fatalf("claimed a target from wave 1 before wave 0 had run")
	}

	// A second worker, of the sort that used to make the canary
	// one-per-worker: it must find nothing while wave 0 is in flight.
	second, err := st.ClaimDeploymentJob(ctx, "worker-2", time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if second != nil {
		t.Fatalf("a second worker claimed %s while wave 0 was still running", second.TargetID)
	}
}

// A canary is a target on its own in the lowest wave. Exactly one attempt, and
// the rest follow only once it has worked.
func TestACanaryIsOneTargetAloneInTheFirstWave(t *testing.T) {
	st, cert, targets := inWaves(t, 0, 1, 1, 1)
	enqueueAll(t, st, cert)
	ctx := context.Background()

	canary, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, time.Now())
	if err != nil || canary == nil {
		t.Fatal("the canary must be claimable")
	}
	if canary.TargetID != targets[0] {
		t.Fatalf("the canary was not the target in wave 0")
	}

	if err := st.CompleteDeploymentJob(ctx, canary.ID, store.DeploySucceeded,
		store.DeploymentAttempt{Number: 1, StartedAt: time.Now(), Worker: "worker-1"},
		time.Now(), false); err != nil {
		t.Fatal(err)
	}

	// The rest of the estate is now free, and free in parallel.
	claimed := map[string]bool{}
	for i := 0; i < 3; i++ {
		job, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			t.Fatalf("only %d of the three later targets became claimable after the canary passed", i)
		}
		claimed[job.TargetID] = true
	}
	for _, id := range targets[1:] {
		if !claimed[id] {
			t.Errorf("target %s never ran after the canary succeeded", id)
		}
	}
}

// The reason a canary exists. A certificate the first wave would not accept
// must not reach the ones behind it, and it must stay stopped rather than
// resuming on a timer.
func TestAFailedEarlierWaveStopsTheOnesBehindIt(t *testing.T) {
	st, cert, _ := inWaves(t, 0, 1)
	enqueueAll(t, st, cert)
	ctx := context.Background()

	canary, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, time.Now())
	if err != nil || canary == nil {
		t.Fatal("the canary must be claimable")
	}

	// Give up on it, the way the queue does once the attempt budget is spent.
	if err := st.CompleteDeploymentJob(ctx, canary.ID, store.DeployFailed,
		store.DeploymentAttempt{Number: 1, StartedAt: time.Now(), Worker: "worker-1"},
		time.Now(), true); err != nil {
		t.Fatal(err)
	}
	failed, err := st.GetDeploymentJob(ctx, canary.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Status != store.DeployFailed {
		t.Fatalf("setup: canary status = %q, want FAILED", failed.Status)
	}

	// Production stays untouched. Deliberately stricter than the same-wave
	// rule, where a terminally failed job stops blocking its peers.
	next, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if next != nil {
		t.Fatalf("wave 1 ran after wave 0 gave up; a certificate staging refused reached %s", next.TargetID)
	}
}

// Everything in one wave is the default and every deployment that existed
// before waves did. It must behave exactly as it did — parallel, with the
// failure pause as the safety net.
func TestOneWaveBehavesAsBefore(t *testing.T) {
	st, cert, _ := inWaves(t, 0, 0, 0)
	enqueueAll(t, st, cert)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		job, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			t.Fatalf("only %d of three same-wave jobs were claimable; waves must not serialise the default", i)
		}
	}
}

// Ordering has to hold for the agent path too. An agent polls for its own work
// and would otherwise install while an earlier wave was still being attempted
// from the core — the declared order holding for half the estate.
func TestAnAgentTargetRespectsItsWave(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	pem := "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	cert := &store.Certificate{
		CommonName: "shop.example.com", FingerprintSHA256: "new",
		Status: "ISSUED", CertificatePEM: &pem, NotAfter: &notAfter,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}

	// Wave 0 is a core-deployed webhook; wave 1 is a host running an agent.
	core := &store.DeploymentTarget{Name: "staging-lb", TargetType: TypeWebhook, IsEnabled: true, DeployOrder: 0}
	if err := st.CreateDeploymentTarget(ctx, core); err != nil {
		t.Fatal(err)
	}
	agent := &store.Agent{Name: "prod-web-01", PublicKey: "k", KeyID: "k1", Status: store.AgentActive}
	if err := st.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	agentTarget, err := st.EnsureAgentDeploymentTarget(ctx, agent)
	if err != nil {
		t.Fatal(err)
	}
	agentTarget.DeployOrder = 1
	if err := st.UpdateDeploymentTarget(ctx, agentTarget); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{core.ID, agentTarget.ID} {
		if err := st.CreateCertificateDeployment(ctx, &store.CertificateDeployment{
			CertificateID: cert.ID, TargetID: id, IsEnabled: true, DeployOnRenewal: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	enqueueAll(t, st, cert)

	// The core takes wave 0.
	if job, err := st.ClaimDeploymentJob(ctx, "worker-1", time.Minute, time.Now()); err != nil || job == nil {
		t.Fatalf("wave 0 must be claimable by the core: %v", err)
	}

	// The agent polls and must find nothing.
	jobs, err := st.ClaimAgentDeploymentJobs(ctx, agent.ID, "agent-worker", time.Minute, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("an agent in wave 1 claimed %d job(s) while wave 0 was still running", len(jobs))
	}
}
