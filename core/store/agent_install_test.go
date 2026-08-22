package store

import (
	"context"
	"testing"
	"time"
)

// agentWithJob sets up one host, one certificate installed on it, and one
// deployment job waiting.
func agentWithJob(t *testing.T, st *MemoryStore, name string) (*Agent, *DeploymentJob) {
	t.Helper()
	ctx := context.Background()

	agent := &Agent{Name: name, Hostname: name + ".internal", Status: AgentActive}
	if err := st.CreateAgent(ctx, agent); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	pem := "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
	cert := &Certificate{
		CommonName: name + ".example.com", FingerprintSHA256: "fp-" + name,
		Status: "ISSUED", CertificatePEM: &pem,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	target, err := st.EnsureAgentDeploymentTarget(ctx, agent)
	if err != nil {
		t.Fatalf("ensure target: %v", err)
	}
	binding, err := st.EnsureCertificateDeployment(ctx, &CertificateDeployment{
		CertificateID: cert.ID, TargetID: target.ID, IsEnabled: true,
		Options: map[string]any{"destinations": []any{"nginx"}},
	})
	if err != nil {
		t.Fatalf("ensure binding: %v", err)
	}

	job := &DeploymentJob{
		DeploymentID: binding.ID, CertificateID: cert.ID, TargetID: target.ID,
		Reason: "MANUAL", Status: DeployPending, RunAfter: time.Now().Add(-time.Minute),
	}
	if _, err := st.EnqueueDeployment(ctx, job); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return agent, job
}

// TestACoreWorkerNeverClaimsAJobForAHostItCannotReach.
//
// The defect this exclusion exists to prevent has happened twice in this
// project in a different guise: a sweep claiming work it has no way to do and
// failing it until the attempt budget runs out, being loudly wrong about
// something that in fact works. A core worker cannot open a connection to a
// machine behind two firewalls, which is the whole reason that machine runs an
// agent.
func TestACoreWorkerNeverClaimsAJobForAHostItCannotReach(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	agentWithJob(t, st, "web-01")

	claimed, err := st.ClaimDeploymentJob(ctx, "core-replica-1", time.Minute, time.Now())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed != nil {
		t.Fatalf("a core worker claimed an agent's job: %+v", claimed)
	}
}

// TestAHostClaimsItsOwnWorkAndNobodyElses.
func TestAHostClaimsItsOwnWorkAndNobodyElses(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	first, firstJob := agentWithJob(t, st, "web-01")
	second, _ := agentWithJob(t, st, "web-02")

	mine, err := st.ClaimAgentDeploymentJobs(ctx, first.ID, "agent web-01", 10*time.Minute, time.Now(), 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(mine) != 1 || mine[0].ID != firstJob.ID {
		t.Fatalf("expected web-01's own job, got %d", len(mine))
	}
	if mine[0].Status != DeployRunning || mine[0].LockedUntil == nil {
		t.Fatal("claiming should take a lease")
	}

	// The second host asking again must not be handed the first host's work,
	// and the first host's job must not be offered twice while it is leased.
	theirs, err := st.ClaimAgentDeploymentJobs(ctx, second.ID, "agent web-02", 10*time.Minute, time.Now(), 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	for _, job := range theirs {
		if job.ID == firstJob.ID {
			t.Fatal("one host was handed another host's deployment")
		}
	}

	again, _ := st.ClaimAgentDeploymentJobs(ctx, first.ID, "agent web-01", 10*time.Minute, time.Now(), 10)
	if len(again) != 0 {
		t.Fatalf("a leased job was offered again, %d times", len(again))
	}
}

// TestAnAgentTargetIsTheSameTargetTwice.
//
// Renaming a host in the core must not turn it into a second place its
// certificates are deployed to.
func TestAnAgentTargetIsTheSameTargetTwice(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	agent := &Agent{Name: "web-01", Status: AgentActive}
	if err := st.CreateAgent(ctx, agent); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	first, err := st.EnsureAgentDeploymentTarget(ctx, agent)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	agent.Name = "web-01-renamed"
	second, err := st.EnsureAgentDeploymentTarget(ctx, agent)
	if err != nil {
		t.Fatalf("ensure again: %v", err)
	}
	if first.ID != second.ID {
		t.Fatal("a renamed host became a second deployment target")
	}
}
