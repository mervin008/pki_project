package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// A conformance suite: one set of tests, run against every implementation of
// Store.
//
// This exists because of a pattern that has repeated in every phase of this
// project. Ten defects have now reached a live database that the test suite
// could not express, and they were not ten unrelated mistakes — they were six
// instances of four classes:
//
//	A. A Go constant the database's CHECK constraint refuses.
//	   (migrations 012, 021, 022, 024)
//	B. A model field a writer does not persist.
//	   (migration 016; and later the in-memory store dropping deploy_on_renewal)
//	C. An empty Go string written into a column whose CHECK passes on NULL.
//	   (certificates.environment, the very first live run)
//	D. A bound parameter PostgreSQL types differently from the driver.
//	   (the CA expiry window; migration 018's interval)
//
// Testing the in-memory store alone cannot find any of them, because the
// in-memory store has no constraints, no column lists, no NULL, and no type
// inference. Testing PostgreSQL alone would find A, C and D but not B in the
// direction that actually bit — the memory store silently dropping a field the
// database persists correctly.
//
// So the shape is: the same assertions, both implementations, and the classes
// tested generatively where possible. `TestEveryValueThisCodebaseCanProduceIsAccepted`
// is the one that matters most: it does not check that `'AGENT'` works, it
// checks that *every* value the Go code can produce is one the schema accepts,
// so the next widening is caught before it ships rather than by a live run.

// implementation is one Store to run the suite against.
type implementation struct {
	name string
	// fresh returns an empty store. For PostgreSQL that means a database of its
	// own, migrated from the repository's own migration files, dropped
	// afterwards — the schema under test is the schema that ships.
	fresh func(t *testing.T) Store
}

// implementations returns every Store this build can exercise.
//
// PostgreSQL is included only when CERTPILOT_TEST_DB_URL points at a server the
// suite may create and drop databases on. It is skipped rather than failed when
// absent, because a test that needs a database server should not stop somebody
// running the unit tests on a train — but `make test-store` sets it up, and CI
// has no excuse.
func implementations(t *testing.T) []implementation {
	t.Helper()

	out := []implementation{{
		name:  "memory",
		fresh: func(t *testing.T) Store { return NewMemoryStore() },
	}}

	if url := os.Getenv("CERTPILOT_TEST_DB_URL"); url != "" {
		out = append(out, implementation{
			name:  "postgres",
			fresh: func(t *testing.T) Store { return freshPostgres(t, url) },
		})
	}
	return out
}

// forEachStore runs one test body against every implementation.
func forEachStore(t *testing.T, body func(t *testing.T, s Store)) {
	t.Helper()
	impls := implementations(t)
	for _, impl := range impls {
		t.Run(impl.name, func(t *testing.T) { body(t, impl.fresh(t)) })
	}
	if len(impls) == 1 {
		t.Log("PostgreSQL not exercised; set CERTPILOT_TEST_DB_URL to include it")
	}
}

// ── Class A: values the database might refuse ───────────────

// TestEveryValueThisCodebaseCanProduceIsAccepted is the test that would have
// prevented four migrations.
//
// Not "does AGENT work" — that is the shape of test written *after* a defect,
// and it passes for ever while the next value fails the same way. This asserts
// the invariant the defects actually violated: **a value the Go code can write
// must be a value the schema accepts.** A new constant added without widening
// its constraint fails here, on a laptop, before it reaches a database.
func TestEveryValueThisCodebaseCanProduceIsAccepted(t *testing.T) {
	// Each case writes a row carrying one value into one CHECK-constrained
	// column. The lists are the Go constants, not the SQL — reading them from
	// the SQL would make the test agree with the schema by construction and
	// assert nothing.
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		t.Run("certificate status", func(t *testing.T) {
			for _, status := range []string{
				"PENDING", "ISSUED", "EXPIRING", "EXPIRED", "REVOKED", "RENEWAL_FAILED",
			} {
				cert := sampleCertificate(fmt.Sprintf("status-%s", status))
				cert.Status = status
				if err := s.CreateCertificate(ctx, cert); err != nil {
					t.Errorf("status %q is written by this codebase and refused by the store: %v", status, err)
				}
			}
		})

		t.Run("discovered via", func(t *testing.T) {
			// Migration 012 widened this for CLOUD. Migration 021 widened it
			// again for AGENT. Both were found by a live run.
			for _, via := range []string{"MANUAL", "SCAN", "CT_LOG", "IMPORT", "REQUESTED", "CLOUD", "AGENT"} {
				cert := sampleCertificate("via-" + via)
				cert.DiscoveredVia = via
				if err := s.CreateCertificate(ctx, cert); err != nil {
					t.Errorf("discovered_via %q is written by this codebase and refused by the store: %v", via, err)
				}
			}
		})

		t.Run("key custody", func(t *testing.T) {
			for _, custody := range []string{KeyCustodyCertPilot, KeyCustodyAgent, KeyCustodyExternal} {
				cert := sampleCertificate("custody-" + custody)
				cert.KeyCustody = custody
				if err := s.CreateCertificate(ctx, cert); err != nil {
					t.Errorf("key_custody %q is refused: %v", custody, err)
				}
			}
		})

		t.Run("deployment target type", func(t *testing.T) {
			// Migration 022 widened this for 'agent'; migration 024 for 'f5',
			// one migration after 022 predicted there would be more.
			for _, targetType := range []string{
				"webhook", "agent", "aws_acm", "azure_key_vault", "f5",
			} {
				target := &DeploymentTarget{
					Name: "target-" + targetType, TargetType: targetType, IsEnabled: true,
				}
				if err := s.CreateDeploymentTarget(ctx, target); err != nil {
					t.Errorf("target_type %q is offered by deploy.Types() and refused by the store: %v",
						targetType, err)
				}
			}
		})

		t.Run("deployment job status and reason", func(t *testing.T) {
			cert := sampleCertificate("job-values")
			if err := s.CreateCertificate(ctx, cert); err != nil {
				t.Fatal(err)
			}
			target := &DeploymentTarget{Name: "job-values", TargetType: "webhook", IsEnabled: true}
			if err := s.CreateDeploymentTarget(ctx, target); err != nil {
				t.Fatal(err)
			}

			for _, reason := range []string{
				DeployReasonRenewal, DeployReasonManual, DeployReasonRetry, DeployReasonDrift,
			} {
				binding := &CertificateDeployment{
					CertificateID: cert.ID, TargetID: target.ID, IsEnabled: true,
				}
				if err := s.CreateCertificateDeployment(ctx, binding); err != nil {
					t.Fatal(err)
				}
				job := &DeploymentJob{
					DeploymentID: binding.ID, CertificateID: cert.ID, TargetID: target.ID,
					Reason: reason, Status: DeployPending, RunAfter: time.Now(),
				}
				if _, err := s.EnqueueDeployment(ctx, job); err != nil {
					t.Errorf("deployment reason %q is refused: %v", reason, err)
				}
				_ = s.DeleteCertificateDeployment(ctx, binding.ID)
			}
		})

		t.Run("agent installation status", func(t *testing.T) {
			agent := &Agent{Name: "install-values", Status: AgentActive}
			if err := s.CreateAgent(ctx, agent); err != nil {
				t.Fatal(err)
			}
			installs := []*AgentInstallation{}
			for i, status := range []string{InstallInstalled, InstallFailed, InstallUnfulfilled} {
				installs = append(installs, &AgentInstallation{
					AgentID: agent.ID, Name: fmt.Sprintf("dest-%d", i),
					CertificateName: "x.example.com", Status: status, ReportedAt: time.Now(),
				})
			}
			if err := s.ReplaceAgentInstallations(ctx, agent.ID, installs); err != nil {
				t.Errorf("an installation status this codebase produces is refused: %v", err)
			}
		})
	})
}

// TestAnUnsetEnvironmentIsAcceptable — class C, and the very first defect this
// project found against a real database.
//
// `certificates.environment` is nullable with a CHECK constraint. The Go field
// is a plain string, so a request that named no environment wrote `”` — and a
// CHECK passes on NULL and fails on the empty string. Every certificate request
// without an explicit environment was rejected by the database, and every one
// of them passed against the in-memory store.
func TestAnUnsetEnvironmentIsAcceptable(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		unset := sampleCertificate("no-environment")
		unset.Environment = ""
		if err := s.CreateCertificate(ctx, unset); err != nil {
			t.Fatalf("a certificate with no environment must be storable: %v", err)
		}

		for _, environment := range []string{"production", "staging", "development"} {
			cert := sampleCertificate("env-" + environment)
			cert.Environment = environment
			if err := s.CreateCertificate(ctx, cert); err != nil {
				t.Errorf("environment %q is refused: %v", environment, err)
			}
		}
	})
}

// ── Class B: fields a writer might drop ─────────────────────

// TestAnUpdateKeepsEveryFieldItWasGiven — the defect migration 016 exists for,
// and the one the in-memory store committed in the other direction.
//
// `UpdateCertificate` has an explicit column list. A field added to the model
// and not to that list is written by nothing and read back as whatever was
// there before — no error, no warning, and the in-memory store cannot show it
// because it stores whole structs. The same class bit the memory store when
// `deploy_on_renewal` was added to the binding model and not to the update path
// that copies fields onto an existing row.
//
// Round-tripping every field is the only shape of test that catches both
// directions at once.
func TestAnUpdateKeepsEveryFieldItWasGiven(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		cert := sampleCertificate("round-trip")
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}

		// Every field a caller can set, changed to something distinguishable.
		later := time.Now().Add(400 * 24 * time.Hour).UTC().Truncate(time.Second)
		leadDays := 45
		cert.CommonName = "changed.example.com"
		cert.SANs = []string{"changed.example.com", "also.example.com"}
		cert.SerialNumber = "deadbeef"
		cert.IssuerDN = "CN=Changed Issuer"
		cert.NotAfter = &later
		cert.DaysRemaining = 400
		cert.KeyType = "RSA"
		cert.KeySize = 4096
		cert.Status = "EXPIRING"
		cert.AutoRenew = false
		cert.RenewalLeadDays = leadDays
		cert.Environment = "staging"
		cert.Team = "platform"
		cert.Tags = []string{"one", "two"}
		cert.KeyCustody = KeyCustodyAgent

		if err := s.UpdateCertificate(ctx, cert); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := s.GetCertificate(ctx, cert.ID)
		if err != nil {
			t.Fatal(err)
		}

		for _, field := range []struct {
			name       string
			want, have any
		}{
			{"common_name", cert.CommonName, got.CommonName},
			{"serial_number", cert.SerialNumber, got.SerialNumber},
			{"issuer_dn", cert.IssuerDN, got.IssuerDN},
			{"days_remaining", cert.DaysRemaining, got.DaysRemaining},
			{"key_type", cert.KeyType, got.KeyType},
			{"key_size", cert.KeySize, got.KeySize},
			{"status", cert.Status, got.Status},
			{"auto_renew", cert.AutoRenew, got.AutoRenew},
			{"renewal_lead_days", cert.RenewalLeadDays, got.RenewalLeadDays},
			{"environment", cert.Environment, got.Environment},
			{"team", cert.Team, got.Team},
			{"key_custody", cert.KeyCustody, got.KeyCustody},
			{"sans", fmt.Sprint(cert.SANs), fmt.Sprint(got.SANs)},
			{"tags", fmt.Sprint(cert.Tags), fmt.Sprint(got.Tags)},
		} {
			if fmt.Sprint(field.want) != fmt.Sprint(field.have) {
				t.Errorf("%s was dropped by the update: wrote %v, read back %v",
					field.name, field.want, field.have)
			}
		}
		if got.NotAfter == nil || !got.NotAfter.UTC().Truncate(time.Second).Equal(later) {
			t.Errorf("not_after was dropped by the update: wrote %v, read back %v", later, got.NotAfter)
		}
	})
}

// TestABindingKeepsEveryFieldItWasGiven is the same assertion for the model
// that actually suffered it in the in-memory store.
func TestABindingKeepsEveryFieldItWasGiven(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		cert := sampleCertificate("binding-round-trip")
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}
		target := &DeploymentTarget{Name: "binding-round-trip", TargetType: "webhook", IsEnabled: true}
		if err := s.CreateDeploymentTarget(ctx, target); err != nil {
			t.Fatal(err)
		}

		binding := &CertificateDeployment{
			CertificateID: cert.ID, TargetID: target.ID,
			IsEnabled: true, DeployOnRenewal: true,
			Options: map[string]any{"destination": "nginx"},
		}
		if err := s.CreateCertificateDeployment(ctx, binding); err != nil {
			t.Fatal(err)
		}

		// The write that dropped a field: the same pair again, with the flag
		// turned off. An implementation that treats this as "already exists,
		// nothing to do" silently ignores the change.
		binding.DeployOnRenewal = false
		binding.IsEnabled = false
		if err := s.CreateCertificateDeployment(ctx, binding); err != nil {
			t.Fatal(err)
		}

		bindings, err := s.ListCertificateDeployments(ctx, cert.ID)
		if err != nil || len(bindings) != 1 {
			t.Fatalf("expected one binding, got %d (%v)", len(bindings), err)
		}
		if bindings[0].DeployOnRenewal {
			t.Error("deploy_on_renewal was dropped by the update; a renewal will deploy where somebody switched that off")
		}
		if bindings[0].IsEnabled {
			t.Error("is_enabled was dropped by the update")
		}
	})
}

// ── Class F: nil versus empty ───────────────────────────────

// TestAnEmptyResultIsAnEmptyListNotNull.
//
// pgx leaves a slice nil when a query returns no rows, and `json.Marshal` turns
// a nil slice into `null` rather than `[]`. The dashboard calls `.map()` on
// that, so an estate with nothing in it rendered as a crash instead of as
// zeros — the first-run defect that is least like a database problem and most
// like a contract one, which is why it belongs in a shared suite rather than a
// PostgreSQL-only one.
func TestAnEmptyResultIsAnEmptyListNotNull(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		certs, _, err := s.ListCertificates(ctx, CertificateFilter{Status: "NOTHING_MATCHES_THIS"})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(certs)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != "[]" {
			t.Errorf("an empty certificate list encodes as %s; anything calling .map() on that crashes", encoded)
		}

		targets, err := s.ListDeploymentTargets(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if encoded, _ := json.Marshal(targets); string(encoded) != "[]" {
			t.Errorf("an empty target list encodes as %s", encoded)
		}
	})
}

// ── Behaviour that must not diverge ─────────────────────────

// TestTheDeploymentQueueBehavesTheSameWayInBothStores.
//
// The halt — a job that has not itself failed waits while another job for the
// same certificate has — is expressed once as a SQL predicate and once as a Go
// loop. Two expressions of one rule is exactly how the in-memory store and the
// database drift, and this is the rule where drifting means a bad certificate
// marching through an estate.
func TestTheDeploymentQueueBehavesTheSameWayInBothStores(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()

		cert := sampleCertificate("queue-behaviour")
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}

		jobs := []*DeploymentJob{}
		for i := 0; i < 3; i++ {
			target := &DeploymentTarget{
				Name: fmt.Sprintf("queue-%d", i), TargetType: "webhook", IsEnabled: true,
			}
			if err := s.CreateDeploymentTarget(ctx, target); err != nil {
				t.Fatal(err)
			}
			binding := &CertificateDeployment{
				CertificateID: cert.ID, TargetID: target.ID, IsEnabled: true, DeployOnRenewal: true,
			}
			if err := s.CreateCertificateDeployment(ctx, binding); err != nil {
				t.Fatal(err)
			}
			job := &DeploymentJob{
				DeploymentID: binding.ID, CertificateID: cert.ID, TargetID: target.ID,
				Reason: DeployReasonRenewal, Status: DeployPending,
				RunAfter: now.Add(-time.Minute),
			}
			if _, err := s.EnqueueDeployment(ctx, job); err != nil {
				t.Fatal(err)
			}
			jobs = append(jobs, job)
		}

		// A second enqueue for a binding that already has one outstanding is a
		// no-op, in both stores, by a partial unique index in one and a loop in
		// the other.
		duplicate := &DeploymentJob{
			DeploymentID: jobs[0].DeploymentID, CertificateID: cert.ID, TargetID: jobs[0].TargetID,
			Reason: DeployReasonManual, Status: DeployPending, RunAfter: now,
		}
		created, err := s.EnqueueDeployment(ctx, duplicate)
		if err != nil {
			t.Fatal(err)
		}
		if created {
			t.Error("a second job for a binding that already has one outstanding must not be created")
		}

		first, err := s.ClaimDeploymentJob(ctx, "worker-1", time.Minute, now)
		if err != nil || first == nil {
			t.Fatalf("expected a claimable job: %v", err)
		}
		if first.Attempts != 1 {
			t.Errorf("claiming should count an attempt, got %d", first.Attempts)
		}

		// It fails and goes back to PENDING.
		if err := s.CompleteDeploymentJob(ctx, first.ID, DeployPending,
			DeploymentAttempt{Number: 1, Error: "the receiver refused it"},
			now.Add(-time.Second), false); err != nil {
			t.Fatal(err)
		}

		// The halt: nothing fresh may start, and the failing one keeps coming
		// back. Claimed with an already-expired lease so the retry is offered
		// repeatedly rather than once.
		for i := 0; i < 3; i++ {
			claimed, err := s.ClaimDeploymentJob(ctx, "worker-2", -time.Second, now)
			if err != nil {
				t.Fatal(err)
			}
			if claimed == nil {
				t.Fatal("the failing job should keep being offered; the queue never gives up on a deployment")
			}
			if claimed.ID != first.ID {
				t.Fatalf("a fresh target was deployed to while another was failing (%s)", claimed.ID)
			}
		}

		// It succeeds, and the rest go.
		if err := s.CompleteDeploymentJob(ctx, first.ID, DeploySucceeded,
			DeploymentAttempt{Number: 4, Detail: "installed"}, now, false); err != nil {
			t.Fatal(err)
		}
		next, err := s.ClaimDeploymentJob(ctx, "worker-2", time.Minute, now)
		if err != nil || next == nil {
			t.Fatalf("the rollout should resume once the failure clears: %v", err)
		}
		if next.ID == first.ID {
			t.Error("the succeeded job was offered again")
		}
	})
}

// TestAnAgentTargetIsNeverClaimedByACoreWorker.
//
// A core worker cannot open a connection to a machine behind two firewalls, and
// one that claimed the job would fail it until the attempt budget ran out. The
// exclusion is a SQL predicate in one store and a loop in the other.
func TestAnAgentTargetIsNeverClaimedByACoreWorker(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()

		agent := &Agent{Name: "queue-agent", Hostname: "queue-agent.internal", Status: AgentActive}
		if err := s.CreateAgent(ctx, agent); err != nil {
			t.Fatal(err)
		}
		cert := sampleCertificate("agent-queue")
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}
		target, err := s.EnsureAgentDeploymentTarget(ctx, agent)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := s.EnsureCertificateDeployment(ctx, &CertificateDeployment{
			CertificateID: cert.ID, TargetID: target.ID, IsEnabled: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.EnqueueDeployment(ctx, &DeploymentJob{
			DeploymentID: binding.ID, CertificateID: cert.ID, TargetID: target.ID,
			Reason: DeployReasonManual, Status: DeployPending, RunAfter: now.Add(-time.Minute),
		}); err != nil {
			t.Fatal(err)
		}

		if claimed, err := s.ClaimDeploymentJob(ctx, "core-replica", time.Minute, now); err != nil {
			t.Fatal(err)
		} else if claimed != nil {
			t.Fatalf("a core worker claimed a job for a host it cannot reach: %s", claimed.ID)
		}

		mine, err := s.ClaimAgentDeploymentJobs(ctx, agent.ID, "agent", 10*time.Minute, now, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(mine) != 1 {
			t.Fatalf("the host should claim its own work, got %d job(s)", len(mine))
		}
	})
}

// ── Helpers ─────────────────────────────────────────────────

var sampleSerial int

// sampleCertificate builds a certificate that is valid everywhere.
//
// Fingerprints are unique per call because the column is unique in one store
// and a map key in the other, and a suite that reused one would pass in memory
// and fail in PostgreSQL for a reason that has nothing to do with what it is
// testing.
func sampleCertificate(name string) *Certificate {
	sampleSerial++
	pem := "-----BEGIN CERTIFICATE-----\nconformance\n-----END CERTIFICATE-----\n"
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	return &Certificate{
		FingerprintSHA256: fmt.Sprintf("%s-%04d", name, sampleSerial),
		CommonName:        name + ".example.com",
		SANs:              []string{name + ".example.com"},
		SerialNumber:      fmt.Sprintf("%04x", sampleSerial),
		IssuerDN:          "CN=Conformance CA",
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		DaysRemaining:     90,
		KeyType:           "ECDSA",
		KeySize:           256,
		Status:            "ISSUED",
		AutoRenew:         true,
		CertificatePEM:    &pem,
		DiscoveredVia:     "MANUAL",
		KeyCustody:        KeyCustodyCertPilot,
		Tags:              []string{},
	}
}

// ── CA authorities ──────────────────────────────────────────

// TestTheChainOfACAComesBackFromBothStores covers a query no unit test could
// have run.
//
// `GetCAChain` builds a recursive CTE that enumerates its own column list and
// then hands the result to the shared scanner, whose list is built by
// `caColumns`. The two drifted: migration 006 added owner_team and owner_email,
// caColumns learned about them, the CTE did not, and every call to the endpoint
// failed against a real database with "column owner_team does not exist". The
// in-memory store walks a map and cannot express the mistake, so the suite was
// green.
//
// The fix is not to add two columns to a list. It is to stop keeping a second
// list: the CTE now selects the whole row, so a column added anywhere is
// carried automatically.
func TestTheChainOfACAComesBackFromBothStores(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		root := sampleAuthority("conformance-root", "ROOT")
		if err := s.CreateCAAuthority(ctx, root); err != nil {
			t.Fatalf("creating the root: %v", err)
		}
		intermediate := sampleAuthority("conformance-issuing", "INTERMEDIATE")
		intermediate.ParentCAID = &root.ID
		if err := s.CreateCAAuthority(ctx, intermediate); err != nil {
			t.Fatalf("creating the intermediate: %v", err)
		}

		chain, err := s.GetCAChain(ctx, intermediate.ID)
		if err != nil {
			t.Fatalf("walking the chain: %v", err)
		}
		if len(chain) != 2 {
			t.Fatalf("chain has %d links, want the intermediate and its root", len(chain))
		}
		if chain[0].ID != intermediate.ID {
			t.Fatalf("chain starts at %q, want the CA that was asked for", chain[0].Name)
		}
		if chain[1].ID != root.ID {
			t.Fatalf("chain ends at %q, want the root", chain[1].Name)
		}
	})
}

// TestAnImportedAuthorityKeepsEveryFieldItWasGiven is class B for the columns
// migration 026 adds. A writer that drops `source` would leave every imported
// CA looking hand-registered, and the importer would then treat operator-owned
// rows as its own to overwrite.
func TestAnImportedAuthorityKeepsEveryFieldItWasGiven(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		seen := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		ca := sampleAuthority("conformance-imported", "ISSUING")
		ca.Source = CASourceGateway
		ca.LastSeenAt = &seen
		if err := s.CreateCAAuthority(ctx, ca); err != nil {
			t.Fatalf("creating: %v", err)
		}

		stored, err := s.GetCAAuthority(ctx, ca.ID)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		if stored.Source != CASourceGateway {
			t.Fatalf("source = %q, want %q", stored.Source, CASourceGateway)
		}
		if stored.LastSeenAt == nil || !stored.LastSeenAt.UTC().Truncate(time.Second).Equal(seen) {
			t.Fatalf("last seen = %v, want %v", stored.LastSeenAt, seen)
		}

		// And through an update, which is the path the importer takes on every
		// sweep after the first.
		later := time.Now().UTC().Truncate(time.Second)
		stored.LastSeenAt = &later
		if err := s.UpdateCAAuthority(ctx, stored); err != nil {
			t.Fatalf("updating: %v", err)
		}
		again, err := s.GetCAAuthority(ctx, ca.ID)
		if err != nil {
			t.Fatalf("reading back after update: %v", err)
		}
		if again.LastSeenAt == nil || !again.LastSeenAt.UTC().Truncate(time.Second).Equal(later) {
			t.Fatalf("last seen after update = %v, want %v", again.LastSeenAt, later)
		}
		if again.Source != CASourceGateway {
			t.Fatalf("source after update = %q, want it preserved", again.Source)
		}
	})
}

// TestACAIsFoundByItsFingerprint covers the lookup the importer identifies by.
//
// The fingerprint is the certificate. Matching on a name would make a renamed
// CA a second CA, and matching on a subject would merge two CAs that share a
// DN — which is what a rotated issuing CA looks like.
func TestACAIsFoundByItsFingerprint(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		ca := sampleAuthority("conformance-byfingerprint", "ISSUING")
		if err := s.CreateCAAuthority(ctx, ca); err != nil {
			t.Fatalf("creating: %v", err)
		}

		found, err := s.GetCAAuthorityByFingerprint(ctx, ca.FingerprintSHA256)
		if err != nil {
			t.Fatalf("looking up by fingerprint: %v", err)
		}
		if found == nil || found.ID != ca.ID {
			t.Fatalf("found %v, want the CA just created", found)
		}

		// Absence is not an error: the importer asks this question about every
		// issuer it is offered, and most of the answers are "not yet".
		missing, err := s.GetCAAuthorityByFingerprint(ctx, "0000-not-a-fingerprint")
		if err != nil {
			t.Fatalf("looking up one that does not exist: %v", err)
		}
		if missing != nil {
			t.Fatalf("found %q for a fingerprint nothing has", missing.Name)
		}
	})
}

// sampleAuthority builds a CA authority whose unique columns are unique per
// call, for the same reason sampleCertificate does.
func sampleAuthority(name, caType string) *CAAuthority {
	sampleSerial++
	return &CAAuthority{
		Name:              fmt.Sprintf("%s-%04d", name, sampleSerial),
		CAType:            caType,
		SubjectDN:         "CN=" + name,
		IssuerDN:          "CN=Conformance Root",
		SerialNumber:      fmt.Sprintf("%04x", sampleSerial),
		NotBefore:         time.Now().Add(-24 * time.Hour),
		NotAfter:          time.Now().Add(365 * 24 * time.Hour),
		KeyType:           "ECDSA",
		KeySize:           256,
		FingerprintSHA256: fmt.Sprintf("%s-fingerprint-%04d", name, sampleSerial),
		CertificatePEM:    "-----BEGIN CERTIFICATE-----\nconformance\n-----END CERTIFICATE-----\n",
		Status:            "HEALTHY",
	}
}
