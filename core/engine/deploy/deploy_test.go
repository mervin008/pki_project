package deploy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/certpilot/certpilot/pkg/webhooksig"
)

const testSecret = "a-signing-secret-long-enough"

// TestAWebhookTargetIsRefusedWhenItCannotBeTrusted covers the configuration
// rules that exist because of what this endpoint can do, rather than what it
// carries. A deployment webhook installs certificates; an unsigned one lets
// anybody who can reach the receiver install theirs.
func TestAWebhookTargetIsRefusedWhenItCannotBeTrusted(t *testing.T) {
	cases := map[string]struct {
		config map[string]any
		want   string
	}{
		"no url": {
			map[string]any{"signing_secret": testSecret},
			"needs url",
		},
		"no signing secret": {
			map[string]any{"url": "https://deploy.example.com/hook"},
			"needs signing_secret",
		},
		"a signing secret too short to matter": {
			map[string]any{"url": "https://deploy.example.com/hook", "signing_secret": "hunter2"},
			"at least 16 characters",
		},
		"plain http without saying so": {
			map[string]any{"url": "http://deploy.example.com/hook", "signing_secret": testSecret},
			"must be https",
		},
		"a private key over plain http to another machine": {
			map[string]any{
				"url":                 "http://deploy.example.com/hook",
				"signing_secret":      testSecret,
				"allow_insecure_http": true,
				"include_private_key": true,
			},
			"would cross the network in the clear",
		},
		"a header CertPilot sets itself": {
			map[string]any{
				"url":            "https://deploy.example.com/hook",
				"signing_secret": testSecret,
				"headers":        map[string]any{"X-CertPilot-Signature": "hunter2"},
			},
			"cannot be overridden",
		},
		"a target type nothing can deploy to": {
			nil,
			"cannot be deployed to yet",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			targetType := TypeWebhook
			if tc.config == nil {
				// A type nothing can deploy to. Deliberately not a plausible
				// one: "f5" used to stand here and became real, which is the
				// hazard with using a real-sounding name as a negative case.
				targetType, tc.config = "carrier-pigeon", map[string]any{}
			}
			_, _, err := ValidateConfig(targetType, tc.config)
			if err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestAPrivateKeyMayCrossLoopbackInTheClear is the deliberate exception to the
// rule above. An agent on the same host means there is no wire, and refusing it
// would rule out the one topology where plaintext is genuinely harmless.
func TestAPrivateKeyMayCrossLoopbackInTheClear(t *testing.T) {
	for _, url := range []string{"http://127.0.0.1:9500/install", "http://localhost:9500/install"} {
		_, deploysKey, err := ValidateConfig(TypeWebhook, map[string]any{
			"url":                 url,
			"signing_secret":      testSecret,
			"allow_insecure_http": true,
			"include_private_key": true,
		})
		if err != nil {
			t.Fatalf("%s should be allowed: %v", url, err)
		}
		if !deploysKey {
			t.Fatal("a target that ships the private key must report that it does")
		}
	}

	// And a name that merely resolves to loopback today does not count: what a
	// name points at when the deployment runs is not what it points at now.
	_, _, err := ValidateConfig(TypeWebhook, map[string]any{
		"url":                 "http://internal.example.com/install",
		"signing_secret":      testSecret,
		"allow_insecure_http": true,
		"include_private_key": true,
	})
	if err == nil {
		t.Fatal("a non-loopback name must not be treated as local")
	}
}

// TestTheDeliveryIsSignedAndCarriesNoKeyUnlessAsked checks the two properties a
// receiver depends on: that it can tell CertPilot from anybody else, and that a
// key does not arrive at a target that never asked for one.
func TestTheDeliveryIsSignedAndCarriesNoKeyUnlessAsked(t *testing.T) {
	var mu sync.Mutex
	var body []byte
	var signature, timestamp string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ = io.ReadAll(r.Body)
		signature = r.Header.Get(webhooksig.SignatureHeader)
		timestamp = r.Header.Get(webhooksig.TimestampHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	d, err := Build(TypeWebhook, `{"url":"`+srv.URL+`","signing_secret":"`+testSecret+`","allow_insecure_http":true}`)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if d.NeedsPrivateKey() {
		t.Fatal("a target that did not ask for the key must not request it")
	}

	detail, err := d.Deploy(context.Background(), Bundle{
		CertificateID:     "cert-1",
		CommonName:        "app.example.com",
		FingerprintSHA256: strings.Repeat("ab", 32),
		CertificatePEM:    "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
		PrivateKeyPEM:     "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
		Options:           map[string]any{"path": "/etc/nginx/certs/app"},
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if err := webhooksig.Verify(testSecret, timestamp, signature, body, time.Minute); err != nil {
		t.Fatalf("the receiver could not verify the delivery: %v", err)
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload.PrivateKeyPEM != "" {
		t.Fatal("the private key reached a target that never asked for it")
	}
	if payload.Options["path"] != "/etc/nginx/certs/app" {
		t.Fatalf("the binding's placement did not reach the receiver: %#v", payload.Options)
	}
	// The detail line ends up in an attempt log a person reads, so it has to
	// name what went where rather than congratulate itself.
	if !strings.Contains(detail, "app.example.com") || !strings.Contains(detail, srv.URL) {
		t.Fatalf("detail should name the certificate and the target, got %q", detail)
	}
}

// ── Queue behaviour ─────────────────────────────────────────

type stubDeployer struct {
	mu      sync.Mutex
	results []error
	calls   int
}

func (s *stubDeployer) Deploy(context.Context, *store.DeploymentJob) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.calls
	s.calls++
	if i < len(s.results) {
		if err := s.results[i]; err != nil {
			return "", err
		}
	}
	return "installed", nil
}

// TestAFailingDeploymentStaysQueuedAndEscalatesOnce is the queue's whole
// contract. A certificate that has been renewed and not installed expires on
// exactly the schedule of one that was never renewed, so nothing is abandoned —
// but the alert fires once, not on every retry.
func TestAFailingDeploymentStaysQueuedAndEscalatesOnce(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	binding := seedBinding(t, st)
	exec := &stubDeployer{results: []error{
		errString("connection refused"),
		errString("connection refused"),
		errString("connection refused"),
		errString("connection refused"),
	}}

	broker := events.NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe(events.TopicCertDeployFailed)
	defer sub.Close()

	q := NewQueue(st, exec, broker, WithWorkers(1))

	job := &store.DeploymentJob{
		DeploymentID:  binding.ID,
		CertificateID: binding.CertificateID,
		TargetID:      binding.TargetID,
		Reason:        store.DeployReasonManual,
	}
	if _, err := st.EnqueueDeployment(ctx, job); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	for i := 0; i < 4; i++ {
		// Rewind so the retry delay does not have to elapse in real time.
		if err := st.CompleteDeploymentJob(ctx, job.ID, store.DeployPending,
			store.DeploymentAttempt{}, time.Now().Add(-time.Hour), false); err != nil && i > 0 {
			t.Fatalf("rewind: %v", err)
		}
		if !q.RunOnce(ctx) {
			t.Fatalf("attempt %d: the queue found nothing to do", i+1)
		}
	}

	after, err := st.GetDeploymentJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// Still outstanding: there is no attempt count at which a certificate stops
	// needing to be where it is served from.
	if after.Status != store.DeployPending {
		t.Fatalf("a failing deployment must stay queued, got %s", after.Status)
	}
	if after.EscalatedAt == nil {
		t.Fatal("four failures should have escalated")
	}

	escalations := drain(sub)
	if len(escalations) != 1 {
		t.Fatalf("expected exactly one escalation, got %d", len(escalations))
	}
}

// TestASuccessfulDeployRecordsWhatThePlaceIsHolding checks that the binding
// carries the fingerprint, and — the part that matters — that a later failure
// does not overwrite it. The place is still holding what it was holding.
func TestASuccessfulDeployRecordsWhatThePlaceIsHolding(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	binding := seedBinding(t, st)
	cert, err := st.GetCertificate(ctx, binding.CertificateID)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}

	if err := st.RecordDeploymentOutcome(ctx, binding.ID, store.DeploymentOutcome{
		Status:      store.DeploymentDeployed,
		Fingerprint: cert.FingerprintSHA256,
		At:          time.Now(),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := st.RecordDeploymentOutcome(ctx, binding.ID, store.DeploymentOutcome{
		Status: store.DeploymentFailed,
		Error:  "connection refused",
		At:     time.Now(),
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	after, err := st.GetCertificateDeployment(ctx, binding.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.DeployedFingerprint != cert.FingerprintSHA256 {
		t.Fatalf("a failed deploy must not change what the place is holding, got %q", after.DeployedFingerprint)
	}
	if after.LastStatus != store.DeploymentFailed || after.LastError == "" {
		t.Fatalf("the failure should still be recorded, got %s / %q", after.LastStatus, after.LastError)
	}
}

// TestOneCertificateCanHaveAJobPerPlace is the constraint that differs from the
// renewal queue. Copying renewal's one-outstanding-job-per-certificate index
// here would have deployed to the first target and silently dropped the rest.
func TestOneCertificateCanHaveAJobPerPlace(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	first := seedBinding(t, st)
	second := &store.CertificateDeployment{
		CertificateID: first.CertificateID,
		TargetID:      seedTarget(t, st, "second target").ID,
		IsEnabled:     true,
	}
	if err := st.CreateCertificateDeployment(ctx, second); err != nil {
		t.Fatalf("bind: %v", err)
	}

	for _, b := range []*store.CertificateDeployment{first, second} {
		job := &store.DeploymentJob{
			DeploymentID:  b.ID,
			CertificateID: b.CertificateID,
			TargetID:      b.TargetID,
		}
		created, err := st.EnqueueDeployment(ctx, job)
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if !created {
			t.Fatal("a second target for the same certificate must get its own job")
		}
	}

	// And a second job for the same place is still refused.
	dup := &store.DeploymentJob{
		DeploymentID:  first.ID,
		CertificateID: first.CertificateID,
		TargetID:      first.TargetID,
	}
	created, err := st.EnqueueDeployment(ctx, dup)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if created {
		t.Fatal("one place must not have two outstanding deployments")
	}
}

// TestADisabledTargetIsAnErrorRatherThanASilentSkip. A queue that quietly
// discards work because a switch is off is a queue that lies about what it did.
func TestADisabledTargetIsAnErrorRatherThanASilentSkip(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	binding := seedBinding(t, st)
	target, err := st.GetDeploymentTarget(ctx, binding.TargetID)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	target.IsEnabled = false
	if err := st.UpdateDeploymentTarget(ctx, target); err != nil {
		t.Fatalf("disable: %v", err)
	}

	keyring, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	exec := NewExecutor(st, keyring, nil)

	_, err = exec.Deploy(ctx, &store.DeploymentJob{
		DeploymentID:  binding.ID,
		CertificateID: binding.CertificateID,
		TargetID:      binding.TargetID,
	})
	if err == nil || !strings.Contains(err.Error(), "switched off") {
		t.Fatalf("a disabled target should refuse loudly, got %v", err)
	}
}

// ── Helpers ─────────────────────────────────────────────────

func seedTarget(t *testing.T, st store.Store, name string) *store.DeploymentTarget {
	t.Helper()
	target := &store.DeploymentTarget{
		Name:       name,
		TargetType: TypeWebhook,
		IsEnabled:  true,
	}
	if err := st.CreateDeploymentTarget(context.Background(), target); err != nil {
		t.Fatalf("target: %v", err)
	}
	return target
}

func seedBinding(t *testing.T, st store.Store) *store.CertificateDeployment {
	t.Helper()
	ctx := context.Background()

	certs, _, err := st.ListCertificates(ctx, store.CertificateFilter{Limit: 1})
	if err != nil || len(certs) == 0 {
		t.Fatalf("the memory store should seed a certificate: %v", err)
	}

	binding := &store.CertificateDeployment{
		CertificateID: certs[0].ID,
		TargetID:      seedTarget(t, st, "lab receiver").ID,
		IsEnabled:     true,
	}
	if err := st.CreateCertificateDeployment(ctx, binding); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return binding
}

func drain(sub *events.Subscription) []events.Event {
	out := []events.Event{}
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				return out
			}
			out = append(out, evt)
		case <-deadline:
			return out
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
