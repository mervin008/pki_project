package cloudsync

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// fakeProvider stands in for a cloud account.
type fakeProvider struct {
	providerType string
	assets       []Asset
	err          error
	scopes       []string
	calls        int
}

func (f *fakeProvider) Type() string     { return f.providerType }
func (f *fakeProvider) Describe() string { return "fake " + f.providerType }
func (f *fakeProvider) Scopes() []string {
	if f.scopes != nil {
		return f.scopes
	}
	return []string{"everything, allegedly"}
}
func (f *fakeProvider) Inventory(context.Context) ([]Asset, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.assets, nil
}

func newTestEngine(t *testing.T, provider Provider) (*Engine, *store.MemoryStore, *events.Broker) {
	t.Helper()
	st := store.NewMemoryStore()
	broker := events.NewBroker()
	t.Cleanup(broker.Stop)

	engine := NewEngine(st, nil,
		WithBroker(broker),
		WithProviderBuilder(func(string, []byte) (Provider, error) { return provider, nil }),
	)
	return engine, st, broker
}

func addConnection(t *testing.T, st store.Store, name, provider string) *store.CloudConnection {
	t.Helper()
	conn := &store.CloudConnection{
		Name: name, Provider: provider, IsEnabled: true, SyncIntervalMinutes: 360,
	}
	if err := st.CreateCloudConnection(context.Background(), conn); err != nil {
		t.Fatalf("CreateCloudConnection: %v", err)
	}
	return conn
}

func boolPtr(b bool) *bool { return &b }

// The rule this whole feature turns on, in its cloud form: a sync that could
// not run must not look like a sync that found nothing.
func TestAFailedSyncMovesTheAttemptButNotTheSuccess(t *testing.T) {
	provider := &fakeProvider{providerType: "aws_acm", err: errors.New("The security token included in the request is expired")}
	engine, st, _ := newTestEngine(t, provider)
	conn := addConnection(t, st, "prod-eu", "aws_acm")

	engine.Sync(context.Background(), conn)

	after, err := st.GetCloudConnection(context.Background(), conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastSyncedAt == nil {
		t.Error("a failed sync did not record that it was attempted")
	}
	if after.LastSuccessAt != nil {
		t.Error("a failed sync recorded a success; an unreachable account now reads as an empty one")
	}
	if after.LastError == "" {
		t.Fatal("the failure was not recorded")
	}
	if after.CertificatesSeen != 0 {
		t.Errorf("certificates_seen = %d after a failed sync", after.CertificatesSeen)
	}

	// And it must eventually read as stale, so silence stops being reassuring.
	if !after.Stale(time.Now().Add(4 * 360 * time.Minute)) {
		t.Error("a connection that has never succeeded never reads as stale")
	}
}

// A sync that failed must not conclude the estate was dismantled.
func TestAFailedSyncDoesNotRemoveWhatAnEarlierOneFound(t *testing.T) {
	provider := &fakeProvider{
		providerType: "kubernetes",
		assets: []Asset{
			{ResourceID: "shop/tls", Name: "tls", Location: "shop", WillRenew: boolPtr(false), RenewalMode: "manual"},
		},
	}
	engine, st, _ := newTestEngine(t, provider)
	conn := addConnection(t, st, "cluster", "kubernetes")

	engine.Sync(context.Background(), conn)

	provider.err = errors.New("connection refused")
	refreshed, _ := st.GetCloudConnection(context.Background(), conn.ID)
	engine.Sync(context.Background(), refreshed)

	certs, _, err := st.ListCloudCertificates(context.Background(), store.CloudCertificateFilter{ConnectionID: conn.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("a failed sync made %d of 1 certificate(s) disappear from the list", len(certs))
	}
}

// Scopes describe the sync that produced them. Carrying forward a scope the
// current credentials can no longer reach would claim coverage that is gone.
func TestScopesAreRecordedOnEverySuccess(t *testing.T) {
	provider := &fakeProvider{
		providerType: "gcp",
		scopes:       []string{"compute sslCertificates in project demo", "NOT Certificate Manager"},
	}
	engine, st, _ := newTestEngine(t, provider)
	conn := addConnection(t, st, "gcp-demo", "gcp")

	engine.Sync(context.Background(), conn)

	after, _ := st.GetCloudConnection(context.Background(), conn.ID)
	if len(after.Scopes) != 2 {
		t.Fatalf("scopes = %v, want the two the provider reported", after.Scopes)
	}
	if after.Scopes[1] != "NOT Certificate Manager" {
		t.Errorf("the scope naming what was *not* looked at was dropped: %v", after.Scopes)
	}
}

// A certificate that disappeared from the account is information. The row is
// kept and flagged rather than deleted, and it leaves the default listing.
func TestCertificatesThatDisappearAreFlaggedNotDeleted(t *testing.T) {
	provider := &fakeProvider{
		providerType: "aws_acm",
		assets: []Asset{
			{ResourceID: "arn:one", Name: "one"},
			{ResourceID: "arn:two", Name: "two"},
		},
	}
	engine, st, _ := newTestEngine(t, provider)
	conn := addConnection(t, st, "acm", "aws_acm")

	engine.Sync(context.Background(), conn)

	provider.assets = provider.assets[:1]
	refreshed, _ := st.GetCloudConnection(context.Background(), conn.ID)
	engine.Sync(context.Background(), refreshed)

	current, _, _ := st.ListCloudCertificates(context.Background(), store.CloudCertificateFilter{ConnectionID: conn.ID})
	if len(current) != 1 {
		t.Fatalf("the default listing shows %d certificates, want the 1 still there", len(current))
	}
	if current[0].ResourceID != "arn:one" {
		t.Errorf("the wrong certificate survived: %s", current[0].ResourceID)
	}

	all, _, _ := st.ListCloudCertificates(context.Background(), store.CloudCertificateFilter{
		ConnectionID: conn.ID, IncludeRemoved: true,
	})
	if len(all) != 2 {
		t.Fatalf("a certificate that disappeared was deleted, taking its history with it (%d rows)", len(all))
	}
	for _, c := range all {
		if c.ResourceID == "arn:two" && c.RemovedAt == nil {
			t.Error("the certificate that disappeared is not marked as gone")
		}
	}
}

// Alerts fire for certificates new to the connection. A sync every six hours
// re-announcing the same ACM inventory is how a channel gets muted, taking the
// CA expiry alerts sharing it along too.
func TestUnmanagedIsAnnouncedOnceNotEverySync(t *testing.T) {
	provider := &fakeProvider{
		providerType: "aws_acm",
		assets:       []Asset{{ResourceID: "arn:one", Name: "shop.example.com", Location: "eu-west-1"}},
	}
	engine, st, broker := newTestEngine(t, provider)
	sub := broker.Subscribe(events.TopicCloudUnmanaged)
	defer sub.Close()

	conn := addConnection(t, st, "acm", "aws_acm")
	engine.Sync(context.Background(), conn)

	select {
	case evt := <-sub.Events():
		payload, _ := evt.Payload.(map[string]any)
		if payload["unmanaged_count"] != 1 {
			t.Errorf("unmanaged_count = %v, want 1", payload["unmanaged_count"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a certificate nobody manages was found and nothing was published")
	}

	refreshed, _ := st.GetCloudConnection(context.Background(), conn.ID)
	engine.Sync(context.Background(), refreshed)

	select {
	case evt := <-sub.Events():
		t.Fatalf("the same certificate was announced again on the next sync: %+v", evt.Payload)
	case <-time.After(300 * time.Millisecond):
	}
}

// Severity tracks time, not category. The same self-managed certificate is a
// note with a year left and an emergency with three weeks left, and ranking
// them alike buries the one that matters in a list of the ones that do not.
func TestRenewalFindingSeverityTracksTimeRemaining(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		after time.Duration
		want  string
	}{
		{"a year away", 365 * 24 * time.Hour, events.SeverityInfo},
		{"two months away", 60 * 24 * time.Hour, events.SeverityWarning},
		{"three weeks away", 21 * 24 * time.Hour, events.SeverityCritical},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expiry := now.Add(tc.after)
			cert := &store.CloudCertificate{NotAfter: &expiry, Location: "eu-west-1"}
			asset := Asset{WillRenew: boolPtr(false), RenewalMode: "IMPORTED"}

			findings := assess(cert, asset, store.CloudProviderAWSACM, now)
			found := false
			for _, f := range findings {
				if f.Code != FindingWillNotRenew {
					continue
				}
				found = true
				if f.Severity != tc.want {
					t.Errorf("severity = %s, want %s", f.Severity, tc.want)
				}
				if !containsAll(f.Detail, "AWS Certificate Manager", "IMPORTED") {
					t.Errorf("the finding does not name the provider and its own word for it: %q", f.Detail)
				}
			}
			if !found {
				t.Fatalf("no will_not_renew finding: %+v", findings)
			}
		})
	}
}

// A provider that claims to renew a certificate and has not, days from expiry,
// is worse news than one nobody claimed to renew: the thing everybody relies on
// has quietly stopped working.
func TestAutomaticRenewalThatHasNotHappenedIsCritical(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(3 * 24 * time.Hour)

	cert := &store.CloudCertificate{NotAfter: &expiry}
	findings := assess(cert, Asset{WillRenew: boolPtr(true), RenewalMode: "MANAGED (ACTIVE)"},
		store.CloudProviderGCP, now)

	for _, f := range findings {
		if f.Code == FindingRenewalOverdue {
			if f.Severity != events.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
			return
		}
	}
	t.Fatalf("a certificate three days from expiry that something claims to renew produced no finding: %+v", findings)
}

// Unknown attachment is not absent attachment. Reporting "nothing is using
// this" when the provider was never asked would be a fabricated finding.
func TestUnattachedIsOnlyReportedWhenItIsKnown(t *testing.T) {
	now := time.Now()
	expiry := now.Add(200 * 24 * time.Hour)

	unknown := assess(&store.CloudCertificate{NotAfter: &expiry},
		Asset{CertificatePEM: "x"}, store.CloudProviderAzureKeyVault, now)
	for _, f := range unknown {
		if f.Code == FindingUnattached {
			t.Fatal("an unattached finding was raised for a provider that cannot say")
		}
	}

	known := assess(&store.CloudCertificate{NotAfter: &expiry, Location: "eu-west-1"},
		Asset{CertificatePEM: "x", Attached: boolPtr(false)}, store.CloudProviderAWSACM, now)
	for _, f := range known {
		if f.Code == FindingUnattached {
			return
		}
	}
	t.Fatal("a certificate nothing is using produced no finding")
}

// Without a body there is no fingerprint, and without a fingerprint the
// managed/unmanaged verdict is a guess. It has to say so.
func TestACertificateWithNoBodySaysSo(t *testing.T) {
	findings := assess(&store.CloudCertificate{}, Asset{}, store.CloudProviderAWSACM, time.Now())
	for _, f := range findings {
		if f.Code == FindingNoBody {
			if f.Severity != events.SeverityWarning {
				t.Errorf("severity = %s, want WARNING", f.Severity)
			}
			return
		}
	}
	t.Fatalf("a record with no certificate body produced no finding: %+v", findings)
}

func TestValidateConnectionRefusesAHammeringInterval(t *testing.T) {
	conn := &store.CloudConnection{Name: "acm", Provider: "aws_acm", SyncIntervalMinutes: 1}
	err := ValidateConnection(conn)
	if err == nil {
		t.Fatal("a one-minute sync interval was accepted")
	}
	if !containsAll(err.Error(), "quota") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
