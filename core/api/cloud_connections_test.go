package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/engine/cloudsync"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// stubCloudProvider stands in for a cloud account, so tests never reach one.
type stubCloudProvider struct{}

func (stubCloudProvider) Type() string     { return "aws_acm" }
func (stubCloudProvider) Describe() string { return "stub account" }
func (stubCloudProvider) Scopes() []string {
	return []string{"AWS Certificate Manager in eu-west-1 only"}
}

func (stubCloudProvider) Inventory(context.Context) ([]cloudsync.Asset, error) {
	no := false
	return []cloudsync.Asset{{
		ResourceID:     "arn:aws:acm:eu-west-1:1:certificate/stub",
		Name:           "legacy.example.com",
		Location:       "eu-west-1",
		CertificatePEM: stubCertPEM,
		RenewalMode:    "IMPORTED",
		WillRenew:      &no,
		Attached:       &no,
	}}, nil
}

// stubCertPEM is generated once so the import path exercises real DER.
var stubCertPEM = func() string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20260818),
		Subject:      pkix.Name{CommonName: "legacy.example.com"},
		DNSNames:     []string{"legacy.example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(20 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}()

func TestCloudConnectionIsValidatedAtCreation(t *testing.T) {
	r, st := realRouter(t)

	cases := map[string]struct {
		body gin.H
		want string
	}{
		"an unknown provider": {
			gin.H{"name": "oracle", "provider": "oracle_cloud", "config": gin.H{}},
			"unknown cloud provider",
		},
		"ACM with no region": {
			gin.H{"name": "acm", "provider": "aws_acm", "config": gin.H{"access_key_id": "a", "secret_access_key": "b"}},
			"region",
		},
		"a vault with no credentials": {
			gin.H{"name": "vault", "provider": "azure_key_vault", "config": gin.H{"vault_url": "https://v.vault.azure.net"}},
			"tenant_id",
		},
		"syncing too hard": {
			gin.H{"name": "acm2", "provider": "aws_acm", "sync_interval_minutes": 1,
				"config": gin.H{"region": "eu-west-1", "access_key_id": "a", "secret_access_key": "b"}},
			"shortest sync interval",
		},
	}
	for name, tc := range cases {
		w := do(r, http.MethodPost, "/api/v1/cloud/connections", tc.body, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", name, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: response does not mention %q: %s", name, tc.want, w.Body.String())
		}
	}

	// A configuration mistake must be caught when it is typed, not six hours
	// later as a sync failure that reads like the account rejecting us.
	conns, err := st.ListCloudConnections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 0 {
		t.Errorf("%d rejected connections were stored anyway", len(conns))
	}
}

// Cloud credentials must never come back out of the API. This is the one
// endpoint whose stored value is read access to somebody's whole cloud account.
func TestCloudCredentialsAreNeverReturned(t *testing.T) {
	r, st := realRouter(t)

	const secret = "wJalrXUtnFEMI-not-a-real-key"
	w := do(r, http.MethodPost, "/api/v1/cloud/connections", gin.H{
		"name": "prod-eu", "provider": "aws_acm",
		"config": gin.H{"region": "eu-west-1", "access_key_id": "AKIDEXAMPLE", "secret_access_key": secret},
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("the create response echoed the secret access key back")
	}

	list := do(r, http.MethodGet, "/api/v1/cloud/connections", nil, nil)
	if strings.Contains(list.Body.String(), secret) {
		t.Fatal("the connection listing carries the secret access key")
	}
	if strings.Contains(list.Body.String(), "config_encrypted") {
		t.Error("the listing exposes the sealed blob; there is no reason for it to leave the server")
	}

	// And it must actually be sealed at rest, not merely hidden from JSON.
	conns, _ := st.ListCloudConnections(context.Background())
	if len(conns) != 1 {
		t.Fatalf("got %d connections, want 1", len(conns))
	}
	if conns[0].ConfigEncrypted == "" {
		t.Fatal("nothing was stored for the credentials")
	}
	if strings.Contains(conns[0].ConfigEncrypted, secret) {
		t.Fatal("the credentials are stored in the clear")
	}

	// The audit trail records the act, not the credential. Audit logs are the
	// table most likely to be exported.
	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range logs {
		if strings.Contains(entry.Details, secret) {
			t.Fatal("the audit log holds the secret access key")
		}
	}
}

// The sharp end: a sync that answers reports what nothing will renew, and says
// what it actually looked at.
func TestSyncReportsWhatNothingWillRenew(t *testing.T) {
	r, _ := realRouter(t)

	created := do(r, http.MethodPost, "/api/v1/cloud/connections", gin.H{
		"name": "prod-eu", "provider": "aws_acm",
		"config": gin.H{"region": "eu-west-1", "access_key_id": "a", "secret_access_key": "b"},
	}, nil)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}

	var createBody struct {
		Data store.CloudConnection `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createBody); err != nil {
		t.Fatal(err)
	}

	w := do(r, http.MethodPost, "/api/v1/cloud/connections/"+createBody.Data.ID+"/sync", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("sync: %d %s", w.Code, w.Body.String())
	}

	var body struct {
		Data    store.CloudConnection     `json:"data"`
		Found   []*store.CloudCertificate `json:"found"`
		Scopes  []string                  `json:"scopes"`
		Summary string                    `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	if len(body.Found) != 1 {
		t.Fatalf("found %d certificates, want 1", len(body.Found))
	}
	found := body.Found[0]
	if found.ManagementState != store.DiscoveryUnmanaged {
		t.Errorf("management state = %q, want UNMANAGED", found.ManagementState)
	}
	if found.CommonName != "legacy.example.com" {
		t.Errorf("common name = %q; the certificate body was not parsed", found.CommonName)
	}

	var codes []string
	for _, f := range found.Findings {
		codes = append(codes, f.Code)
	}
	if !containsString(codes, cloudsync.FindingWillNotRenew) {
		t.Errorf("findings = %v, want will_not_renew for an IMPORTED certificate", codes)
	}
	if !containsString(codes, cloudsync.FindingUnattached) {
		t.Errorf("findings = %v, want unattached for a certificate nothing is using", codes)
	}

	// The scopes are what stop a short list reading as a small estate.
	if len(body.Scopes) == 0 {
		t.Error("the sync did not report what it looked at")
	}
	if !strings.Contains(body.Summary, "does not renew") {
		t.Errorf("summary does not lead with the finding: %q", body.Summary)
	}
	if body.Data.LastSuccessAt == nil {
		t.Error("a successful sync did not record a success")
	}
}

// A sync that could not run must not look like one that found nothing — and
// the status code has to carry the difference too.
func TestAFailedSyncAnswers502AndSaysWhatItMeans(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	// Stored directly with credentials the stub builder will still accept, then
	// broken by replacing the sealed blob with something that cannot be opened.
	conn := &store.CloudConnection{
		Name: "broken", Provider: "aws_acm", IsEnabled: true, SyncIntervalMinutes: 360,
		ConfigEncrypted: "not-a-sealed-blob",
	}
	if err := st.CreateCloudConnection(ctx, conn); err != nil {
		t.Fatal(err)
	}

	w := do(r, http.MethodPost, "/api/v1/cloud/connections/"+conn.ID+"/sync", nil, nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 — CertPilot worked and the account did not (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not the same as finding no certificates") {
		t.Errorf("the response does not distinguish a failed sync from an empty account: %s", w.Body.String())
	}

	after, _ := st.GetCloudConnection(ctx, conn.ID)
	if after.LastSyncedAt == nil {
		t.Error("the attempt was not recorded")
	}
	if after.LastSuccessAt != nil {
		t.Error("a failed sync recorded a success")
	}
}

// Importing a found certificate adopts it — and must not promise renewal that
// cannot happen. CertPilot holds no private key for something it read out of
// somebody else's store.
func TestImportingACloudCertificateNeverPromisesRenewal(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	created := do(r, http.MethodPost, "/api/v1/cloud/connections", gin.H{
		"name": "prod-eu", "provider": "aws_acm",
		"config": gin.H{"region": "eu-west-1", "access_key_id": "a", "secret_access_key": "b"},
	}, nil)
	var createBody struct {
		Data store.CloudConnection `json:"data"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &createBody)

	if w := do(r, http.MethodPost, "/api/v1/cloud/connections/"+createBody.Data.ID+"/sync", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("sync: %d %s", w.Code, w.Body.String())
	}

	certs, _, err := st.ListCloudCertificates(ctx, store.CloudCertificateFilter{})
	if err != nil || len(certs) != 1 {
		t.Fatalf("expected one cloud certificate, got %d (%v)", len(certs), err)
	}

	w := do(r, http.MethodPost, "/api/v1/cloud/import", gin.H{
		"cloud_certificate_id": certs[0].ID, "team": "Platform", "environment": "production",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}

	var body struct {
		Data    store.Certificate `json:"data"`
		Message string            `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.AutoRenew {
		t.Fatal("the imported record claims it will renew itself; there is no private key for it")
	}
	if body.Data.DiscoveredVia != "CLOUD" {
		t.Errorf("discovered_via = %q, want CLOUD so its provenance survives", body.Data.DiscoveredVia)
	}
	if !strings.Contains(body.Message, "cannot be renewed automatically") {
		t.Errorf("the response does not say renewal is not automatic: %q", body.Message)
	}
	// It appeared here because AWS does not renew it either, and saying so is
	// the difference between adopting a certificate and adopting a problem.
	if !strings.Contains(body.Message, "the provider does not renew it either") {
		t.Errorf("the response does not repeat why it was found: %q", body.Message)
	}

	// And the finding is settled, not still asking for the same work.
	after, _ := st.GetCloudCertificate(ctx, certs[0].ID)
	if !after.IsImported || after.ManagementState != store.DiscoveryManaged {
		t.Errorf("the cloud record was not settled by the import: imported=%t state=%s",
			after.IsImported, after.ManagementState)
	}
}

// A stale connection is named on the listing rather than left to be inferred
// from a timestamp nobody reads.
func TestStaleConnectionsAreSurfaced(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	conn := &store.CloudConnection{
		Name: "forgotten", Provider: "gcp", IsEnabled: true, SyncIntervalMinutes: 60,
	}
	if err := st.CreateCloudConnection(ctx, conn); err != nil {
		t.Fatal(err)
	}
	// Aged through the sync path, which is the only thing allowed to move these
	// timestamps. This is the realistic shape of the failure: it worked three
	// days ago, the credentials lapsed, and it has been attempting every hour
	// since. last_synced_at is a minute old and means nothing.
	long := time.Now().Add(-72 * time.Hour)
	if err := st.MarkCloudConnectionSynced(ctx, conn.ID, long, long.Add(time.Hour),
		true, []string{"compute sslCertificates in project demo"}, 3, 0, ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.MarkCloudConnectionSynced(ctx, conn.ID, now, now.Add(time.Hour), false, nil, 0, 0,
		"the metadata server would not issue a token"); err != nil {
		t.Fatal(err)
	}

	w := do(r, http.MethodGet, "/api/v1/cloud/connections", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct {
		Stale   []string `json:"stale_connections"`
		Warning string   `json:"warning"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Stale) != 1 || body.Stale[0] != "forgotten" {
		t.Fatalf("stale_connections = %v, want the connection that has never answered", body.Stale)
	}
	if !strings.Contains(body.Warning, "not being watched") {
		t.Errorf("the warning does not say what the silence means: %q", body.Warning)
	}

	// The recent attempt must not be what the screen leads with. A connection
	// checked one minute ago and last answered three days ago is the exact case
	// a single "last checked" column would report as healthy.
	after, _ := st.GetCloudConnection(ctx, conn.ID)
	if after.LastSyncedAt == nil || time.Since(*after.LastSyncedAt) > time.Minute {
		t.Fatalf("last_synced_at = %v, want the recent failed attempt", after.LastSyncedAt)
	}
	if after.LastSuccessAt == nil || time.Since(*after.LastSuccessAt) < 71*time.Hour {
		t.Fatalf("last_success_at = %v, want the sync from three days ago", after.LastSuccessAt)
	}
}
