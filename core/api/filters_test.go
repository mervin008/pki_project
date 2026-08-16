package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// decodeList pulls the `data` array out of a list response.
func decodeList[T any](t *testing.T, body []byte) ([]T, int64) {
	t.Helper()
	var envelope struct {
		Data  []T   `json:"data"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decoding response: %v\nbody: %s", err, body)
	}
	return envelope.Data, envelope.Total
}

// ── GET /dashboard/activity ─────────────────────────────

// TestActivityFilteredByAction is the endpoint-level statement of why this step
// exists. The feed defaults to the newest 20 entries of a table that also
// carries every issuance, so on a busy day a CA expiry alert is off the
// dashboard within minutes of being recorded. Being able to ask for it by
// action is what makes it reachable at all.
func TestActivityFilteredByAction(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		if err := st.CreateAuditLog(ctx, &store.AuditLog{Action: "cert.issued", EntityType: "certificate"}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}
	if err := st.CreateAuditLog(ctx, &store.AuditLog{Action: "ca.expiry_alert", EntityType: "ca_authority"}); err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}
	for i := 0; i < 50; i++ {
		if err := st.CreateAuditLog(ctx, &store.AuditLog{Action: "cert.issued", EntityType: "certificate"}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}

	// Unfiltered, the alert is buried: it is the 51st newest entry and the
	// default page is 20.
	w := do(r, http.MethodGet, "/api/v1/dashboard/activity", nil, nil)
	logs, _ := decodeList[store.AuditLog](t, w.Body.Bytes())
	for _, l := range logs {
		if l.Action == "ca.expiry_alert" {
			t.Fatal("precondition failed: the alert should not be on the default page")
		}
	}

	w = do(r, http.MethodGet, "/api/v1/dashboard/activity?action=ca.expiry_alert", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	logs, total := decodeList[store.AuditLog](t, w.Body.Bytes())
	if len(logs) != 1 || logs[0].Action != "ca.expiry_alert" {
		t.Fatalf("want the single alert, got %d entries", len(logs))
	}
	if total != 1 {
		t.Errorf("total should describe the filtered set, want 1, got %d", total)
	}
}

func TestActivityAcceptsRepeatedAndCommaSeparatedActions(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	for _, action := range []string{"ca.expiry_alert", "ca.health_changed", "cert.issued"} {
		if err := st.CreateAuditLog(ctx, &store.AuditLog{Action: action, EntityType: "x"}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}

	for _, query := range []string{
		"?action=ca.expiry_alert&action=ca.health_changed", // what an HTTP client builds
		"?action=ca.expiry_alert,ca.health_changed",        // what someone types
	} {
		w := do(r, http.MethodGet, "/api/v1/dashboard/activity"+query, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d", query, w.Code)
		}
		_, total := decodeList[store.AuditLog](t, w.Body.Bytes())
		if total != 2 {
			t.Errorf("%s: want 2 matches, got %d", query, total)
		}
	}
}

func TestActivityRejectsUnusableParameters(t *testing.T) {
	r, _ := realRouter(t)

	// Each of these would otherwise be silently ignored, and a filter that
	// quietly does nothing is worse than one that fails: the caller believes
	// they are looking at a narrowed view.
	cases := []string{
		"?since=yesterday",
		"?limit=0",
		"?limit=99999",
		"?limit=lots",
		"?offset=-1",
	}
	for _, query := range cases {
		w := do(r, http.MethodGet, "/api/v1/dashboard/activity"+query, nil, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", query, w.Code)
		}
	}
}

func TestActivityHonoursSince(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	if err := st.CreateAuditLog(ctx, &store.AuditLog{Action: "ca.expiry_alert", EntityType: "ca_authority"}); err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}

	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	w := do(r, http.MethodGet, "/api/v1/dashboard/activity?since="+future, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	_, total := decodeList[store.AuditLog](t, w.Body.Bytes())
	if total != 0 {
		t.Errorf("a lower bound in the future should match nothing, got %d", total)
	}

	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	w = do(r, http.MethodGet, "/api/v1/dashboard/activity?since="+past, nil, nil)
	_, total = decodeList[store.AuditLog](t, w.Body.Bytes())
	if total == 0 {
		t.Error("a lower bound in the past should match the entry just written")
	}
}

// ── GET /pki/authorities ────────────────────────────────

func TestAuthoritiesSortedByUrgency(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	// Alphabetical order is the reverse of urgency order here, so a handler
	// that ignored `sort` would fail rather than coincidentally pass.
	for _, spec := range []struct {
		name string
		days int
	}{
		{"aaa-comfortable", 900},
		{"zzz-imminent", 3},
	} {
		if err := st.CreateCAAuthority(ctx, &store.CAAuthority{
			Name:     spec.name,
			CAType:   "ISSUING",
			Status:   "HEALTHY",
			NotAfter: time.Now().Add(time.Duration(spec.days) * 24 * time.Hour),
		}); err != nil {
			t.Fatalf("CreateCAAuthority: %v", err)
		}
	}

	w := do(r, http.MethodGet, "/api/v1/pki/authorities?sort=urgency", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	cas, _ := decodeList[store.CAAuthority](t, w.Body.Bytes())
	if len(cas) == 0 {
		t.Fatal("no authorities returned")
	}
	if cas[0].Name != "zzz-imminent" {
		t.Errorf("urgency order must put the worst first, got %s", cas[0].Name)
	}
}

func TestAuthoritiesExpiringWindow(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	if err := st.CreateCAAuthority(ctx, &store.CAAuthority{
		Name: "expires-next-week", CAType: "ISSUING", Status: "CRITICAL",
		NotAfter: time.Now().Add(7 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("CreateCAAuthority: %v", err)
	}

	w := do(r, http.MethodGet, "/api/v1/pki/authorities?expiring_within_days=30", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	cas, _ := decodeList[store.CAAuthority](t, w.Body.Bytes())
	if len(cas) != 1 || cas[0].Name != "expires-next-week" {
		t.Fatalf("want only the CA inside the window, got %d results", len(cas))
	}

	w = do(r, http.MethodGet, "/api/v1/pki/authorities?expiring_within_days=notanumber", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("an unparseable window should be 400, got %d", w.Code)
	}
}

func TestAuthorityListOmitsPEMButDetailKeepsIt(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	ca := &store.CAAuthority{
		Name: "pem-carrying-ca", CAType: "ROOT", Status: "HEALTHY",
		NotAfter:       time.Now().Add(900 * 24 * time.Hour),
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nnot-a-real-certificate\n-----END CERTIFICATE-----",
	}
	if err := st.CreateCAAuthority(ctx, ca); err != nil {
		t.Fatalf("CreateCAAuthority: %v", err)
	}

	w := do(r, http.MethodGet, "/api/v1/pki/authorities", nil, nil)
	cas, _ := decodeList[store.CAAuthority](t, w.Body.Bytes())
	for _, listed := range cas {
		if listed.CertificatePEM != "" {
			t.Errorf("%s: the list must not carry the PEM — it is re-sent on every dashboard refresh", listed.Name)
		}
	}

	w = do(r, http.MethodGet, "/api/v1/pki/authorities/"+ca.ID, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("detail: want 200, got %d", w.Code)
	}
	var detail store.CAAuthority
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decoding detail: %v", err)
	}
	if detail.CertificatePEM == "" {
		t.Error("the detail endpoint should still return the certificate")
	}
}

// ── Private key export ──────────────────────────────────

// TestPrivateKeyExportFindsAKeyTheRecordDoesNotCarry covers the defect this
// step uncovered: the handler tested cert.PrivateKeyEncrypted on a record
// returned by GetCertificate, and no query selects that column — so against
// PostgreSQL the endpoint answered "no private key is stored" for every
// certificate, including ones whose keys it held.
//
// The store is the in-memory one here, so this asserts the handler reads
// through the dedicated accessor rather than the record field. The store-level
// test that the two disagree is in core/store.
func TestPrivateKeyExportReadsThroughTheDedicatedAccessor(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	sealed := "not-a-real-envelope"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cert := &store.Certificate{
		CommonName: "app.example.com", Status: "ISSUED",
		NotAfter: &notAfter, PrivateKeyEncrypted: &sealed,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	// The key is present, so this must get past the "no key stored" 404 and
	// fail at decryption instead — the value is not a real sealed envelope.
	// A 404 here would mean the handler never found the key at all.
	w := do(r, http.MethodGet, "/api/v1/certificates/"+cert.ID+"/private-key", nil, nil)
	if w.Code == http.StatusNotFound {
		t.Fatal("the handler did not find a private key that is stored")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500 from the decryption failure, got %d: %s", w.Code, w.Body)
	}

	// A certificate genuinely without a key still reports 404.
	keyless := &store.Certificate{CommonName: "imported.example.com", Status: "ISSUED", NotAfter: &notAfter}
	if err := st.CreateCertificate(ctx, keyless); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	w = do(r, http.MethodGet, "/api/v1/certificates/"+keyless.ID+"/private-key", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("a certificate with no stored key should be 404, got %d", w.Code)
	}
}

// ── Dashboard statistics ────────────────────────────────

func TestDashboardStatsExposeExpiredAndUnknownCAs(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	for _, status := range []string{"EXPIRED", "UNKNOWN"} {
		if err := st.CreateCAAuthority(ctx, &store.CAAuthority{
			Name: "ca-" + status, CAType: "ISSUING", Status: status,
			NotAfter: time.Now().Add(24 * time.Hour),
		}); err != nil {
			t.Fatalf("CreateCAAuthority: %v", err)
		}
	}

	w := do(r, http.MethodGet, "/api/v1/dashboard/stats", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var stats store.DashboardStats
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decoding stats: %v", err)
	}

	if stats.ExpiredCAs != 1 {
		t.Errorf("expired CAs: want 1, got %d", stats.ExpiredCAs)
	}
	if stats.UnknownCAs != 1 {
		t.Errorf("unknown CAs: want 1, got %d", stats.UnknownCAs)
	}
	sum := stats.HealthyCAs + stats.WarningCAs + stats.CriticalCAs + stats.ExpiredCAs + stats.UnknownCAs
	if sum != stats.TotalCAs {
		t.Errorf("the CA buckets must partition the estate: %d counted, %d total", sum, stats.TotalCAs)
	}
}
