package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// TestScanRejectsMalformedTargetsBeforeConnectingToAnything.
//
// A rejected target has to be rejected before any target is scanned. A run that
// probed nine hosts and then failed on the tenth would leave the operator
// unable to say which part of their list was actually reached — and this
// endpoint opens connections in the organisation's name.
func TestScanRejectsMalformedTargetsBeforeScanning(t *testing.T) {
	r, st := realRouter(t)

	cases := map[string]gin.H{
		"a URL":          {"targets": []string{"https://example.com"}},
		"a path":         {"targets": []string{"example.com/health"}},
		"an empty list":  {"targets": []string{}},
		"an absent list": {},
	}

	for name, body := range cases {
		w := do(r, http.MethodPost, "/api/v1/discovery/scan", body, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", name, w.Code, w.Body.String())
		}
	}

	scans, _, err := st.ListDiscoveryScans(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("ListDiscoveryScans: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("a rejected request recorded %d scan(s); nothing should have been attempted", len(scans))
	}
}

// A single request must not become a port scanner with CertPilot's return
// address on it.
func TestScanCapsTheNumberOfTargets(t *testing.T) {
	r, _ := realRouter(t)

	targets := make([]string, maxTargetsPerScan+1)
	for i := range targets {
		targets[i] = "192.0.2.1"
	}

	w := do(r, http.MethodPost, "/api/v1/discovery/scan", gin.H{"targets": targets}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "limited to") {
		t.Errorf("the refusal should say what the limit is: %s", w.Body.String())
	}
}

// TestScanReportsUnmanagedAndAudits — the finding, the audit entry naming what
// was connected to, and the alert, in one pass.
func TestScanReportsUnmanagedAndAudits(t *testing.T) {
	r, st := realRouter(t)
	target := startScanTarget(t)

	w := do(r, http.MethodPost, "/api/v1/discovery/scan",
		gin.H{"targets": []string{target}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var resp struct {
		Scan    *store.DiscoveryScan     `json:"scan"`
		Data    []*store.DiscoveryResult `json:"data"`
		Summary string                   `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if resp.Scan.UnmanagedCount != 1 {
		t.Errorf("unmanaged count = %d, want 1", resp.Scan.UnmanagedCount)
	}
	if len(resp.Data) != 1 || resp.Data[0].ManagementState != store.DiscoveryUnmanaged {
		t.Fatalf("results = %+v, want one UNMANAGED", resp.Data)
	}
	// The summary is what a tile shows, and zero-unmanaged and
	// zero-reachable must not read the same.
	if !strings.Contains(resp.Summary, "does not manage") {
		t.Errorf("summary does not name the finding: %q", resp.Summary)
	}

	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{Actions: []string{"discovery.scan"}})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(logs))
	}
	// Scanning reaches out to third-party infrastructure. "Who asked us to
	// connect to that" has to be answerable afterwards.
	if !strings.Contains(logs[0].Details, target) {
		t.Errorf("the audit entry does not record the target scanned: %s", logs[0].Details)
	}
}

// TestImportAdoptsAResult — and never claims it will renew it.
func TestImportAdoptsAResultWithoutPromisingRenewal(t *testing.T) {
	r, st := realRouter(t)
	target := startScanTarget(t)

	scanResp := do(r, http.MethodPost, "/api/v1/discovery/scan", gin.H{"targets": []string{target}}, nil)
	var scan struct {
		Data []*store.DiscoveryResult `json:"data"`
	}
	if err := json.Unmarshal(scanResp.Body.Bytes(), &scan); err != nil {
		t.Fatalf("decoding scan: %v", err)
	}
	resultID := scan.Data[0].ID

	w := do(r, http.MethodPost, "/api/v1/discovery/import",
		gin.H{"result_id": resultID, "auto_renew": true, "team": "Platform", "environment": "production"}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", w.Code, w.Body.String())
	}

	var imported struct {
		Data    *store.Certificate `json:"data"`
		Message string             `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &imported); err != nil {
		t.Fatalf("decoding import: %v", err)
	}

	// The load-bearing assertion. CertPilot holds no private key for something
	// it merely observed, so auto_renew on this record would be a promise the
	// system cannot keep — discovered at expiry, by which time it is too late.
	if imported.Data.AutoRenew {
		t.Error("an imported certificate must not be marked auto-renewing: there is no private key to renew it with")
	}
	if !strings.Contains(imported.Message, "cannot be renewed automatically") {
		t.Errorf("the response should say renewal is not available: %q", imported.Message)
	}
	if imported.Data.DiscoveredVia != "SCAN" {
		t.Errorf("discovered_via = %q, want SCAN", imported.Data.DiscoveredVia)
	}

	// The result stops being an outstanding finding.
	result, err := st.GetDiscoveryResult(context.Background(), resultID)
	if err != nil {
		t.Fatalf("GetDiscoveryResult: %v", err)
	}
	if !result.IsImported || result.ImportedCertificateID == nil {
		t.Error("the discovery result was not linked to the certificate it was imported as")
	}
	if result.ManagementState != store.DiscoveryManaged {
		t.Errorf("management state = %q after import, want MANAGED", result.ManagementState)
	}
}

// Two people adopting the same finding should converge on one record rather
// than one of them getting an error to interpret.
func TestImportingTheSameCertificateTwiceConverges(t *testing.T) {
	r, _ := realRouter(t)
	target := startScanTarget(t)

	scanResp := do(r, http.MethodPost, "/api/v1/discovery/scan", gin.H{"targets": []string{target}}, nil)
	var scan struct {
		Data []*store.DiscoveryResult `json:"data"`
	}
	_ = json.Unmarshal(scanResp.Body.Bytes(), &scan)

	first := do(r, http.MethodPost, "/api/v1/discovery/import", gin.H{"result_id": scan.Data[0].ID}, nil)
	if first.Code != http.StatusCreated {
		t.Fatalf("first import = %d, want 201", first.Code)
	}
	second := do(r, http.MethodPost, "/api/v1/discovery/import", gin.H{"result_id": scan.Data[0].ID}, nil)
	if second.Code != http.StatusOK {
		t.Fatalf("second import = %d, want 200 (%s)", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "already managed") {
		t.Errorf("the second import should say the certificate is already managed: %s", second.Body.String())
	}
}

func TestImportRejectsSomethingThatIsNotACertificate(t *testing.T) {
	r, _ := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/discovery/import",
		gin.H{"certificate_pem": "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (%s)", w.Code, w.Body.String())
	}

	empty := do(r, http.MethodPost, "/api/v1/discovery/import", gin.H{}, nil)
	if empty.Code != http.StatusBadRequest {
		t.Errorf("empty import status = %d, want 400", empty.Code)
	}
}

// A scan that reached nothing and a scan that found nothing produce the same
// empty results list. Only one of them means the estate is clean, so the
// summary has to distinguish them.
func TestSummaryDistinguishesUnreachableFromClean(t *testing.T) {
	unreachable := &store.DiscoveryScan{ResultsCount: 3, UnreachableCount: 3}
	clean := &store.DiscoveryScan{ResultsCount: 3, ManagedCount: 3}

	if summarize(unreachable) == summarize(clean) {
		t.Fatal("an estate nothing answered from reads the same as a clean one")
	}
	if !strings.Contains(summarize(unreachable), "answered") {
		t.Errorf("unreachable summary = %q", summarize(unreachable))
	}
	if !strings.Contains(summarize(clean), "already managed") {
		t.Errorf("clean summary = %q", summarize(clean))
	}
}

func TestScanHistoryIsReadable(t *testing.T) {
	r, _ := realRouter(t)
	target := startScanTarget(t)

	scanResp := do(r, http.MethodPost, "/api/v1/discovery/scan", gin.H{"targets": []string{target}}, nil)
	var scan struct {
		Scan *store.DiscoveryScan `json:"scan"`
	}
	_ = json.Unmarshal(scanResp.Body.Bytes(), &scan)

	list := do(r, http.MethodGet, "/api/v1/discovery/scans", nil, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d", list.Code)
	}
	if !strings.Contains(list.Body.String(), scan.Scan.ID) {
		t.Error("the scan just run is missing from the history")
	}

	detail := do(r, http.MethodGet, "/api/v1/discovery/scans/"+scan.Scan.ID, nil, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail status = %d (%s)", detail.Code, detail.Body.String())
	}

	filtered := do(r, http.MethodGet, "/api/v1/discovery/results?management_state=UNMANAGED", nil, nil)
	if filtered.Code != http.StatusOK {
		t.Fatalf("results status = %d", filtered.Code)
	}
	var results struct {
		Total int64 `json:"total"`
	}
	_ = json.Unmarshal(filtered.Body.Bytes(), &results)
	if results.Total != 1 {
		t.Errorf("unmanaged results = %d, want 1", results.Total)
	}
}

// startScanTarget brings up a TLS server with a self-signed certificate and
// returns its host:port.
func startScanTarget(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "discovered.test"},
		DNSNames:     []string{"discovered.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().(*net.TCPAddr)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port))
}

// A scan too wide to wait for goes to the background and says so. The client
// should not have to infer that from the status code.
func TestWideScanRunsInTheBackground(t *testing.T) {
	r, st := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/discovery/scan",
		gin.H{"targets": []string{"192.0.2.0/26"}}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%s)", w.Code, w.Body.String())
	}

	var resp struct {
		Scan        *store.DiscoveryScan `json:"scan"`
		Poll        string               `json:"poll"`
		Summary     string               `json:"summary"`
		TargetCount int                  `json:"target_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Scan.Status != store.ScanRunning {
		t.Errorf("status = %q, want RUNNING", resp.Scan.Status)
	}
	if resp.TargetCount != 62 {
		t.Errorf("target_count = %d, want 62 usable addresses in a /26", resp.TargetCount)
	}
	if !strings.Contains(resp.Poll, resp.Scan.ID) {
		t.Errorf("no poll URL for the run: %q", resp.Poll)
	}

	// Cancelled immediately: this test must not spend a minute connecting to
	// TEST-NET-1, and cancelling is the behaviour being relied on to do that.
	cancel := do(r, http.MethodPost, "/api/v1/discovery/scans/"+resp.Scan.ID+"/cancel", nil, nil)
	if cancel.Code != http.StatusOK {
		t.Fatalf("cancel status = %d (%s)", cancel.Code, cancel.Body.String())
	}
	if !strings.Contains(cancel.Body.String(), "already found is kept") {
		t.Errorf("the cancel response should say results are kept: %s", cancel.Body.String())
	}

	logs, _, err := st.ListAuditLogs(context.Background(),
		store.AuditLogFilter{Actions: []string{"discovery.cancelled"}})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("got %d cancellation audit entries, want 1", len(logs))
	}
}

// Expansion is where a typo becomes an incident: one misplaced digit turns a
// /24 into sixteen million outbound connections carrying CertPilot's address.
func TestScanRefusesAnAbsurdRange(t *testing.T) {
	r, st := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/discovery/scan", gin.H{"targets": []string{"10.0.0.0/8"}}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "16777216") {
		t.Errorf("the refusal does not say how large the range is: %s", w.Body.String())
	}

	scans, _, _ := st.ListDiscoveryScans(context.Background(), 10, 0)
	if len(scans) != 0 {
		t.Errorf("a refused range recorded %d scan(s); nothing should have been started", len(scans))
	}
}

// Cancelling a scan that is not running is not an error — it has usually just
// finished — but the response has to say what state it is actually in.
func TestCancellingAFinishedScanSaysSo(t *testing.T) {
	r, _ := realRouter(t)
	target := startScanTarget(t)

	scanResp := do(r, http.MethodPost, "/api/v1/discovery/scan", gin.H{"targets": []string{target}}, nil)
	var scan struct {
		Scan *store.DiscoveryScan `json:"scan"`
	}
	_ = json.Unmarshal(scanResp.Body.Bytes(), &scan)

	w := do(r, http.MethodPost, "/api/v1/discovery/scans/"+scan.Scan.ID+"/cancel", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "COMPLETED") {
		t.Errorf("the response should name the scan's actual status: %s", w.Body.String())
	}

	missing := do(r, http.MethodPost, "/api/v1/discovery/scans/no-such-scan/cancel", nil, nil)
	if missing.Code != http.StatusNotFound {
		t.Errorf("cancelling an unknown scan = %d, want 404", missing.Code)
	}
}

// The audit trail and the scan record keep what someone typed, not what it
// expanded into.
//
// A scan is repeated by re-running what was asked for and found again by the
// range somebody remembers typing. Two hundred and fifty four addresses in a
// scan record answer neither question, and they make the audit entry unreadable
// exactly when it is being read for a reason.
func TestScanRecordsWhatWasTypedNotWhatItExpandedTo(t *testing.T) {
	r, st := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/discovery/scan",
		gin.H{"targets": []string{"192.0.2.0/26"}}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Scan *store.DiscoveryScan `json:"scan"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	defer do(r, http.MethodPost, "/api/v1/discovery/scans/"+resp.Scan.ID+"/cancel", nil, nil)

	if len(resp.Scan.Targets) != 1 || resp.Scan.Targets[0] != "192.0.2.0/26" {
		t.Errorf("scan targets = %v, want the one entry that was typed", resp.Scan.Targets)
	}
	// The expansion is not lost — it is a count, which is what progress needs.
	if resp.Scan.TargetCount != 62 {
		t.Errorf("target_count = %d, want 62", resp.Scan.TargetCount)
	}

	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{Actions: []string{"discovery.scan"}})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(logs))
	}
	if !strings.Contains(logs[0].Details, "192.0.2.0/26") {
		t.Errorf("the audit entry does not record what was asked for: %s", logs[0].Details)
	}
	if strings.Contains(logs[0].Details, "192.0.2.17") {
		t.Errorf("the audit entry expanded the range into individual addresses: %s", logs[0].Details)
	}
	if !strings.Contains(logs[0].Details, `"endpoints":62`) {
		t.Errorf("the audit entry does not say how far the range expanded: %s", logs[0].Details)
	}
}

// A schedule is validated where it is entered, not on the night it matters.
// One that looks configured on screen and silently never scans is worse than
// no schedule at all.
func TestScheduleIsValidatedAtCreation(t *testing.T) {
	r, st := realRouter(t)

	cases := map[string]struct {
		body gin.H
		want string
	}{
		"targets that do not parse": {
			gin.H{"name": "typo", "targets": []string{"https://example.com"}, "interval_minutes": 1440},
			"looks like a URL",
		},
		"a range past the expansion limit": {
			gin.H{"name": "huge", "targets": []string{"10.0.0.0/8"}, "interval_minutes": 1440},
			"past the",
		},
		"an interval short enough to be a denial of service": {
			gin.H{"name": "hammer", "targets": []string{"example.com"}, "interval_minutes": 1},
			"shortest interval",
		},
		"a run that cannot finish before the next starts": {
			gin.H{"name": "overlap", "targets": []string{"10.0.0.0/20"}, "interval_minutes": 15},
			"overlap",
		},
	}
	for name, tc := range cases {
		w := do(r, http.MethodPost, "/api/v1/discovery/schedules", tc.body, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", name, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: response does not mention %q: %s", name, tc.want, w.Body.String())
		}
	}

	schedules, err := st.ListDiscoverySchedules(context.Background())
	if err != nil {
		t.Fatalf("ListDiscoverySchedules: %v", err)
	}
	if len(schedules) != 0 {
		t.Errorf("%d rejected schedules were stored anyway", len(schedules))
	}
}

func TestScheduleLifecycle(t *testing.T) {
	r, st := realRouter(t)
	target := startScanTarget(t)

	w := do(r, http.MethodPost, "/api/v1/discovery/schedules",
		gin.H{"name": "nightly perimeter", "targets": []string{target}, "interval_minutes": 1440}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d (%s)", w.Code, w.Body.String())
	}
	var created struct {
		Data *store.DiscoverySchedule `json:"data"`
		Next string                   `json:"next"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if !created.Data.IsEnabled {
		t.Error("a newly written schedule should be enabled")
	}
	if !strings.Contains(created.Next, "1 day(s)") {
		t.Errorf("the response does not say how often it will run: %q", created.Next)
	}

	// Running it now must not move its real schedule: someone testing what they
	// just wrote should not silently push tonight's run to tomorrow.
	run := do(r, http.MethodPost, "/api/v1/discovery/schedules/"+created.Data.ID+"/run", nil, nil)
	if run.Code != http.StatusAccepted {
		t.Fatalf("run status = %d (%s)", run.Code, run.Body.String())
	}
	after, err := st.GetDiscoverySchedule(context.Background(), created.Data.ID)
	if err != nil {
		t.Fatalf("GetDiscoverySchedule: %v", err)
	}
	if after.LastRunAt != nil || after.NextRunAt != nil {
		t.Error("running a schedule on demand moved its schedule")
	}

	upd := do(r, http.MethodPut, "/api/v1/discovery/schedules/"+created.Data.ID,
		gin.H{"name": "nightly perimeter", "targets": []string{target}, "interval_minutes": 720,
			"is_enabled": false}, nil)
	if upd.Code != http.StatusOK {
		t.Fatalf("update status = %d (%s)", upd.Code, upd.Body.String())
	}

	del := do(r, http.MethodDelete, "/api/v1/discovery/schedules/"+created.Data.ID, nil, nil)
	if del.Code != http.StatusOK {
		t.Fatalf("delete status = %d (%s)", del.Code, del.Body.String())
	}
	// Deleting is not neutral: those targets stop being watched by anything.
	if !strings.Contains(del.Body.String(), "no longer being watched") {
		t.Errorf("the delete response does not say what stops happening: %s", del.Body.String())
	}

	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{
		Actions: []string{"discovery.schedule_created", "discovery.schedule_updated", "discovery.schedule_deleted"},
	})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 3 {
		t.Errorf("got %d schedule audit entries, want 3", len(logs))
	}
}

// The outstanding-work list defaults to the latest observation per endpoint.
// A nightly schedule records the same unmanaged certificate every night, and
// counting each as a separate finding turns one problem into thirty.
func TestResultsDefaultToTheLatestObservation(t *testing.T) {
	r, _ := realRouter(t)
	target := startScanTarget(t)

	for i := 0; i < 3; i++ {
		if w := do(r, http.MethodPost, "/api/v1/discovery/scan", gin.H{"targets": []string{target}}, nil); w.Code != http.StatusOK {
			t.Fatalf("scan %d: %d (%s)", i, w.Code, w.Body.String())
		}
	}

	latest := do(r, http.MethodGet, "/api/v1/discovery/results", nil, nil)
	var latestBody struct {
		Total int64 `json:"total"`
	}
	_ = json.Unmarshal(latest.Body.Bytes(), &latestBody)
	if latestBody.Total != 1 {
		t.Errorf("default results total = %d, want 1 — three scans of one endpoint is one finding", latestBody.Total)
	}

	// The history is still reachable, which is what an investigation wants.
	all := do(r, http.MethodGet, "/api/v1/discovery/results?latest=false", nil, nil)
	var allBody struct {
		Total int64 `json:"total"`
	}
	_ = json.Unmarshal(all.Body.Bytes(), &allBody)
	if allBody.Total != 3 {
		t.Errorf("history total = %d, want 3", allBody.Total)
	}
}
