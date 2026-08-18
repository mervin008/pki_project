package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/engine/ctlog"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// stubCTSource stands in for the transparency index, so tests never reach a
// public service.
type stubCTSource struct{}

func (stubCTSource) Name() string { return "stub" }

func (stubCTSource) Search(_ context.Context, domain string, _ bool, _ *int64) ([]ctlog.Entry, error) {
	return []ctlog.Entry{
		{ID: 1, SerialNumber: "aabbcc", CommonName: "shadow." + domain,
			IssuerDN: "C=US, O=Let's Encrypt, CN=R11", SANs: []string{"shadow." + domain}},
	}, nil
}

func TestCTMonitorIsValidatedAtCreation(t *testing.T) {
	r, st := realRouter(t)

	cases := map[string]struct {
		body gin.H
		want string
	}{
		"a URL":            {gin.H{"domain": "https://example.com"}, "not a domain"},
		"a wildcard":       {gin.H{"domain": "*.example.com"}, "include_subdomains"},
		"not a domain":     {gin.H{"domain": "localhost"}, "does not look like"},
		"polling too hard": {gin.H{"domain": "example.com", "check_interval_minutes": 5}, "shortest check interval"},
	}
	for name, tc := range cases {
		w := do(r, http.MethodPost, "/api/v1/ct/monitors", tc.body, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", name, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: response does not mention %q: %s", name, tc.want, w.Body.String())
		}
	}

	monitors, err := st.ListCTMonitors(context.Background())
	if err != nil {
		t.Fatalf("ListCTMonitors: %v", err)
	}
	if len(monitors) != 0 {
		t.Errorf("%d rejected monitors were stored anyway", len(monitors))
	}
}

// Watching the same domain twice would double every alert about it.
func TestTheSameDomainCannotBeWatchedTwice(t *testing.T) {
	r, _ := realRouter(t)

	if w := do(r, http.MethodPost, "/api/v1/ct/monitors", gin.H{"domain": "example.com"}, nil); w.Code != http.StatusCreated {
		t.Fatalf("first create = %d (%s)", w.Code, w.Body.String())
	}
	// Different case, same domain.
	w := do(r, http.MethodPost, "/api/v1/ct/monitors", gin.H{"domain": "EXAMPLE.com"}, nil)
	if w.Code != http.StatusConflict {
		t.Errorf("second create = %d, want 409 (%s)", w.Code, w.Body.String())
	}
}

// An on-demand check returns what it found, and says plainly when it could not
// look — 502, not an empty list. "We looked and found nothing" and "we could
// not look" are opposite answers.
func TestOnDemandCheckReportsFindings(t *testing.T) {
	r, st := realRouter(t)

	create := do(r, http.MethodPost, "/api/v1/ct/monitors", gin.H{"domain": "example.com"}, nil)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", create.Code, create.Body.String())
	}
	var created struct {
		Data *store.CTMonitor `json:"data"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &created)

	w := do(r, http.MethodPost, "/api/v1/ct/monitors/"+created.Data.ID+"/check", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("check = %d (%s)", w.Code, w.Body.String())
	}
	var checked struct {
		Data    *store.CTMonitor       `json:"data"`
		Found   []*store.CTCertificate `json:"found"`
		Summary string                 `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &checked); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(checked.Found) != 1 {
		t.Fatalf("found %d certificates, want 1", len(checked.Found))
	}
	if checked.Found[0].ManagementState != store.DiscoveryUnmanaged {
		t.Errorf("state = %q, want UNMANAGED", checked.Found[0].ManagementState)
	}
	if checked.Data.LastSuccessAt == nil {
		t.Error("a successful check did not record last_success_at")
	}
	// The summary has to say what it means, not that a job ran.
	if !strings.Contains(checked.Summary, "private keys") {
		t.Errorf("summary does not say what an unmanaged certificate means: %q", checked.Summary)
	}

	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{Actions: []string{"ct.monitor_created"}})
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("got %d audit entries, want 1", len(logs))
	}
}

// A list of monitors has to surface the ones that have stopped answering.
// Reporting only "last checked" lets a monitor that has been unable to reach
// the log for a week read exactly like one that has found nothing.
func TestStaleMonitorsAreSurfaced(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	monitor := &store.CTMonitor{
		Domain: "neglected.example", IsEnabled: true, CheckIntervalMinutes: 60,
	}
	if err := st.CreateCTMonitor(ctx, monitor); err != nil {
		t.Fatalf("CreateCTMonitor: %v", err)
	}

	// Aged through the path a real check takes. It cannot be back-dated through
	// UpdateCTMonitor, and deliberately so: editing a monitor must not rewrite
	// when it was created or when it last answered.
	longAgo := time.Now().Add(-72 * time.Hour)
	if err := st.MarkCTMonitorChecked(ctx, monitor.ID, longAgo, longAgo.Add(time.Hour),
		true, nil, 0, 0, ""); err != nil {
		t.Fatalf("MarkCTMonitorChecked: %v", err)
	}

	w := do(r, http.MethodGet, "/api/v1/ct/monitors", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d", w.Code)
	}
	var body struct {
		StaleDomains []string `json:"stale_domains"`
		Warning      string   `json:"warning"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)

	if len(body.StaleDomains) != 1 || body.StaleDomains[0] != "neglected.example" {
		t.Errorf("stale domains = %v, want the one that has never answered", body.StaleDomains)
	}
	if !strings.Contains(body.Warning, "Nothing is watching") {
		t.Errorf("the warning does not say what the consequence is: %q", body.Warning)
	}
}
