package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func verifyReport(t *testing.T, r *gin.Engine, query string) *store.AuditChainReport {
	t.Helper()
	w := do(r, http.MethodGet, "/api/v1/audit/verify"+query, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /audit/verify%s = %d, want 200: %s", query, w.Code, w.Body.String())
	}
	report := &store.AuditChainReport{}
	if err := json.Unmarshal(w.Body.Bytes(), report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return report
}

// A record nothing has touched must verify, and the endpoint must say how much
// of it the answer actually covers.
func TestVerifyReportsAnIntactChain(t *testing.T) {
	r, st := realRouter(t)

	for i := 0; i < 3; i++ {
		if err := st.CreateAuditLog(context.Background(), &store.AuditLog{
			Action:     "certificate.issued",
			EntityType: "certificate",
			Details:    `{"cn":"a.example.test"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}

	report := verifyReport(t, r, "")
	if !report.Intact {
		t.Fatalf("expected an intact chain, got %q", report.Reason)
	}
	if report.Verified < 3 {
		t.Errorf("expected at least the 3 entries just written, got %d", report.Verified)
	}
}

// The people who could tamper with the audit log are the ones this answer would
// implicate. Telling them whether the check passes tells them whether a rewrite
// worked.
func TestVerifyIsAdminOnly(t *testing.T) {
	r, st := realRouter(t)

	viewer, err := st.ResolveUser(context.Background(), store.UserIdentity{
		Issuer:  apiTestIssuer,
		Subject: "00uAPITESTviewer01",
		Email:   "viewer@certpilot.test",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if viewer.Role == store.RoleAdmin {
		t.Fatalf("the harness gave the viewer an admin role, which would make this test vacuous")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &middleware.UserClaims{
		Email: "viewer@certpilot.test",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "00uAPITESTviewer01",
			Issuer:    apiTestIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := token.SignedString([]byte(apiTestSecret))
	if err != nil {
		t.Fatal(err)
	}

	w := do(r, http.MethodGet, "/api/v1/audit/verify", nil,
		map[string]string{"Authorization": "Bearer " + signed})
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET /audit/verify as a viewer = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// A display token is a credential left on an unattended screen in a corridor.
// It is refused on every route above viewer, and this is one of them.
func TestVerifyRefusesADisplayToken(t *testing.T) {
	r, _ := realRouter(t)
	raw, _ := mintToken(t, r, "corridor screen", 30)

	w := do(r, http.MethodGet, "/api/v1/audit/verify", nil,
		map[string]string{"X-Display-Token": raw})
	if w.Code == http.StatusOK {
		t.Fatalf("a display token must not be able to ask whether the audit log is intact: %s", w.Body.String())
	}
}

func TestVerifyRejectsBadParameters(t *testing.T) {
	r, _ := realRouter(t)

	for _, query := range []string{"?from=0", "?from=nonsense", "?limit=0", "?limit=999999", "?nonsense=1"} {
		w := do(r, http.MethodGet, "/api/v1/audit/verify"+query, nil, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET /audit/verify%s = %d, want 400: %s", query, w.Code, w.Body.String())
		}
	}
}

// A partial walk must not present itself as a whole-record guarantee.
func TestVerifyMarksATruncatedWalk(t *testing.T) {
	r, st := realRouter(t)
	for i := 0; i < 5; i++ {
		if err := st.CreateAuditLog(context.Background(), &store.AuditLog{
			Action: "ca.checked", EntityType: "ca_authority",
		}); err != nil {
			t.Fatal(err)
		}
	}

	report := verifyReport(t, r, "?limit=2")
	if !report.Truncated {
		t.Error("a walk that stopped at its limit must say so")
	}
	if report.Verified != 2 {
		t.Errorf("expected 2 entries checked, got %d", report.Verified)
	}
}
