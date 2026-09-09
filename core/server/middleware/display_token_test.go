package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
)

// fakeDisplayStore is a minimal DisplayTokenStore. Touches are reported on a
// channel because they happen on a goroutine deliberately kept off the request
// path.
type fakeDisplayStore struct {
	mu      sync.Mutex
	tokens  map[string]*store.DisplayToken // keyed by hash
	touched chan touch
}

type touch struct {
	ID string
	IP string
	At time.Time
}

func newFakeDisplayStore() *fakeDisplayStore {
	return &fakeDisplayStore{
		tokens:  make(map[string]*store.DisplayToken),
		touched: make(chan touch, 16),
	}
}

func (f *fakeDisplayStore) add(t *store.DisplayToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[t.TokenHash] = t
}

func (f *fakeDisplayStore) GetDisplayTokenByHash(_ context.Context, hash string) (*store.DisplayToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[hash]
	if !ok {
		return nil, fmt.Errorf("display token not found")
	}
	clone := *t
	return &clone, nil
}

func (f *fakeDisplayStore) TouchDisplayToken(_ context.Context, id string, seenAt time.Time, ip string) error {
	f.touched <- touch{ID: id, IP: ip, At: seenAt}
	return nil
}

// issueToken mints a token, registers it, and returns the raw value.
func issueToken(t *testing.T, f *fakeDisplayStore, name string, mutate func(*store.DisplayToken)) string {
	t.Helper()

	raw, hash, err := GenerateDisplayToken()
	if err != nil {
		t.Fatalf("GenerateDisplayToken: %v", err)
	}
	tok := &store.DisplayToken{
		ID:        "token-" + name,
		Name:      name,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
	if mutate != nil {
		mutate(tok)
	}
	f.add(tok)
	return raw
}

// displayRouter mirrors the real chain: display tokens first, bearer second.
//
// The routes are the real ones from router.go, because the guarantee being
// tested is about paths a screen might actually reach, and a synthetic "/test"
// route would prove nothing about "/certificates/:id/private-key".
func displayRouter(f *fakeDisplayStore, cfg config.AuthConfig) *gin.Engine {
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = testSecret
	}
	cfg.RoleClaim = "certpilot_role"
	a, err := NewAuthenticator(context.Background(), cfg)
	if err != nil {
		panic(err)
	}

	echo := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"role":        c.GetString(ContextUserRole),
			"user":        c.GetString(ContextUserID),
			"email":       c.GetString(ContextUserEmail),
			"auth_method": c.GetString(ContextAuthMethod),
			"token_id":    c.GetString(ContextDisplayTokenID),
		})
	}

	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.Use(DisplayTokenAuth(f))
	v1.Use(a.Middleware())
	{
		v1.GET("/events", echo)
		v1.GET("/pki/authorities", echo)
		v1.GET("/dashboard/stats", echo)
		v1.GET("/dashboard/activity", echo)
		v1.GET("/certificates", echo)
		v1.POST("/certificates", RequireRole(RoleOperator), echo)
		v1.GET("/certificates/:id", echo)
		v1.PUT("/certificates/:id", RequireRole(RoleOperator), echo)
		v1.PATCH("/certificates/:id", RequireRole(RoleOperator), echo)
		v1.DELETE("/certificates/:id", RequireRole(RoleAdmin), echo)
		v1.POST("/certificates/:id/renew", RequireRole(RoleOperator), echo)
		v1.GET("/certificates/:id/private-key", RequireRole(RoleAdmin), echo)
		v1.GET("/display-tokens", RequireRole(RoleAdmin), echo)
		v1.POST("/display-tokens", RequireRole(RoleAdmin), echo)
		v1.DELETE("/display-tokens/:id", RequireRole(RoleAdmin), echo)
		v1.POST("/pki/authorities", RequireRole(RoleOperator), echo)
		v1.DELETE("/pki/authorities/:id", RequireRole(RoleAdmin), echo)
	}
	return r
}

// callWithDisplayToken sends the token in the header.
func callWithDisplayToken(r *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("X-Display-Token", token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return body
}

func TestDisplayTokenGrantsReadOnlyViewerAccess(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "corridor-screen", nil)
	r := displayRouter(f, config.AuthConfig{})

	for _, path := range []string{"/api/v1/events", "/api/v1/pki/authorities", "/api/v1/dashboard/stats", "/api/v1/certificates"} {
		t.Run(path, func(t *testing.T) {
			w := callWithDisplayToken(r, http.MethodGet, path, raw)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
			body := decodeBody(t, w)
			if body["role"] != RoleViewer {
				t.Fatalf("role = %q, want viewer", body["role"])
			}
			if body["auth_method"] != AuthMethodDisplayToken {
				t.Fatalf("auth_method = %q, want %q", body["auth_method"], AuthMethodDisplayToken)
			}
			if body["token_id"] != "token-corridor-screen" {
				t.Fatalf("token_id = %q", body["token_id"])
			}
		})
	}
}

// The central guarantee: this credential sits on an unattended screen, so no
// request that changes anything may succeed with it, on any route, by any
// method.
func TestDisplayTokenRejectedOnEveryWriteRoute(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)
	r := displayRouter(f, config.AuthConfig{})

	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/certificates"},
		{http.MethodPut, "/api/v1/certificates/abc"},
		{http.MethodPatch, "/api/v1/certificates/abc"},
		{http.MethodDelete, "/api/v1/certificates/abc"},
		{http.MethodPost, "/api/v1/certificates/abc/renew"},
		{http.MethodPost, "/api/v1/pki/authorities"},
		{http.MethodDelete, "/api/v1/pki/authorities/abc"},
		{http.MethodPost, "/api/v1/display-tokens"},
		{http.MethodDelete, "/api/v1/display-tokens/abc"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := callWithDisplayToken(r, tc.method, tc.path, raw)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 — a display token performed a write (body: %s)",
					w.Code, w.Body.String())
			}
		})
	}
}

// These are GET routes, so the method check does not cover them. They are
// refused by path, independently of the role gate they already carry.
func TestDisplayTokenRejectedOnSensitiveReads(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)
	r := displayRouter(f, config.AuthConfig{})

	cases := map[string]string{
		"private key export":             "/api/v1/certificates/abc/private-key",
		"token enumeration":              "/api/v1/display-tokens",
		"actor-attributed activity feed": "/api/v1/dashboard/activity",
	}

	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			w := callWithDisplayToken(r, http.MethodGet, path, raw)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

// Even if a future change loosened the role gate on private-key export, the
// path check must still refuse a display token. This asserts the second barrier
// exists rather than the first one merely happening to fire.
func TestPrivateKeyIsRefusedByPathNotOnlyByRole(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)

	r := gin.New()
	a, err := NewAuthenticator(context.Background(), config.AuthConfig{JWTSecret: testSecret, RoleClaim: "certpilot_role"})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	v1 := r.Group("/api/v1")
	v1.Use(DisplayTokenAuth(f))
	v1.Use(a.Middleware())
	// Deliberately ungated, standing in for a future mistake.
	v1.GET("/certificates/:id/private-key", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := callWithDisplayToken(r, http.MethodGet, "/api/v1/certificates/abc/private-key", raw)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — the path barrier did not hold on its own", w.Code)
	}
}

func TestRevokedAndExpiredTokensAreRejected(t *testing.T) {
	f := newFakeDisplayStore()
	revokedAt := time.Now().Add(-time.Hour)

	revoked := issueToken(t, f, "revoked", func(tok *store.DisplayToken) {
		tok.RevokedAt = &revokedAt
	})
	expired := issueToken(t, f, "expired", func(tok *store.DisplayToken) {
		tok.ExpiresAt = time.Now().Add(-time.Minute)
	})
	// Revocation must win over a still-valid expiry, and must not be undone by
	// one.
	revokedButUnexpired := issueToken(t, f, "revoked-unexpired", func(tok *store.DisplayToken) {
		tok.RevokedAt = &revokedAt
		tok.ExpiresAt = time.Now().Add(365 * 24 * time.Hour)
	})

	r := displayRouter(f, config.AuthConfig{})

	for name, raw := range map[string]string{
		"revoked":                revoked,
		"expired":                expired,
		"revoked but unexpired":  revokedButUnexpired,
		"never issued":           "cpd_" + strings.Repeat("A", 43),
		"empty after the prefix": "cpd_",
	} {
		t.Run(name, func(t *testing.T) {
			w := callWithDisplayToken(r, http.MethodGet, "/api/v1/pki/authorities", raw)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

// The response must not distinguish revoked from expired from never-issued: the
// difference is useful to an operator reading logs and useful to an attacker
// probing the API, and only one of them should get it.
func TestRejectionReasonIsNotDisclosed(t *testing.T) {
	f := newFakeDisplayStore()
	revokedAt := time.Now()
	revoked := issueToken(t, f, "revoked", func(tok *store.DisplayToken) { tok.RevokedAt = &revokedAt })
	unknown := "cpd_" + strings.Repeat("B", 43)

	r := displayRouter(f, config.AuthConfig{})

	first := callWithDisplayToken(r, http.MethodGet, "/api/v1/pki/authorities", revoked)
	second := callWithDisplayToken(r, http.MethodGet, "/api/v1/pki/authorities", unknown)

	if first.Body.String() != second.Body.String() {
		t.Fatalf("responses differ: revoked=%q unknown=%q", first.Body.String(), second.Body.String())
	}
}

// A rejected display token must abort, not fall through.
//
// This was the sharpest failure available while anonymous access existed: a
// token that failed would have landed on the anonymous path and been granted
// admin. Anonymous access is gone, so the consequence is now a 401 rather than
// a privilege escalation — but the property being tested is the same one, and
// it is the property that would matter again if any fallback were ever added.
func TestInvalidDisplayTokenNeverFallsThrough(t *testing.T) {
	f := newFakeDisplayStore()
	r := displayRouter(f, config.AuthConfig{JWTSecret: testSecret})

	w := callWithDisplayToken(r, http.MethodGet, "/api/v1/pki/authorities", "cpd_"+strings.Repeat("C", 43))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a rejected display token fell through instead of aborting (body: %s)",
			w.Code, w.Body.String())
	}
}

// A valid display token is viewer and stays viewer, whatever else is
// configured.
func TestValidDisplayTokenIsAlwaysViewer(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)
	r := displayRouter(f, config.AuthConfig{JWTSecret: testSecret})

	w := callWithDisplayToken(r, http.MethodGet, "/api/v1/pki/authorities", raw)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if role := decodeBody(t, w)["role"]; role != RoleViewer {
		t.Fatalf("role = %q, want viewer", role)
	}
}

func TestDisplayTokenAcceptedFromQueryString(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)
	r := displayRouter(f, config.AuthConfig{})

	// EventSource cannot set headers, so this is the path the wall display
	// actually uses to reach the stream.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?display_token="+raw, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if role := decodeBody(t, w)["role"]; role != RoleViewer {
		t.Fatalf("role = %q, want viewer", role)
	}
}

// A display token in the query string must not silently downgrade a real
// session, or an operator's actions would be attributed to a screen.
func TestBearerTakesPrecedenceOverDisplayToken(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)
	r := displayRouter(f, config.AuthConfig{JWTSecret: testSecret})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?display_token="+raw, nil)
	req.Header.Set("Authorization", "Bearer "+signHS256(t, validClaims(RoleOperator)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["role"] != RoleOperator {
		t.Fatalf("role = %q, want operator", body["role"])
	}
	if body["auth_method"] != AuthMethodBearer {
		t.Fatalf("auth_method = %q, want bearer", body["auth_method"])
	}
}

// And a display token must not rescue a request whose bearer token is bad.
func TestDisplayTokenDoesNotRescueAnInvalidBearerToken(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)
	r := displayRouter(f, config.AuthConfig{JWTSecret: testSecret})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates?display_token="+raw, nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestNoDisplayTokenFallsThroughToBearerAuth(t *testing.T) {
	f := newFakeDisplayStore()
	r := displayRouter(f, config.AuthConfig{JWTSecret: testSecret})

	if w := callWithDisplayToken(r, http.MethodGet, "/api/v1/certificates", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no credentials at all", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	req.Header.Set("Authorization", "Bearer "+signHS256(t, validClaims(RoleAdmin)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a valid bearer token", w.Code)
	}
}

func TestLastSeenIsRecordedAndThrottled(t *testing.T) {
	f := newFakeDisplayStore()
	raw := issueToken(t, f, "screen", nil)
	r := displayRouter(f, config.AuthConfig{})

	if w := callWithDisplayToken(r, http.MethodGet, "/api/v1/pki/authorities", raw); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	select {
	case got := <-f.touched:
		if got.ID != "token-screen" {
			t.Fatalf("touched token %q", got.ID)
		}
		if got.IP == "" {
			t.Fatal("no client IP recorded — a leaked token would be invisible")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("last-seen was never recorded")
	}

	// A screen polls; the second and third requests must not each cost a write.
	for range 5 {
		callWithDisplayToken(r, http.MethodGet, "/api/v1/pki/authorities", raw)
	}
	select {
	case got := <-f.touched:
		t.Fatalf("last-seen written again within the throttle window: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestGenerateDisplayTokenProperties(t *testing.T) {
	seen := make(map[string]bool)

	for range 100 {
		raw, hash, err := GenerateDisplayToken()
		if err != nil {
			t.Fatalf("GenerateDisplayToken: %v", err)
		}
		if !strings.HasPrefix(raw, DisplayTokenPrefix) {
			t.Fatalf("token %q has no %q prefix — secret scanners rely on it", raw, DisplayTokenPrefix)
		}
		// 32 bytes in unpadded base64url is 43 characters.
		if body := strings.TrimPrefix(raw, DisplayTokenPrefix); len(body) != 43 {
			t.Fatalf("token body is %d characters, want 43 (256 bits)", len(body))
		}
		if seen[raw] {
			t.Fatal("a token was generated twice")
		}
		seen[raw] = true

		if hash != HashDisplayToken(raw) {
			t.Fatal("hash is not a deterministic function of the raw token")
		}
		if len(hash) != 64 {
			t.Fatalf("hash is %d characters, want 64 hex characters", len(hash))
		}
		if strings.Contains(hash, strings.TrimPrefix(raw, DisplayTokenPrefix)) {
			t.Fatal("the hash contains the raw token")
		}
	}
}

func TestRedactQueryString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string // substrings that must NOT appear
		keep string   // substring that must appear
	}{
		{
			name: "display token in query",
			in:   "/api/v1/events?display_token=cpd_supersecretvalue",
			want: []string{"cpd_supersecretvalue"},
			keep: "REDACTED",
		},
		{
			name: "no query string is untouched",
			in:   "/api/v1/certificates",
			keep: "/api/v1/certificates",
		},
		{
			name: "unrelated parameters survive",
			in:   "/api/v1/certificates?status=ISSUED",
			keep: "status=ISSUED",
		},
		{
			name: "unparseable query is dropped whole",
			in:   "/api/v1/events?display_token=%zz",
			want: []string{"%zz"},
			keep: "REDACTED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactQueryString(tc.in)
			for _, forbidden := range tc.want {
				if strings.Contains(got, forbidden) {
					t.Fatalf("redacted target %q still contains %q", got, forbidden)
				}
			}
			if tc.keep != "" && !strings.Contains(got, tc.keep) {
				t.Fatalf("redacted target %q does not contain %q", got, tc.keep)
			}
		})
	}
}

func TestDisplayTokenStatusTransitions(t *testing.T) {
	now := time.Now()
	revoked := now.Add(-time.Hour)

	cases := []struct {
		name  string
		token store.DisplayToken
		want  string
	}{
		{"active", store.DisplayToken{ExpiresAt: now.Add(time.Hour)}, store.DisplayTokenActive},
		{"expired", store.DisplayToken{ExpiresAt: now.Add(-time.Second)}, store.DisplayTokenExpired},
		{"expiring exactly now", store.DisplayToken{ExpiresAt: now}, store.DisplayTokenExpired},
		{"revoked", store.DisplayToken{ExpiresAt: now.Add(time.Hour), RevokedAt: &revoked}, store.DisplayTokenRevoked},
		{"revoked and expired reads as revoked", store.DisplayToken{ExpiresAt: now.Add(-time.Hour), RevokedAt: &revoked}, store.DisplayTokenRevoked},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.token.Status(now); got != tc.want {
				t.Fatalf("Status = %q, want %q", got, tc.want)
			}
			if usable := tc.token.IsUsable(now); usable != (tc.want == store.DisplayTokenActive) {
				t.Fatalf("IsUsable = %v for status %q", usable, tc.want)
			}
		})
	}
}
