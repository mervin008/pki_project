package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func init() { gin.SetMode(gin.TestMode) }

const testSecret = "test-shared-secret-that-is-long-enough"

func signHS256(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func validClaims(role string) *UserClaims {
	c := &UserClaims{
		Email: "operator@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "11111111-1111-1111-1111-111111111111",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if role != "" {
		c.AppMetadata = map[string]any{"certpilot_role": role}
	}
	return c
}

func newTestAuth(t *testing.T, cfg config.AuthConfig) *Authenticator {
	t.Helper()
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "certpilot_role"
	}
	a, err := NewAuthenticator(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

func runRequest(a *Authenticator, authHeader string, handlers ...gin.HandlerFunc) *httptest.ResponseRecorder {
	r := gin.New()
	group := r.Group("/", a.Middleware())
	group.Use(handlers...)
	group.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"role":  c.GetString(ContextUserRole),
			"user":  c.GetString(ContextUserID),
			"email": c.GetString(ContextUserEmail),
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestValidTokenIsAccepted(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	w := runRequest(a, "Bearer "+signHS256(t, validClaims(RoleOperator)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["role"] != RoleOperator {
		t.Fatalf("role = %q, want %q", body["role"], RoleOperator)
	}
	if body["email"] != "operator@example.com" {
		t.Fatalf("email = %q", body["email"])
	}
}

// This is the regression test for the bypass: previously, a token that failed
// validation fell through to a hardcoded admin identity whenever dev mode was
// on. An invalid token must always be a rejection.
func TestInvalidTokenIsNeverAdmin(t *testing.T) {
	cases := map[string]config.AuthConfig{
		"secret configured":          {JWTSecret: testSecret},
		"anonymous access permitted": {JWTSecret: testSecret, AllowAnonymous: true},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			a := newTestAuth(t, cfg)

			forged := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims(RoleAdmin))
			signed, err := forged.SignedString([]byte("the-wrong-secret"))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			w := runRequest(a, "Bearer "+signed)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 — a token signed with the wrong key was accepted (body: %s)",
					w.Code, w.Body.String())
			}
		})
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	claims := validClaims(RoleAdmin)
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))

	w := runRequest(a, "Bearer "+signHS256(t, claims))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an expired token", w.Code)
	}
}

func TestTokenWithoutExpiryIsRejected(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	claims := validClaims(RoleAdmin)
	claims.ExpiresAt = nil

	w := runRequest(a, "Bearer "+signHS256(t, claims))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a token with no expiry", w.Code)
	}
}

// The "none" algorithm attack: an attacker strips the signature and sets alg to
// none. Pinning accepted algorithms is what prevents it.
func TestNoneAlgorithmIsRejected(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	token := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims(RoleAdmin))
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	w := runRequest(a, "Bearer "+signed)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an unsigned token", w.Code)
	}
}

func TestMissingAndMalformedHeaders(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	cases := map[string]string{
		"no header":        "",
		"no bearer prefix": signHS256(t, validClaims(RoleAdmin)),
		"empty bearer":     "Bearer ",
		"wrong scheme":     "Basic dXNlcjpwYXNz",
	}

	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			w := runRequest(a, header)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

func TestAnonymousAccessOnlyAppliesWithNoHeader(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{AllowAnonymous: true})

	w := runRequest(a, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when anonymous access is enabled", w.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["role"] != RoleAdmin {
		t.Fatalf("anonymous role = %q, want admin", body["role"])
	}
}

// Roles come from app_metadata, which the user cannot write. A role smuggled in
// at the top level or in user_metadata must be ignored.
func TestRoleIsReadOnlyFromAppMetadata(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	type sneakyClaims struct {
		Role         string         `json:"role"`
		UserMetadata map[string]any `json:"user_metadata"`
		UserClaims
	}

	claims := sneakyClaims{
		Role:         RoleAdmin,
		UserMetadata: map[string]any{"certpilot_role": RoleAdmin},
		UserClaims:   *validClaims(""),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	w := runRequest(a, "Bearer "+signed)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["role"] != RoleViewer {
		t.Fatalf("role = %q, want viewer — a role outside app_metadata was trusted", body["role"])
	}
}

func TestUnknownRoleFallsBackToViewer(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	claims := validClaims("superuser")
	w := runRequest(a, "Bearer "+signHS256(t, claims))

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["role"] != RoleViewer {
		t.Fatalf("role = %q, want viewer for an unrecognised role", body["role"])
	}
}

func TestRequireRole(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})

	cases := []struct {
		name     string
		role     string
		required []string
		want     int
	}{
		{"admin passes operator gate", RoleAdmin, []string{RoleOperator}, http.StatusOK},
		{"admin passes admin gate", RoleAdmin, []string{RoleAdmin}, http.StatusOK},
		{"operator passes operator gate", RoleOperator, []string{RoleOperator}, http.StatusOK},
		{"operator blocked from admin gate", RoleOperator, []string{RoleAdmin}, http.StatusForbidden},
		{"viewer blocked from operator gate", RoleViewer, []string{RoleOperator}, http.StatusForbidden},
		{"auditor blocked from operator gate", RoleAuditor, []string{RoleOperator}, http.StatusForbidden},
		{"auditor passes multi-role gate", RoleAuditor, []string{RoleOperator, RoleAuditor}, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := runRequest(a, "Bearer "+signHS256(t, validClaims(tc.role)), RequireRole(tc.required...))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestNewAuthenticatorRequiresAVerificationMethod(t *testing.T) {
	if _, err := NewAuthenticator(context.Background(), config.AuthConfig{}); err == nil {
		t.Fatal("expected an error when no verification method is configured")
	}
}

func TestIssuerAndAudienceAreEnforced(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{
		JWTSecret: testSecret,
		Issuer:    "https://issuer.example.com",
		Audience:  "certpilot",
	})

	t.Run("matching", func(t *testing.T) {
		claims := validClaims(RoleOperator)
		claims.Issuer = "https://issuer.example.com"
		claims.Audience = jwt.ClaimStrings{"certpilot"}

		if w := runRequest(a, "Bearer "+signHS256(t, claims)); w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		claims := validClaims(RoleOperator)
		claims.Issuer = "https://evil.example.com"
		claims.Audience = jwt.ClaimStrings{"certpilot"}

		if w := runRequest(a, "Bearer "+signHS256(t, claims)); w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 for a token from another issuer", w.Code)
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		claims := validClaims(RoleOperator)
		claims.Issuer = "https://issuer.example.com"
		claims.Audience = jwt.ClaimStrings{"some-other-service"}

		if w := runRequest(a, "Bearer "+signHS256(t, claims)); w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 for a token minted for another audience", w.Code)
		}
	})
}

// JWKS verification is the path production should use, so it gets an
// end-to-end test against a real key set.
func TestJWKSVerification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pub, err := jwk.Import(key.Public())
	if err != nil {
		t.Fatalf("import key: %v", err)
	}
	if err := pub.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pub.Set(jwk.AlgorithmKey, "ES256"); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		t.Fatalf("add key: %v", err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
	}))
	defer srv.Close()

	a := newTestAuth(t, config.AuthConfig{JWKSURL: srv.URL})

	token := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims(RoleOperator))
	token.Header["kid"] = "test-key-1"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	w := runRequest(a, "Bearer "+signed)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["role"] != RoleOperator {
		t.Fatalf("role = %q, want operator", body["role"])
	}

	// A token signed by a different key must not be accepted.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims(RoleAdmin))
	forged.Header["kid"] = "test-key-1"
	forgedSigned, err := forged.SignedString(other)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if w := runRequest(a, "Bearer "+forgedSigned); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a token signed by an unknown key", w.Code)
	}
}

// When only a JWKS is configured, an HMAC token must not be accepted — that is
// the algorithm-confusion attack.
func TestHMACTokenRejectedWhenOnlyJWKSConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	a := newTestAuth(t, config.AuthConfig{JWKSURL: srv.URL})

	w := runRequest(a, "Bearer "+signHS256(t, validClaims(RoleAdmin)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an HMAC token against a JWKS-only configuration", w.Code)
	}
}

func TestCORSRestrictsOrigins(t *testing.T) {
	r := gin.New()
	r.Use(CORS([]string{"http://localhost:5173", "https://certpilot.example.com"}))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	cases := []struct {
		origin      string
		wantAllowed string
	}{
		{"http://localhost:5173", "http://localhost:5173"},
		{"https://certpilot.example.com", "https://certpilot.example.com"},
		{"https://evil.example.com", ""},
		{"", ""},
	}

	for _, tc := range cases {
		t.Run(tc.origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			got := w.Header().Get("Access-Control-Allow-Origin")
			if got != tc.wantAllowed {
				t.Fatalf("Allow-Origin = %q, want %q", got, tc.wantAllowed)
			}
			// A wildcard with credentials is rejected by browsers outright.
			if got == "*" {
				t.Fatal("Allow-Origin must never be a wildcard when credentials are allowed")
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	r := gin.New()
	r.Use(SecurityHeaders())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Cache-Control":          "no-store",
	}
	for header, expected := range want {
		if got := w.Header().Get(header); got != expected {
			t.Errorf("%s = %q, want %q", header, got, expected)
		}
	}
}
