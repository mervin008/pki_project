package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// A real identity provider, in the sense that matters here: it publishes a
// discovery document, serves a JWKS, and exchanges an authorization code for a
// signed ID token. Stubbing the exchange instead would leave the parts most
// worth testing — audience, issuer, nonce and signature — untested.
type fakeIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	// What the next token exchange will return, so a test can hand back a
	// token that is wrong in exactly one way.
	idToken func(issuer string) string
	// Set when the exchange is called, so a test can assert what was sent.
	lastForm map[string]string
	// Refuse the exchange outright, the way a provider does for a spent code.
	refuseExchange bool
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 idp.server.URL,
			"authorization_endpoint": idp.server.URL + "/authorize",
			"token_endpoint":         idp.server.URL + "/token",
			"jwks_uri":               idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub, err := jwk.Import(key.Public())
		if err != nil {
			t.Error(err)
			return
		}
		_ = pub.Set(jwk.KeyIDKey, idp.kid)
		_ = pub.Set(jwk.AlgorithmKey, "RS256")
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		_ = json.NewEncoder(w).Encode(set)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if idp.refuseExchange {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_ = r.ParseForm()
		idp.lastForm = map[string]string{}
		for k := range r.PostForm {
			idp.lastForm[k] = r.PostForm.Get(k)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "an-access-token-nobody-should-keep",
			"refresh_token": "a-refresh-token-nobody-should-keep",
			"id_token":      idp.idToken(idp.server.URL),
			"token_type":    "Bearer",
			"expires_in":    300,
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// signIDToken mints an ID token. Every field a test might want to spoil is a
// parameter, because the negative cases are the point of this file.
func (f *fakeIDP) signIDToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.kid
	signed, err := token.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (f *fakeIDP) goodClaims(clientID string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   f.server.URL,
		"sub":   "00uFEDERATEDsubject1",
		"aud":   clientID,
		"email": "federated@example.test",
		"name":  "Federated Operator",
		"nonce": "the-nonce-from-this-attempt",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
}

const federatedClientID = "certpilot-console-test"

// oidcRouter wires a core configured against the fake provider.
func oidcRouter(t *testing.T, idp *fakeIDP) (*gin.Engine, store.Store) {
	t.Helper()

	st := store.NewMemoryStore()
	cfg := config.AuthConfig{
		Issuer:    idp.server.URL,
		ClientID:  federatedClientID,
		JWKSURL:   idp.server.URL + "/jwks",
		RoleClaim: "certpilot_role",
	}

	auth, err := middleware.NewAuthenticator(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	auth = auth.WithUserDirectory(st)

	engine := gin.New()
	handler := NewSessionHandler(st, cfg, auth)
	engine.POST("/api/v1/auth/callback", handler.Callback)
	_ = events.NewBroker()
	return engine, st
}

func callback(t *testing.T, r *gin.Engine, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return do(r, http.MethodPost, "/api/v1/auth/callback", body, nil)
}

func goodCallbackBody() map[string]any {
	return map[string]any{
		"code":          "an-authorization-code",
		"code_verifier": "a-code-verifier-of-adequate-length-for-pkce",
		"redirect_uri":  "http://localhost:3000/auth/callback",
		"nonce":         "the-nonce-from-this-attempt",
	}
}

// The happy path, and the property this whole change exists for: the browser
// gets a session cookie and nothing token-shaped.
func TestFederatedCallbackIssuesASessionCookie(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string { return idp.signIDToken(t, idp.goodClaims(federatedClientID)) }
	r, _ := oidcRouter(t, idp)

	w := callback(t, r, goodCallbackBody())
	if w.Code != http.StatusOK {
		t.Fatalf("callback = %d, want 200: %s", w.Code, w.Body.String())
	}

	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == middleware.SessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie was set, so the browser has no credential at all")
	}
	if !cookie.HttpOnly {
		t.Error("the session cookie must be httpOnly; a readable one is the thing this replaced")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie must be SameSite=Strict")
	}

	// The response must not carry the provider's tokens onward, or the browser
	// is back to holding one by another route.
	body := w.Body.String()
	for _, leaked := range []string{"an-access-token-nobody-should-keep", "a-refresh-token-nobody-should-keep", "id_token"} {
		if contains(body, leaked) {
			t.Errorf("the response carries %q; the point of redeeming the code here is that it does not", leaked)
		}
	}
}

// PKCE is what proves the code belongs to the browser that asked for it, and
// there is no client secret to fall back on. Sending the exchange without the
// verifier would be a silent downgrade.
func TestFederatedCallbackSendsThePKCEVerifier(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string { return idp.signIDToken(t, idp.goodClaims(federatedClientID)) }
	r, _ := oidcRouter(t, idp)

	if w := callback(t, r, goodCallbackBody()); w.Code != http.StatusOK {
		t.Fatalf("callback = %d: %s", w.Code, w.Body.String())
	}

	if got := idp.lastForm["code_verifier"]; got != "a-code-verifier-of-adequate-length-for-pkce" {
		t.Errorf("the code verifier was not sent to the token endpoint, got %q", got)
	}
	if got := idp.lastForm["grant_type"]; got != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", got)
	}
	if _, present := idp.lastForm["client_secret"]; present {
		t.Error("a client secret was sent; this is a public client and has none")
	}
}

// The nonce is the only thing tying the ID token to this particular sign-in.
// A provider will happily re-issue one that is valid in every other respect.
func TestFederatedCallbackRefusesAReplayedNonce(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string {
		claims := idp.goodClaims(federatedClientID)
		claims["nonce"] = "a-nonce-from-some-other-sign-in"
		return idp.signIDToken(t, claims)
	}
	r, _ := oidcRouter(t, idp)

	if w := callback(t, r, goodCallbackBody()); w.Code != http.StatusUnauthorized {
		t.Fatalf("callback with a mismatched nonce = %d, want 401: %s", w.Code, w.Body.String())
	}
}

// An ID token's audience is the client id. Accepting one minted for a different
// application is accepting a token the operator never authorised for CertPilot.
func TestFederatedCallbackRefusesAnotherApplicationsToken(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string {
		return idp.signIDToken(t, idp.goodClaims("some-other-application"))
	}
	r, _ := oidcRouter(t, idp)

	if w := callback(t, r, goodCallbackBody()); w.Code != http.StatusUnauthorized {
		t.Fatalf("callback with the wrong audience = %d, want 401: %s", w.Code, w.Body.String())
	}
}

func TestFederatedCallbackRefusesAnotherIssuersToken(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string {
		claims := idp.goodClaims(federatedClientID)
		claims["iss"] = "https://not-the-configured-provider.example"
		return idp.signIDToken(t, claims)
	}
	r, _ := oidcRouter(t, idp)

	if w := callback(t, r, goodCallbackBody()); w.Code != http.StatusUnauthorized {
		t.Fatalf("callback with the wrong issuer = %d, want 401: %s", w.Code, w.Body.String())
	}
}

// An unsigned token is the oldest JWT attack there is.
//
// Refused by the key lookup rather than by the algorithm pinning — jwt-go will
// only verify "none" against its explicit sentinel key, which nothing here
// returns. Kept because the guarantee matters regardless of which layer
// provides it, and noted so the next person does not read this as evidence for
// the pinning. The test below is the one that covers that.
func TestFederatedCallbackRefusesAnUnsignedToken(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, idp.goodClaims(federatedClientID))
		signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	r, _ := oidcRouter(t, idp)

	if w := callback(t, r, goodCallbackBody()); w.Code != http.StatusUnauthorized {
		t.Fatalf("callback with an unsigned token = %d, want 401: %s", w.Code, w.Body.String())
	}
}

// Algorithm pinning, and the one configuration where it is load-bearing.
//
// jwt_secret is a documented legacy option for HS256 verification, and an
// instance can have both it and a JWKS. Without pinning, an ID token signed
// HS256 with that shared secret verifies here — the key lookup hands the secret
// back quite happily — and a symmetric key held by anything that can mint an
// API token becomes a way to assert any federated identity at all.
func TestFederatedCallbackRefusesASymmetricallySignedIDToken(t *testing.T) {
	const legacySecret = "a-legacy-shared-secret-long-enough-to-be-real"

	idp := newFakeIDP(t)
	claims := idp.goodClaims(federatedClientID)
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := forged.SignedString([]byte(legacySecret))
	if err != nil {
		t.Fatal(err)
	}
	idp.idToken = func(string) string { return signed }

	st := store.NewMemoryStore()
	cfg := config.AuthConfig{
		Issuer:    idp.server.URL,
		ClientID:  federatedClientID,
		JWKSURL:   idp.server.URL + "/jwks",
		JWTSecret: legacySecret,
		RoleClaim: "certpilot_role",
	}
	auth, err := middleware.NewAuthenticator(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	engine.POST("/api/v1/auth/callback", NewSessionHandler(st, cfg, auth.WithUserDirectory(st)).Callback)

	if w := callback(t, engine, goodCallbackBody()); w.Code != http.StatusUnauthorized {
		t.Fatalf("an HS256-signed ID token = %d, want 401: %s", w.Code, w.Body.String())
	}
}

// The provider says who you are; CertPilot says what you may do. A suspended
// account must be refused here even though the provider still accepts it.
func TestFederatedCallbackRefusesASuspendedAccount(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string { return idp.signIDToken(t, idp.goodClaims(federatedClientID)) }
	r, st := oidcRouter(t, idp)

	// One successful sign-in to create the row, then suspend it.
	if w := callback(t, r, goodCallbackBody()); w.Code != http.StatusOK {
		t.Fatalf("first callback = %d: %s", w.Code, w.Body.String())
	}
	users, err := st.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, u := range users {
		if u.Subject == "00uFEDERATEDsubject1" {
			id = u.ID
		}
	}
	if id == "" {
		t.Fatal("the federated sign-in created no user row")
	}
	if _, err := st.SetUserStatus(context.Background(), id, store.UserStatusSuspended); err != nil {
		t.Fatal(err)
	}

	if w := callback(t, r, goodCallbackBody()); w.Code != http.StatusForbidden {
		t.Fatalf("callback for a suspended account = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// A spent or forged code must not produce a session, and the reason must not be
// echoed back — it tells somebody probing which half to fix.
func TestFederatedCallbackRefusesARejectedCode(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string { return idp.signIDToken(t, idp.goodClaims(federatedClientID)) }
	idp.refuseExchange = true
	r, _ := oidcRouter(t, idp)

	w := callback(t, r, goodCallbackBody())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("callback with a refused code = %d, want 401: %s", w.Code, w.Body.String())
	}
	if contains(w.Body.String(), "invalid_grant") {
		t.Error("the provider's own error was echoed to the caller")
	}
}

func TestFederatedCallbackRequiresEveryField(t *testing.T) {
	idp := newFakeIDP(t)
	idp.idToken = func(string) string { return idp.signIDToken(t, idp.goodClaims(federatedClientID)) }
	r, _ := oidcRouter(t, idp)

	for _, missing := range []string{"code", "code_verifier", "redirect_uri", "nonce"} {
		body := goodCallbackBody()
		delete(body, missing)
		if w := callback(t, r, body); w.Code != http.StatusBadRequest {
			t.Errorf("callback without %s = %d, want 400", missing, w.Code)
		}
	}
}

// An instance with only local accounts must not expose a federated sign-in
// path at all.
func TestFederatedCallbackIsAbsentWithoutAProvider(t *testing.T) {
	st := store.NewMemoryStore()
	cfg := config.AuthConfig{RoleClaim: "certpilot_role"}
	auth, err := middleware.NewAuthenticator(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	engine.POST("/api/v1/auth/callback", NewSessionHandler(st, cfg, auth.WithUserDirectory(st)).Callback)

	if w := callback(t, engine, goodCallbackBody()); w.Code != http.StatusNotFound {
		t.Fatalf("callback with no provider configured = %d, want 404: %s", w.Code, w.Body.String())
	}
}
