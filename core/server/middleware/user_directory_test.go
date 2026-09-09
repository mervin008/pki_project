package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

// directoryAuth builds an authenticator backed by a real in-memory store.
func directoryAuth(t *testing.T, bootstrap ...string) (*Authenticator, store.Store) {
	t.Helper()
	st := store.NewMemoryStore()
	a := newTestAuth(t, config.AuthConfig{
		JWTSecret:       testSecret,
		Issuer:          "https://idp.example.com",
		BootstrapAdmins: bootstrap,
	})
	return a.WithUserDirectory(st), st
}

// claimsFor builds a token for one person, optionally asserting a role claim.
func claimsFor(subject, email, roleClaim string) *UserClaims {
	c := &UserClaims{
		Email: email,
		Name:  "Test Person",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    "https://idp.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if roleClaim != "" {
		c.AppMetadata = map[string]any{"certpilot_role": roleClaim}
	}
	return c
}

func roleFrom(t *testing.T, body []byte) string {
	t.Helper()
	var parsed map[string]string
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return parsed["role"]
}

// TestTheStoredRoleBeatsTheTokensClaim is the property the users table exists
// for. Without it, anyone able to influence their own token's claims — or an
// administrator of the identity provider acting outside CertPilot — decides
// what they may do to the CA hierarchy.
func TestTheStoredRoleBeatsTheTokensClaim(t *testing.T) {
	a, _ := directoryAuth(t)

	// The token asserts admin. The directory has never seen this subject, so
	// the role it gets is the default.
	token := signHS256(t, claimsFor("00u9vme99nxudvxZA0h7", "stranger@example.com", "admin"))
	w := runRequest(a, "Bearer "+token)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := roleFrom(t, w.Body.Bytes()); got != store.RoleViewer {
		t.Fatalf("role = %q, want %q — a claim in the token decided the role", got, store.RoleViewer)
	}
}

// TestAnOktaSubjectIsAccepted guards the shape that migration 028 was written
// for. Okta, Google and Auth0 subjects are not uuids, and the column they land
// in refused them until that migration widened it.
func TestAnOktaSubjectIsAccepted(t *testing.T) {
	for _, subject := range []string{
		"00u9vme99nxudvxZA0h7",           // Okta
		"110169484474386276334",          // Google
		"auth0|507f1f77bcf86cd799439011", // Auth0
	} {
		a, st := directoryAuth(t)
		w := runRequest(a, "Bearer "+signHS256(t, claimsFor(subject, "person@example.com", "")))
		if w.Code != http.StatusOK {
			t.Fatalf("subject %q: status = %d, want 200: %s", subject, w.Code, w.Body.String())
		}
		users, err := st.ListUsers(context.Background())
		if err != nil || len(users) != 1 {
			t.Fatalf("subject %q: users = %d (err %v), want 1", subject, len(users), err)
		}
		if users[0].Subject != subject {
			t.Fatalf("stored subject = %q, want %q", users[0].Subject, subject)
		}
	}
}

// TestBootstrapGrantsAdminOnFirstSignInOnly is the half of the bootstrap rule
// that is easy to get wrong. Matching on every request would mean the setting
// silently restores an admin somebody had deliberately demoted.
func TestBootstrapGrantsAdminOnFirstSignInOnly(t *testing.T) {
	a, st := directoryAuth(t, "Founder@Example.com")

	// Case-insensitive, as email comparison must be.
	token := signHS256(t, claimsFor("sub-founder", "founder@example.com", ""))
	if got := roleFrom(t, runRequest(a, "Bearer "+token).Body.Bytes()); got != store.RoleAdmin {
		t.Fatalf("first sign-in role = %q, want admin", got)
	}

	users, _ := st.ListUsers(context.Background())
	if len(users) != 1 {
		t.Fatalf("users = %d, want 1", len(users))
	}
	if users[0].RoleSource != store.RoleSourceBootstrap {
		t.Fatalf("role_source = %q, want BOOTSTRAP", users[0].RoleSource)
	}

	// Demoted by an administrator, then signs in again.
	if _, err := st.SetUserRole(context.Background(), users[0].ID, store.RoleViewer); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	if got := roleFrom(t, runRequest(a, "Bearer "+token).Body.Bytes()); got != store.RoleViewer {
		t.Fatalf("role after demotion = %q, want viewer — the bootstrap list re-promoted a demoted account", got)
	}
}

// TestASuspendedAccountIsRefused. The identity provider still accepts the
// person, so sign-in succeeds; CertPilot has to be the one saying no.
func TestASuspendedAccountIsRefused(t *testing.T) {
	a, st := directoryAuth(t)
	token := signHS256(t, claimsFor("sub-leaver", "leaver@example.com", ""))

	runRequest(a, "Bearer "+token) // creates the row
	users, _ := st.ListUsers(context.Background())
	if _, err := st.SetUserStatus(context.Background(), users[0].ID, store.UserStatusSuspended); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}

	w := runRequest(a, "Bearer "+token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a suspended account: %s", w.Code, w.Body.String())
	}
}

// TestSubjectsAreScopedToTheirIssuer. A subject is unique only within the
// issuer that minted it, so the same string from two providers is two people.
func TestSubjectsAreScopedToTheirIssuer(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	first, err := st.ResolveUser(ctx, store.UserIdentity{
		Issuer: "https://one.example.com", Subject: "12345", Email: "a@example.com",
	}, nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := st.ResolveUser(ctx, store.UserIdentity{
		Issuer: "https://two.example.com", Subject: "12345", Email: "b@example.com",
	}, nil)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if first.ID == second.ID {
		t.Fatal("the same subject from two issuers resolved to one user — one provider's " +
			"subject would inherit another's role")
	}
}

// TestResolvingRefusesAnEmptyIdentity. An empty issuer would collide every
// provider's subjects into one namespace.
func TestResolvingRefusesAnEmptyIdentity(t *testing.T) {
	st := store.NewMemoryStore()
	for _, id := range []store.UserIdentity{
		{Issuer: "", Subject: "abc"},
		{Issuer: "https://idp.example.com", Subject: ""},
	} {
		if _, err := st.ResolveUser(context.Background(), id, nil); err == nil {
			t.Fatalf("ResolveUser(%+v) succeeded, want an error", id)
		}
	}
}

// TestNoDirectoryFallsBackToTheClaim keeps the previous behaviour available for
// a deployment with no store wired in, which is how the other tests here run.
func TestNoDirectoryFallsBackToTheClaim(t *testing.T) {
	a := newTestAuth(t, config.AuthConfig{JWTSecret: testSecret})
	w := runRequest(a, "Bearer "+signHS256(t, claimsFor("sub", "x@example.com", "operator")))
	if got := roleFrom(t, w.Body.Bytes()); got != store.RoleOperator {
		t.Fatalf("role = %q, want operator from the claim", got)
	}
}
