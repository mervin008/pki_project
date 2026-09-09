package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestEverySubjectShapeARealProviderIssuesIsAccepted is the test migration 028
// was written for, and the one whose absence let the defect ship.
//
// The actor columns were uuid on the reasoning that OIDC subjects fit one.
// Three of the four providers CertPilot documents do not issue uuids, so the
// first certificate issued by anyone signed in through Okta, Google Workspace
// or Auth0 aborted on the insert. Nothing caught it because development runs
// anonymously and the anonymous subject is a hardcoded uuid — a fixture that
// agreed with the bug.
//
// Store defect class (D): a parameter PostgreSQL types differently than
// expected.
func TestEverySubjectShapeARealProviderIssuesIsAccepted(t *testing.T) {
	subjects := map[string]string{
		"okta":     "00u9vme99nxudvxZA0h7",
		"google":   "110169484474386276334",
		"auth0":    "auth0|507f1f77bcf86cd799439011",
		"keycloak": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"entra":    "AAAAAAAAAAAAAAAAAAAAAJb3Zlcmxvbmc",
		// The specification's actual limit: 255 ASCII characters.
		"maximum": strings.Repeat("s", 255),
	}

	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		for provider, subject := range subjects {
			u, err := s.ResolveUser(ctx, UserIdentity{
				Issuer:  "https://idp.example.com",
				Subject: subject,
				Email:   provider + "@example.com",
			}, nil)
			if err != nil {
				t.Fatalf("%s subject %q was refused: %v", provider, subject, err)
			}
			if u.Subject != subject {
				t.Fatalf("%s: stored subject = %q, want %q", provider, u.Subject, subject)
			}
		}
	})
}

// TestEveryRoleTheGoCodeCanWriteIsAccepted is class (A): a Go constant the
// CHECK constraint refuses. The three definitions that must agree are these
// constants, middleware.Role*, and the CHECK in migration 028.
func TestEveryRoleTheGoCodeCanWriteIsAccepted(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		u, err := s.ResolveUser(ctx, UserIdentity{
			Issuer: "https://idp.example.com", Subject: "role-probe", Email: "r@example.com",
		}, nil)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}

		for _, role := range []string{RoleViewer, RoleAuditor, RoleOperator, RoleAdmin} {
			updated, err := s.SetUserRole(ctx, u.ID, role)
			if err != nil {
				t.Fatalf("role %q was refused by the schema: %v", role, err)
			}
			if updated.Role != role {
				t.Fatalf("role = %q, want %q", updated.Role, role)
			}
			if updated.RoleSource != RoleSourceAssigned {
				t.Fatalf("role_source = %q, want ASSIGNED", updated.RoleSource)
			}
		}

		for _, status := range []string{UserStatusActive, UserStatusSuspended} {
			if _, err := s.SetUserStatus(ctx, u.ID, status); err != nil {
				t.Fatalf("status %q was refused by the schema: %v", status, err)
			}
		}
	})
}

// TestResolvingIsIdempotent. This runs on every authenticated request; a second
// call must return the same user rather than a second row.
func TestResolvingIsIdempotent(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		id := UserIdentity{Issuer: "https://idp.example.com", Subject: "same", Email: "same@example.com"}

		first, err := s.ResolveUser(ctx, id, nil)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		second, err := s.ResolveUser(ctx, id, nil)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if first.ID != second.ID {
			t.Fatalf("two rows for one identity: %s then %s", first.ID, second.ID)
		}

		users, err := s.ListUsers(ctx)
		if err != nil || len(users) != 1 {
			t.Fatalf("users = %d (err %v), want 1", len(users), err)
		}
	})
}

// TestSigningInNeverChangesARole. The property the whole design rests on: if a
// sign-in could write a role, the bootstrap list would re-promote anyone who
// had been demoted, every time they logged in.
func TestSigningInNeverChangesARole(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		id := UserIdentity{Issuer: "https://idp.example.com", Subject: "founder", Email: "founder@example.com"}
		bootstrap := []string{"founder@example.com"}

		first, err := s.ResolveUser(ctx, id, bootstrap)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		if first.Role != RoleAdmin || first.RoleSource != RoleSourceBootstrap {
			t.Fatalf("first sign-in = %s/%s, want admin/BOOTSTRAP", first.Role, first.RoleSource)
		}

		if _, err := s.SetUserRole(ctx, first.ID, RoleViewer); err != nil {
			t.Fatalf("demote: %v", err)
		}

		again, err := s.ResolveUser(ctx, id, bootstrap)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if again.Role != RoleViewer {
			t.Fatalf("role after signing in again = %q, want viewer — the bootstrap list "+
				"re-promoted an account somebody had deliberately demoted", again.Role)
		}
	})
}

// TestProviderDetailsRefreshButNeverBlank. Class (C): empty string versus NULL.
// A provider that omits the email scope on one request must not erase what an
// earlier request recorded.
func TestProviderDetailsRefreshButNeverBlank(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		base := UserIdentity{Issuer: "https://idp.example.com", Subject: "detail"}

		withDetails := base
		withDetails.Email = "person@example.com"
		withDetails.DisplayName = "A Person"
		if _, err := s.ResolveUser(ctx, withDetails, nil); err != nil {
			t.Fatalf("first: %v", err)
		}

		// Same person, a token carrying neither claim.
		after, err := s.ResolveUser(ctx, base, nil)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if after.Email != "person@example.com" || after.DisplayName != "A Person" {
			t.Fatalf("details were erased by a token that simply did not carry them: %+v", after)
		}

		// A genuine change is persisted.
		changed := base
		changed.Email = "renamed@example.com"
		updated, err := s.ResolveUser(ctx, changed, nil)
		if err != nil {
			t.Fatalf("third: %v", err)
		}
		if updated.Email != "renamed@example.com" {
			t.Fatalf("email = %q, want the updated address", updated.Email)
		}
	})
}

// TestTouchRecordsLastSeen. Written through a guard so that a wall display does
// not produce a row version per request; the first touch must still land.
func TestTouchRecordsLastSeen(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		u, err := s.ResolveUser(ctx, UserIdentity{
			Issuer: "https://idp.example.com", Subject: "seen", Email: "seen@example.com",
		}, nil)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}

		later := time.Now().Add(2 * time.Hour)
		if err := s.TouchUser(ctx, u.ID, later); err != nil {
			t.Fatalf("touch: %v", err)
		}

		reread, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if reread.LastSeenAt == nil || reread.LastSeenAt.Before(later.Add(-time.Minute)) {
			t.Fatalf("last_seen_at = %v, want about %v", reread.LastSeenAt, later)
		}
	})
}

// TestGetUserOnAMissingIdReturnsNothing, rather than an error the caller has to
// distinguish from a real failure.
func TestGetUserOnAMissingIdReturnsNothing(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		u, err := s.GetUser(context.Background(), "8f14e45f-ceea-467a-9575-9f0e1a2b3c4d")
		if err != nil {
			t.Fatalf("GetUser on a missing id errored: %v", err)
		}
		if u != nil {
			t.Fatalf("GetUser on a missing id returned %+v, want nil", u)
		}
	})
}
