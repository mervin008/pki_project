package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

func nowPlusAnHour() time.Time { return time.Now().Add(time.Hour) }

// adminID returns the id of the account the test harness runs as.
func adminID(t *testing.T, st store.Store) string {
	t.Helper()
	users, err := st.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range users {
		if u.Role == store.RoleAdmin {
			return u.ID
		}
	}
	t.Fatal("no administrator in the store")
	return ""
}

// TestTheLastAdminCannotBeDemoted is the guard that makes this screen safe to
// use. Demoting the only administrator locks everybody out of the CA hierarchy,
// and the only way back is a SQL update — which is the situation this screen
// exists to remove.
func TestTheLastAdminCannotBeDemoted(t *testing.T) {
	r, st := realRouter(t)

	// One request establishes the administrator the harness signs in as.
	do(r, http.MethodGet, "/api/v1/users", nil, nil)
	id := adminID(t, st)

	for _, body := range []map[string]any{
		{"role": "viewer"},
		{"status": "SUSPENDED"},
	} {
		w := do(r, http.MethodPatch, "/api/v1/users/"+id, body, nil)
		if w.Code != http.StatusConflict {
			t.Fatalf("PATCH %v = %d, want 409 — the only administrator was removed: %s",
				body, w.Code, w.Body.String())
		}
	}

	after, err := st.GetUser(context.Background(), id)
	if err != nil || after.Role != store.RoleAdmin || !after.IsActive() {
		t.Fatalf("the administrator changed anyway: %+v (err %v)", after, err)
	}
}

// TestAnAdminCanBeDemotedOnceAnotherExists — the guard must not be a
// permanent one, or an administrator can never be replaced.
func TestAnAdminCanBeDemotedOnceAnotherExists(t *testing.T) {
	r, st := realRouter(t)
	do(r, http.MethodGet, "/api/v1/users", nil, nil)
	first := adminID(t, st)

	w := do(r, http.MethodPost, "/api/v1/users", map[string]any{
		"email": "second@example.com", "role": "admin",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create second admin = %d: %s", w.Code, w.Body.String())
	}

	if w := do(r, http.MethodPatch, "/api/v1/users/"+first, map[string]any{"role": "viewer"}, nil); w.Code != http.StatusOK {
		t.Fatalf("demote with a second admin present = %d: %s", w.Code, w.Body.String())
	}
}

// TestACreatedAccountGetsAPasswordShownOnce.
func TestACreatedAccountGetsAPasswordShownOnce(t *testing.T) {
	r, _ := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/users", map[string]any{
		"email": "newcomer@example.com", "role": "operator",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		InitialPassword string `json:"initial_password"`
		User            struct {
			Role               string `json:"role"`
			MustChangePassword bool   `json:"must_change_password"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.InitialPassword) < 12 {
		t.Fatalf("initial password = %q, want something long enough to be one", body.InitialPassword)
	}
	if body.User.Role != "operator" {
		t.Fatalf("role = %q, want operator", body.User.Role)
	}
	if !body.User.MustChangePassword {
		t.Fatal("must_change_password is false — somebody other than the account holder knows this one")
	}

	// Reading the account back must never disclose it again.
	list := do(r, http.MethodGet, "/api/v1/users", nil, nil)
	if contains(list.Body.String(), body.InitialPassword) {
		t.Fatal("the account list disclosed the initial password")
	}
}

// TestASecondAccountForOneAddressIsRefused. Two rows for one person makes
// "who did this" ambiguous in the audit log, which is the one place it must not
// be.
func TestASecondAccountForOneAddressIsRefused(t *testing.T) {
	r, _ := realRouter(t)

	first := do(r, http.MethodPost, "/api/v1/users",
		map[string]any{"email": "twice@example.com", "role": "viewer"}, nil)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create = %d: %s", first.Code, first.Body.String())
	}

	second := do(r, http.MethodPost, "/api/v1/users",
		map[string]any{"email": "TWICE@example.com", "role": "admin"}, nil)
	if second.Code != http.StatusConflict {
		t.Fatalf("second create = %d, want 409 — a duplicate account was made, and the "+
			"address differed only in case: %s", second.Code, second.Body.String())
	}
}

// TestSuspendingEndsSessions. Suspension that leaves a session alive means
// nothing until it expires, which on a console left open is however long
// somebody leaves it open.
func TestSuspendingEndsSessions(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	created := do(r, http.MethodPost, "/api/v1/users",
		map[string]any{"email": "leaver@example.com", "role": "operator"}, nil)
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &body)

	if _, err := st.CreateSession(ctx, body.User.ID, "hash-for-a-live-session",
		nowPlusAnHour(), "test", "127.0.0.1"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if w := do(r, http.MethodPatch, "/api/v1/users/"+body.User.ID,
		map[string]any{"status": "SUSPENDED"}, nil); w.Code != http.StatusOK {
		t.Fatalf("suspend = %d: %s", w.Code, w.Body.String())
	}

	sess, _, err := st.SessionByHash(ctx, "hash-for-a-live-session")
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	if sess != nil && sess.RevokedAt == nil {
		t.Fatal("the suspended account still holds a live session")
	}
}

// TestAnInvalidRoleIsRefusedBeforeTheDatabaseSeesIt. Store defect class (A):
// a value the CHECK constraint would refuse should fail with a message that
// names the acceptable ones.
func TestAnInvalidRoleIsRefusedBeforeTheDatabaseSeesIt(t *testing.T) {
	r, _ := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/users",
		map[string]any{"email": "wrong@example.com", "role": "superuser"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !contains(w.Body.String(), "operator") {
		t.Fatalf("the error does not list the roles that would work: %s", w.Body.String())
	}
}

func contains(haystack, needle string) bool {
	return needle != "" && len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
