package store

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The PostgreSQL side of the conformance suite.
//
// A database per test, created and dropped, migrated from the repository's own
// migration files. That last part is not a detail: the value of this harness is
// that the schema under test is the schema that ships, applied by the migrator
// that ships, in the order it ships. A hand-maintained `schema_test.sql` would
// drift from `migrations/` and the suite would go on passing while the two
// diverged — which is precisely the failure mode this whole exercise exists to
// end.
//
// CERTPILOT_TEST_DB_URL must point at a server the suite may create and drop
// databases on. Pointing it at anything with data in it is a mistake this
// harness cannot prevent, so it refuses the obvious ones.

// freshPostgres creates a database, migrates it, and drops it when the test
// finishes.
func freshPostgres(t *testing.T, adminURL string) Store {
	t.Helper()

	refuseIfProduction(t, adminURL)

	ctx := context.Background()
	name := fmt.Sprintf("certpilot_test_%d_%d", time.Now().UnixNano()%1e9, rand.Intn(1<<16))

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Skipf("cannot reach the test database server: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("could not create a test database: %v", err)
	}
	_ = admin.Close(ctx)

	t.Cleanup(func() {
		admin, err := pgx.Connect(context.Background(), adminURL)
		if err != nil {
			t.Logf("could not drop %s: %v", name, err)
			return
		}
		defer func() { _ = admin.Close(context.Background()) }()
		// FORCE, because a pool that has not finished closing holds a
		// connection and DROP DATABASE refuses while one exists — which turns
		// a passing test into a litter of databases nobody cleans up.
		if _, err := admin.Exec(context.Background(),
			"DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("could not drop %s: %v", name, err)
		}
	})

	// Straight from an empty database to the migrations, with nothing applied
	// first. That is the claim being tested: the schema this project ships needs
	// nothing a stock PostgreSQL server does not already have. The harness used
	// to apply a prelude of borrowed platform objects here, which meant the
	// suite proved the migrations worked on a database no deployment had.
	url := replaceDatabase(adminURL, name)

	result, err := Migrate(ctx, url, repoPath(t, "migrations"))
	if err != nil {
		t.Fatalf("the migrations this project ships did not apply to a plain PostgreSQL database: %v", err)
	}
	t.Logf("migrated %s: %d migration(s) applied", name, len(result.Applied))

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("could not connect to the migrated test database: %v", err)
	}
	t.Cleanup(pool.Close)

	store, err := NewPostgresStore(ctx, url)
	if err != nil {
		t.Fatalf("could not open the store: %v", err)
	}
	pool.Close()
	return store
}

// refuseIfProduction is a guard, not a security control.
//
// This harness creates and drops databases. Pointed at the wrong server it
// destroys things, and the commonest way to point it at the wrong server is to
// paste the URL that was already in the shell. Refusing the two that matter
// costs nothing and has caught worse.
func refuseIfProduction(t *testing.T, url string) {
	t.Helper()
	lower := strings.ToLower(url)
	for _, marker := range []string{"supabase.co", "supabase.com", "rds.amazonaws.com", "neon.tech"} {
		if strings.Contains(lower, marker) {
			t.Fatalf(
				"CERTPILOT_TEST_DB_URL points at %s. This suite creates and drops databases; point it at a throwaway server",
				marker)
		}
	}
}

// replaceDatabase swaps the database name in a connection URL.
func replaceDatabase(url, name string) string {
	base, query, hasQuery := strings.Cut(url, "?")
	slash := strings.LastIndex(base, "/")
	if slash < 0 {
		base += "/" + name
	} else {
		base = base[:slash+1] + name
	}
	if hasQuery {
		return base + "?" + query
	}
	return base
}

// repoPath resolves a path relative to the repository root.
//
// Tests run with the package directory as the working directory, and the
// migrations are two levels up. Walked rather than hardcoded so that moving the
// package produces a clear failure instead of a mysterious one.
func repoPath(t *testing.T, parts ...string) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return filepath.Join(append([]string{dir}, parts...)...)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root (no go.work above the test's working directory)")
	return ""
}
