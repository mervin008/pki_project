package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// The defects the in-memory store is structurally incapable of having.
//
// Everything in conformance_test.go runs against both implementations, because
// the interesting failures there were the two disagreeing. These two classes
// are different: they are properties of PostgreSQL itself, and the in-memory
// store cannot exhibit them even in principle.
//
//	D. A bound parameter PostgreSQL types differently from the driver.
//	E. A NULL column scanned into a non-pointer Go field.
//
// Both have shipped. Both were found by a person running the thing.

func postgresOnly(t *testing.T) *PostgresStore {
	t.Helper()
	url := os.Getenv("CERTPILOT_TEST_DB_URL")
	if url == "" {
		t.Skip("set CERTPILOT_TEST_DB_URL to exercise PostgreSQL")
	}
	store, ok := freshPostgres(t, url).(*PostgresStore)
	if !ok {
		t.Fatal("expected a PostgresStore")
	}
	return store
}

// TestQueriesWithBoundIntervalsRun — class D.
//
// Two of these have shipped. The CA expiry window was
// `not_after <= now() + ($1 || ' days')`, which leaves both sides of `||`
// untyped: PostgreSQL resolved it as `text || text` and reported the parameter
// as text while the driver held an int. Migration 018's staleness sweep was
// `$1 - <interval>`, where an untyped `$1` is inferred as an *interval* rather
// than a timestamp — and the identical predicate with a literal `now()` worked,
// which is why it survived to runtime.
//
// Neither is expressible in Go. There is no inference to get wrong, so the
// in-memory store runs the same logic correctly for ever while the database
// refuses the query. The only test that finds this class is one that runs the
// query.
func TestQueriesWithBoundIntervalsRun(t *testing.T) {
	store := postgresOnly(t)
	ctx := context.Background()

	t.Run("the CA expiry window", func(t *testing.T) {
		for _, days := range []int{1, 30, 365} {
			if _, err := store.ListCAAuthorities(ctx, CAFilter{ExpiringWithinDays: days}); err != nil {
				t.Fatalf("the CA expiry window with %d days did not run: %v", days, err)
			}
		}
	})

	t.Run("the agent staleness sweep", func(t *testing.T) {
		// The predicate that was inferred as an interval. Bound `now`, not a
		// literal — binding it is the whole of what broke.
		if _, err := store.GetStaleAgents(ctx, time.Now(), 50); err != nil {
			t.Fatalf("the staleness sweep did not run: %v", err)
		}
	})

	t.Run("the renewal sweep", func(t *testing.T) {
		if _, err := store.GetCertificatesDueForRenewal(ctx, 30); err != nil {
			t.Fatalf("the renewal sweep did not run: %v", err)
		}
	})
}

// TestOneNullColumnDoesNotBlankAWholeList — class E.
//
// Several nullable columns scan into non-pointer Go fields, and pgx fails the
// *whole query* rather than the row. One hand-inserted certificate with a null
// `key_size` would have blanked the certificate list for everybody — a single
// bad row taking out a page, which is a failure mode no amount of testing
// against a store that has no NULL will produce.
//
// Inserted with raw SQL on purpose. Going through CreateCertificate would write
// whatever the Go zero value is and prove nothing; the row that causes this
// arrives from a bulk import, a migration, or somebody's psql session.
func TestOneNullColumnDoesNotBlankAWholeList(t *testing.T) {
	store := postgresOnly(t)
	ctx := context.Background()

	healthy := sampleCertificate("healthy-neighbour")
	if err := store.CreateCertificate(ctx, healthy); err != nil {
		t.Fatal(err)
	}

	// Everything nullable, left null. This is the row somebody's import script
	// writes.
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO public.certificates (fingerprint_sha256, common_name, status)
		VALUES ('null-heavy-row', 'imported.example.com', 'ISSUED')`); err != nil {
		t.Fatalf("could not insert a sparse row: %v", err)
	}

	certs, total, err := store.ListCertificates(ctx, CertificateFilter{Limit: 100})
	if err != nil {
		t.Fatalf("one row with null columns took out the whole certificate list: %v", err)
	}
	if total < 2 {
		t.Fatalf("expected both certificates, got %d", total)
	}

	var found bool
	for _, cert := range certs {
		if cert.CommonName == "imported.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("the sparse row is missing from the list; it should be readable, not skipped")
	}

	// And it is readable on its own, which is what a detail page does.
	sparse, err := store.GetCertificateByFingerprint(ctx, "null-heavy-row")
	if err != nil {
		t.Fatalf("the sparse row could not be read individually: %v", err)
	}
	if sparse == nil {
		t.Fatal("the sparse row was not found by fingerprint")
	}
}

// TestTheMigrationsApplyTwice.
//
// Migration 001 had to be made rerunnable because `create policy` has no
// `if not exists`: applying the file to a database that already had the schema
// failed on the first policy and rolled everything back. Every migration since
// has been written to be idempotent, and nothing has ever checked that they
// still are.
//
// The migrator's own checksumming means a second `Migrate` skips them, so this
// re-applies the files directly — which is what happens when somebody runs the
// SQL by hand against a database that is already migrated, and it is exactly
// the situation migration 001's note was written about.
func TestTheMigrationsApplyTwice(t *testing.T) {
	store := postgresOnly(t)
	ctx := context.Background()

	dir := repoPath(t, "migrations")
	migrations, err := LoadMigrations(dir)
	if err != nil {
		t.Fatalf("could not read the migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations were found")
	}

	for _, migration := range migrations {
		if _, err := store.pool.Exec(ctx, migration.SQL); err != nil {
			t.Errorf("%s is not idempotent; applying it to a migrated database failed: %v",
				migration.Name, err)
		}
	}
}
