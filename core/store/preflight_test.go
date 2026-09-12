package store

import (
	"os"
	"strings"
	"testing"
)

// The RLS rule is the one this check turns on, and both ways of getting it
// wrong are bad in different ways. Too permissive and the core serves an empty
// dashboard that looks like a healthy estate; too strict and it refuses to
// start against a database it can read perfectly well.
//
// Verified live against PostgreSQL for the BYPASSRLS case, which is how the
// documented setup connects (the `postgres` role there has rolbypassrls). The
// non-owner cases are covered here rather than by creating a login role on a
// real project.
func TestRLSBlockedTables(t *testing.T) {
	tables := func(info tableInfo) map[string]tableInfo {
		m := map[string]tableInfo{}
		for _, name := range requiredTables {
			m[name] = info
		}
		return m
	}

	cases := []struct {
		name        string
		info        tableInfo
		bypassesRLS bool
		wantBlocked bool
	}{
		{
			name:        "owner of tables with RLS enabled but not forced reads everything",
			info:        tableInfo{rowSecurity: true, isOwner: true},
			wantBlocked: false,
		},
		{
			// How the documented setup connects: as the owner of the tables.
			name:        "BYPASSRLS reads everything even when RLS is forced",
			info:        tableInfo{rowSecurity: true, forceRowSecurity: true, isOwner: false},
			bypassesRLS: true,
			wantBlocked: false,
		},
		{
			// The failure this check exists for: a plausible-looking, entirely
			// empty dashboard.
			name:        "non-owner without BYPASSRLS is filtered",
			info:        tableInfo{rowSecurity: true, isOwner: false},
			wantBlocked: true,
		},
		{
			// FORCE applies RLS to the owner too, which is the trap in
			// "but I connected as the owner".
			name:        "owner is filtered when RLS is forced",
			info:        tableInfo{rowSecurity: true, forceRowSecurity: true, isOwner: true},
			wantBlocked: true,
		},
		{
			name:        "RLS disabled is never blocked, whoever connects",
			info:        tableInfo{rowSecurity: false, isOwner: false},
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked := rlsBlockedTables(tables(tc.info), tc.bypassesRLS)
			if tc.wantBlocked && len(blocked) == 0 {
				t.Error("expected the connection to be refused, but no table was reported blocked")
			}
			if !tc.wantBlocked && len(blocked) > 0 {
				t.Errorf("expected the connection to be allowed, but %v were reported blocked", blocked)
			}
		})
	}
}

// A table nobody has created yet is the migration check's business. Reporting
// it here as well would bury "run make migrate" under an RLS message that does
// not apply.
func TestRLSCheckIgnoresAbsentTables(t *testing.T) {
	if blocked := rlsBlockedTables(map[string]tableInfo{}, false); len(blocked) > 0 {
		t.Errorf("missing tables should not be reported as RLS-blocked, got %v", blocked)
	}
}

// PostgreSQL's inet type does not scan into a Go *string, and pgx fails the
// whole query rather than the offending row — so one audit entry recorded with
// a client IP took out the entire activity feed. Writing works either way,
// which is what made it invisible until the API read back what it had written.
//
// The fix is to select host(ip_address). This guards it, because the in-memory
// store cannot express the failure and nothing else here would notice a revert.
func TestInetColumnsAreReadThroughHost(t *testing.T) {
	source, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}

	// Only projections are the problem: writing an inet works either way. This
	// scans the text between each SELECT and its FROM rather than the whole
	// file, because an INSERT names the same columns and naming them there is
	// correct. The earlier version of this test looked for ", ip_address," in
	// the file at large and relied on every INSERT happening to end its column
	// list at ip_address — which stopped being true the moment one grew.
	for _, projection := range selectProjections(string(source)) {
		for _, column := range []string{"ip_address", "last_seen_ip"} {
			for _, field := range strings.Split(projection, ",") {
				if strings.TrimSpace(field) == column {
					t.Errorf("%s is selected directly; it is an inet column and must be read as host(%s)",
						column, column)
				}
			}
		}
	}
}

// selectProjections returns the text between each SELECT and the FROM that
// follows it. Case-sensitive on purpose: every query in postgres.go writes its
// keywords in capitals, and matching loosely would start pulling prose out of
// the comments that explain them.
func selectProjections(source string) []string {
	var out []string
	rest := source
	for {
		start := strings.Index(rest, "SELECT ")
		if start < 0 {
			return out
		}
		rest = rest[start+len("SELECT "):]
		end := strings.Index(rest, "FROM ")
		if end < 0 {
			// A SELECT with no FROM — pg_advisory_xact_lock, COUNT over a
			// literal — projects no columns and cannot contain the defect.
			return out
		}
		out = append(out, rest[:end])
		rest = rest[end:]
	}
}

// TestStoreTestsRunAgainstBothImplementations is the guard for the gap that
// produced this file's neighbours.
//
// discovery_test.go and cloud_test.go had always called NewMemoryStore()
// directly rather than going through forEachStore, so every assertion in them
// had only ever been made against the in-memory store. Running them against
// PostgreSQL for the first time found three defects in an afternoon: a writer
// passing an empty string over a column default and being refused by its CHECK,
// a unique constraint that was case-sensitive where the memory store was not,
// and an adopted cloud certificate reverting to unmanaged on the next sync.
//
// A test that only exercises the implementation with no constraints is a test
// that agrees with itself. This makes writing another one a failure rather than
// a discovery two years later.
func TestStoreTestsRunAgainstBothImplementations(t *testing.T) {
	// Files where a bare MemoryStore is correct, each for a stated reason.
	// Adding to this list should feel like a decision.
	allowed := map[string]string{
		// Tests of the in-memory implementation itself.
		"inmemory_test.go": "exercises the in-memory store specifically",
		// The harness that builds the implementations.
		"conformance_test.go":      "constructs both implementations",
		"postgres_harness_test.go": "constructs the PostgreSQL implementation",
		// A helper typed on *MemoryStore, which the interface cannot express.
		"agent_install_test.go": "uses a fixture helper typed on *MemoryStore",
		// Simulates tampering by writing to the store's backing slice, which is
		// the whole point and is not expressible through the interface. The
		// PostgreSQL half of the audit chain — the advisory lock under
		// concurrency, the round trip through timestamptz and text, tampering
		// done in SQL with the trigger dropped — lives in postgres_only_test.go.
		"audit_chain_test.go": "reaches into the store to simulate tampering",
		// This file, which contains the string it searches for.
		"preflight_test.go": "contains the literal it looks for",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, ok := allowed[name]; ok {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "NewMemoryStore()") {
			t.Errorf("%s builds a MemoryStore directly. Use forEachStore, so the assertions "+
				"are made against PostgreSQL too — an in-memory store has no CHECK constraints, "+
				"no foreign keys, and no uuid columns to refuse anything", name)
		}
	}
}
