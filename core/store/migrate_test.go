package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The repository's own migration files, which is the set that actually has to
// load and order correctly.
func repoMigrationsDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolving the migrations directory: %v", err)
	}
	return dir
}

func TestRepositoryMigrationsLoadInNumericOrder(t *testing.T) {
	migrations, err := LoadMigrations(repoMigrationsDir(t))
	if err != nil {
		t.Fatalf("loading the repository's migrations: %v", err)
	}

	// 004 adds columns to a table 001 creates, and 005 drops constraints 001
	// declares. Order is correctness here, not neatness.
	var got []string
	for _, m := range migrations {
		got = append(got, m.Version)
	}

	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("migrations are not in ascending order: %v", got)
		}
	}

	if got[0] != "001" {
		t.Errorf("first migration = %q, want 001; got the full order %v", got[0], got)
	}
}

func TestEveryMigrationHasContentAndAChecksum(t *testing.T) {
	migrations, err := LoadMigrations(repoMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	for _, m := range migrations {
		if m.SQL == "" {
			t.Errorf("%s is empty", m.Name)
		}
		if len(m.Checksum) != 64 {
			t.Errorf("%s has checksum %q, want 64 hex characters", m.Name, m.Checksum)
		}
		// A duplicate version would make one migration permanently shadow the
		// other: the first recorded wins and the second is skipped forever.
		if other, dup := seen[m.Version]; dup {
			t.Errorf("version %s is claimed by both %s and %s", m.Version, other, m.Name)
		}
		seen[m.Version] = m.Name
	}
}

func TestChecksumChangesWithContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "001_thing.sql")

	if err := os.WriteFile(path, []byte("select 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("select 2;"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := LoadMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}

	// This is what lets Migrate report an already-applied migration that has
	// since been edited, rather than skipping it silently and leaving two
	// databases quietly divergent.
	if first[0].Checksum == second[0].Checksum {
		t.Error("editing a migration did not change its checksum, so drift would go unreported")
	}
}

func TestLoadMigrationsRejectsAnEmptyDirectory(t *testing.T) {
	// Getting --migrations wrong must not read as "nothing to do". A silent
	// success there means the core starts against an unmigrated database.
	if _, err := LoadMigrations(t.TempDir()); err == nil {
		t.Error("an empty migrations directory was accepted; it must be an error")
	}

	if _, err := LoadMigrations(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a missing migrations directory was accepted; it must be an error")
	}
}

func TestVersionOf(t *testing.T) {
	cases := map[string]string{
		"001_initial_schema.sql":      "001",
		"005_identity_decoupling.sql": "005",
		"nonumber.sql":                "nonumber",
		"_leading.sql":                "_leading",
	}
	for filename, want := range cases {
		if got := versionOf(filename); got != want {
			t.Errorf("versionOf(%q) = %q, want %q", filename, got, want)
		}
	}
}

// The migrations the core needs on any deployment must not depend on Supabase.
// Only 001 is permitted to, and that exception is documented in the README and
// in docs/database.md rather than being discovered by an operator at deploy time.
func TestOnlyTheInitialMigrationDependsOnSupabase(t *testing.T) {
	migrations, err := LoadMigrations(repoMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range migrations {
		if m.Version == "001" {
			continue
		}
		for _, symbol := range []string{"auth.users", "auth.jwt()", "auth.uid()"} {
			if containsOutsideComments(m.SQL, symbol) {
				t.Errorf("%s references %s, so it will not apply to plain PostgreSQL", m.Name, symbol)
			}
		}
	}
}

// containsOutsideComments ignores `--` comment text, so a migration may explain
// why it avoids something without appearing to use it. 005 in particular talks
// about auth.users at length precisely because it is removing the dependency.
func containsOutsideComments(sql, needle string) bool {
	for _, line := range strings.Split(sql, "\n") {
		code, _, _ := strings.Cut(line, "--")
		if strings.Contains(code, needle) {
			return true
		}
	}
	return false
}
