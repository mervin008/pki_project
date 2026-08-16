package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration is one SQL file from the migrations directory.
type Migration struct {
	Version  string // "001", taken from the filename prefix
	Name     string // full filename, for messages
	SQL      string
	Checksum string // sha256 of SQL, hex
}

// MigrationResult reports what a Migrate call did, so the caller can print
// something more useful than "ok".
type MigrationResult struct {
	Applied []string
	Skipped []string
	// Drifted names migrations already recorded as applied whose file has
	// since changed. Reported rather than reapplied — see Migrate.
	Drifted []string
}

// migrationLockID is an arbitrary constant used with pg_advisory_lock so that
// two cores starting at once do not both try to migrate. The value has no
// meaning beyond being unlikely to collide with another application's lock.
const migrationLockID int64 = 8021977463117

// LoadMigrations reads and orders the .sql files in dir.
//
// Ordering is lexicographic on the filename, which is why they are numbered
// with a fixed-width prefix. It is not "whatever the filesystem returns":
// 004 adds columns to a table 001 creates, and applying them out of order
// fails in a way that is tedious to unpick by hand.
func LoadMigrations(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading migrations from %s: %w", dir, err)
	}

	var migrations []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(body)
		migrations = append(migrations, Migration{
			Version:  versionOf(e.Name()),
			Name:     e.Name(),
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}

	if len(migrations) == 0 {
		return nil, fmt.Errorf("no .sql files found in %s", dir)
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Name < migrations[j].Name
	})
	return migrations, nil
}

// versionOf extracts the numeric prefix: "004_monitoring_queries.sql" -> "004".
// A file without one is keyed by its name minus the suffix, which still sorts
// and still records — an unnumbered migration is a mistake worth surviving, not
// worth crashing over.
func versionOf(filename string) string {
	if i := strings.IndexByte(filename, '_'); i > 0 {
		return filename[:i]
	}
	return strings.TrimSuffix(filename, ".sql")
}

// Migrate applies every migration in dir that this database has not recorded.
//
// It is deliberately a separate command rather than something NewPostgresStore
// does on startup. Migrating automatically on boot means a rolling deploy runs
// schema changes from however many replicas start first, against a database the
// older replicas are still reading — and it removes the operator's chance to
// look at the change before it lands on production data.
//
// Every migration in this repository is written to be idempotent (`if not
// exists`, `if exists`, guarded DO blocks). That is what makes the recording
// step safe to do after the fact: if the process dies between applying a file
// and recording it, the next run reapplies it harmlessly.
func Migrate(ctx context.Context, connStr, dir string) (*MigrationResult, error) {
	migrations, err := LoadMigrations(dir)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("connecting to the database: %w", err)
	}
	defer pool.Close()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring a connection: %w", err)
	}
	defer conn.Release()

	// Held for the duration and released when the session ends, including on a
	// crash. A second core blocks here rather than racing.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return nil, fmt.Errorf("taking the migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx),
			"SELECT pg_advisory_unlock($1)", migrationLockID)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS public.schema_migrations (
			version    text primary key,
			name       text not null,
			checksum   text not null,
			applied_at timestamptz not null default now()
		)`); err != nil {
		return nil, fmt.Errorf("creating schema_migrations: %w", err)
	}

	rows, err := conn.Query(ctx, "SELECT version, checksum FROM public.schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("reading applied migrations: %w", err)
	}
	applied := map[string]string{}
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return nil, err
		}
		applied[version] = checksum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := &MigrationResult{}
	for _, m := range migrations {
		if recorded, ok := applied[m.Version]; ok {
			// Reported, never reapplied. Editing a migration that has already
			// run somewhere means this database and that one have diverged,
			// and rerunning the edited file cannot reconcile them — only a new
			// migration can. Saying so is more useful than either silently
			// ignoring it or silently rerunning it.
			if recorded != m.Checksum {
				result.Drifted = append(result.Drifted, m.Name)
			}
			result.Skipped = append(result.Skipped, m.Name)
			continue
		}

		slog.Info("applying migration", "file", m.Name)

		// The simple protocol, explicitly: these files contain many statements
		// and their own BEGIN/COMMIT, neither of which the extended protocol
		// accepts. Postgres wraps an unbracketed multi-statement script in an
		// implicit transaction, so a file either lands whole or not at all.
		if _, err := conn.Conn().PgConn().Exec(ctx, m.SQL).ReadAll(); err != nil {
			return result, fmt.Errorf("applying %s: %w", m.Name, err)
		}

		if _, err := conn.Exec(ctx, `
			INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (version) DO UPDATE
			SET name = excluded.name, checksum = excluded.checksum, applied_at = excluded.applied_at`,
			m.Version, m.Name, m.Checksum, time.Now().UTC()); err != nil {
			return result, fmt.Errorf("recording %s (it did apply; rerun to record it): %w", m.Name, err)
		}

		result.Applied = append(result.Applied, m.Name)
	}

	return result, nil
}
