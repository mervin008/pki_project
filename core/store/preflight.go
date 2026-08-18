package store

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requiredTables are the tables the core reads or writes on an ordinary
// request. Tables belonging to features that are not wired up yet
// (endpoint_tls_posture) are deliberately absent: refusing to start over a
// table nothing queries would be a false alarm.
//
// The discovery tables are here because they are now written on every scan, and
// because of how they fail without their columns: a scan would run, reach out
// across the network, and lose everything it found. An empty results list is
// the same shape as a clean estate.
var requiredTables = []string{
	"audit_logs",
	"ca_accounts",
	"ca_authorities",
	"certificates",
	"cloud_certificates",
	"cloud_connections",
	"deployment_targets",
	"ct_certificates",
	"ct_monitors",
	"discovery_results",
	"discovery_scans",
	"display_tokens",
	"notification_channels",
	"policies",
	"renewal_jobs",
}

// Preflight verifies that the connected database can actually serve the core,
// and refuses to continue when it cannot.
//
// The reason this exists rather than letting the first query fail:
//
// PostgreSQL row-level security does not reject a SELECT it disallows. It
// filters it, and returns zero rows. A core connected as a role the RLS
// policies do not admit therefore starts cleanly, answers every request, and
// reports an estate containing no certificates, no CAs, and nothing expiring —
// which on a wall display is indistinguishable from an organisation whose PKI
// is in perfect health. This is the precise failure this product exists to
// prevent, arriving through its own database connection.
//
// The same reasoning covers a database that has never been migrated: an empty
// dashboard is a plausible-looking dashboard, so "no tables" has to be an error
// at startup rather than a mystery at 2am.
func Preflight(ctx context.Context, pool *pgxpool.Pool) error {
	present, err := existingTables(ctx, pool)
	if err != nil {
		return err
	}

	var missing []string
	for _, t := range requiredTables {
		if _, ok := present[t]; !ok {
			missing = append(missing, t)
		}
	}
	if len(missing) == len(requiredTables) {
		return fmt.Errorf("the database has none of CertPilot's tables; apply the schema first: make migrate")
	}
	if len(missing) > 0 {
		return fmt.Errorf("the database schema is incomplete, missing %s; apply the outstanding migrations: make migrate",
			strings.Join(missing, ", "))
	}

	bypasses, err := roleBypassesRLS(ctx, pool)
	if err != nil {
		return err
	}
	if blocked := rlsBlockedTables(present, bypasses); len(blocked) > 0 {
		return fmt.Errorf(
			"row-level security would silently hide rows in %s from this connection, "+
				"so the dashboard would show an empty, healthy-looking estate. "+
				"Connect as the role that owns these tables (on Supabase that is `postgres`), "+
				"or grant the current role BYPASSRLS",
			strings.Join(blocked, ", "))
	}

	// Not fatal. A stale schema mostly degrades a feature rather than lying
	// about the estate, and refusing to start would take the monitoring offline
	// to fix something less serious than being offline.
	warnOnStaleSchema(ctx, pool)
	return nil
}

// rlsBlockedTables names the required tables whose rows row-level security
// would filter out for the connecting role.
//
// A role reads a table's rows in spite of RLS only if it has BYPASSRLS, or it
// owns the table (directly or through a role it is a member of) and the table
// is not set to FORCE. Anything else is filtered — silently, and to nothing.
//
// Split out from Preflight so this decision can be tested without a database.
// It is the rule the whole check turns on, and getting it inverted would be
// worse than not having the check: the core would refuse to start against a
// database it could read perfectly well.
func rlsBlockedTables(present map[string]tableInfo, bypassesRLS bool) []string {
	if bypassesRLS {
		return nil
	}
	var blocked []string
	for _, t := range requiredTables {
		info, ok := present[t]
		if !ok {
			continue // absence is the caller's separate, earlier check
		}
		if info.rowSecurity && (!info.isOwner || info.forceRowSecurity) {
			blocked = append(blocked, t)
		}
	}
	return blocked
}

type tableInfo struct {
	rowSecurity      bool
	forceRowSecurity bool
	isOwner          bool
}

func existingTables(ctx context.Context, pool *pgxpool.Pool) (map[string]tableInfo, error) {
	rows, err := pool.Query(ctx, `
		SELECT c.relname,
		       c.relrowsecurity,
		       c.relforcerowsecurity,
		       pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE')
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'r'`)
	if err != nil {
		return nil, fmt.Errorf("inspecting the database schema: %w", err)
	}
	defer rows.Close()

	present := map[string]tableInfo{}
	for rows.Next() {
		var name string
		var info tableInfo
		if err := rows.Scan(&name, &info.rowSecurity, &info.forceRowSecurity, &info.isOwner); err != nil {
			return nil, err
		}
		present[name] = info
	}
	return present, rows.Err()
}

func roleBypassesRLS(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var bypasses bool
	err := pool.QueryRow(ctx, `
		SELECT coalesce(bool_or(r.rolsuper OR r.rolbypassrls), false)
		FROM pg_catalog.pg_roles r
		WHERE pg_catalog.pg_has_role(current_user, r.oid, 'USAGE')`).Scan(&bypasses)
	if err != nil {
		return false, fmt.Errorf("checking row-level security for the current role: %w", err)
	}
	return bypasses, nil
}

// warnOnStaleSchema names the specific things a partially-migrated database
// will get wrong, rather than reporting a version number the operator then has
// to look up.
func warnOnStaleSchema(ctx context.Context, pool *pgxpool.Pool) {
	checks := []struct {
		query       string
		consequence string
	}{
		{
			// Migration 004.
			query: `SELECT NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'notification_channels'
				  AND column_name = 'severity_threshold')`,
			consequence: "notification_channels has no severity_threshold column (migration 004); alert routing will fail",
		},
		{
			// Migration 004.
			query: `SELECT NOT EXISTS (
				SELECT 1 FROM pg_catalog.pg_indexes
				WHERE schemaname = 'public' AND indexname = 'idx_audit_logs_action_created')`,
			consequence: "the audit log has no index on action (migration 004); filtering activity will scan the whole table",
		},
		{
			// Migration 007.
			query: `SELECT NOT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'discovery_results'
				  AND column_name = 'management_state')`,
			consequence: "discovery_results has no management_state column (migration 007); scans will run and then fail to record what they found",
		},
		{
			// Migration 009 / 010.
			query: `SELECT NOT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = 'discovery_schedules')`,
			consequence: "there is no discovery_schedules table (migration 009); scheduled scans will not run",
		},
		{
			// Migration 011.
			query: `SELECT NOT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = 'cloud_connections')`,
			consequence: "there is no cloud_connections table (migration 011); certificates stored in ACM, Key Vault, GCP, or Kubernetes will not be inventoried",
		},
		{
			// Migration 013.
			query: `SELECT NOT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = 'renewal_jobs')`,
			consequence: "there is no renewal_jobs table (migration 013); the renewal sweep will find certificates due and be unable to queue any of them",
		},
		{
			// Migration 005. This one is a hard failure at write time rather
			// than a slow query, so it is worth naming precisely.
			query: `SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_constraint con
				JOIN pg_catalog.pg_class child ON child.oid = con.conrelid
				JOIN pg_catalog.pg_namespace cns ON cns.oid = child.relnamespace
				JOIN pg_catalog.pg_class parent ON parent.oid = con.confrelid
				JOIN pg_catalog.pg_namespace pns ON pns.oid = parent.relnamespace
				WHERE con.contype = 'f' AND cns.nspname = 'public' AND pns.nspname = 'auth')`,
			consequence: "tables still reference auth.users (migration 005); issuing a certificate or writing an audit " +
				"entry will fail with a foreign key violation unless every actor exists in Supabase Auth",
		},
	}

	for _, check := range checks {
		var problem bool
		if err := pool.QueryRow(ctx, check.query).Scan(&problem); err != nil {
			slog.Debug("schema check could not run", "error", err)
			continue
		}
		if problem {
			slog.Warn("database schema is out of date", "consequence", check.consequence,
				"fix", "make migrate")
		}
	}
}
