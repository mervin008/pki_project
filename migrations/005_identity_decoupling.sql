-- 005_identity_decoupling.sql
--
-- Severs the foreign keys from CertPilot's tables to an external `auth.users`.
--
-- Why this is required rather than tidying:
--
-- Migration 001 used to declare every actor column as
-- `references auth.users(id) on delete set null`, against an identity table
-- CertPilot does not own — but the core does not authenticate against any such
-- table. It verifies OIDC tokens against a JWKS
-- endpoint (`auth.jwks_url`), which is just as likely to be Keycloak, Okta,
-- Entra, Auth0, or Authentik, and stores the `sub` claim from whichever one is
-- configured. None of those subjects exist in `auth.users`.
--
-- The result on a live database is not a subtle inconsistency, it is a hard
-- failure: `INSERT INTO certificates (..., created_by)` raises a foreign key
-- violation and issuance stops. Local development trips it immediately —
-- anonymous access writes the fixed subject 00000000-0000-0000-0000-000000000001,
-- which is deliberately not a real user anywhere.
--
-- Migration 003 already took this position explicitly for `display_tokens`:
-- "created_by and revoked_by hold the subject claim from the identity provider
-- without a foreign key." This applies that decision to the tables 001 created,
-- which predate it.
--
-- What is deliberately kept:
--
--   * The columns themselves. Actor attribution is the point of an audit log;
--     only the referential constraint is wrong.
--   * The uuid type. Every OIDC provider worth deploying issues a uuid or an
--     opaque string that fits one, and widening to text would break the
--     existing indexes for no gain. A provider whose subjects are not uuids is
--     a schema change, not a silent coercion.
--   * Row-level security and its policies. They protect direct PostgREST
--     access, which is a different threat model from the core's connection.
--     (Both were later removed outright: the schema is plain PostgreSQL and
--     authorisation for people is enforced in the API layer.)
--
-- On a database built by a current CertPilot this is a no-op by construction:
-- 001 no longer creates the constraints. It still matters on a database built
-- by an older one, where they exist and must be dropped.

begin;

-- Discovered rather than named. Postgres generates constraint names like
-- `certificates_created_by_fkey`, but a name is a guess, and
-- `drop constraint if exists <wrong guess>` succeeds while doing nothing —
-- which would leave the failure in place and look like it had been fixed.
-- Matching on the referenced schema cannot miss one and cannot drop anything
-- else.
do $$
declare
  fk record;
  dropped int := 0;
begin
  for fk in
    select con.conrelid::regclass::text as table_name,
           con.conname                  as constraint_name
    from pg_constraint con
    join pg_class      child  on child.oid  = con.conrelid
    join pg_namespace  cns    on cns.oid    = child.relnamespace
    join pg_class      parent on parent.oid = con.confrelid
    join pg_namespace  pns    on pns.oid    = parent.relnamespace
    where con.contype = 'f'
      and cns.nspname = 'public'
      and pns.nspname = 'auth'
  loop
    execute format('alter table %s drop constraint %I',
                   fk.table_name, fk.constraint_name);
    raise notice 'dropped % on %', fk.constraint_name, fk.table_name;
    dropped := dropped + 1;
  end loop;

  raise notice 'identity decoupling: % foreign key(s) to auth.* removed', dropped;
end
$$;

-- The indexes on those columns are kept and are not redundant. They existed to
-- support the foreign key, but they are also what makes "everything this actor
-- did" answerable, which is the question an audit trail is for.
create index if not exists idx_audit_logs_actor_created
  on public.audit_logs (actor_id, created_at desc)
  where actor_id is not null;

commit;

-- ── A note on row-level security, for whoever reads this next ──────────────
--
-- RLS stays enabled on every table from 001. The core is unaffected because it
-- connects as the table owner, and Postgres does not apply RLS to a table's
-- owner unless the table is set to `force row level security`. None are.
--
-- This is load-bearing and fails silently in the worst possible direction. A
-- policy that denies a SELECT does not raise an error — it returns zero rows.
-- So a core connected as some other role would come up healthy, report a
-- perfectly empty estate, and show every dashboard tile at zero, which is
-- indistinguishable from an organisation that has no expiring CAs.
--
-- `store.Preflight` checks for exactly this at startup and refuses to run
-- rather than serve a reassuring lie. If you introduce a dedicated role for the
-- core, grant it `bypassrls` and re-read that check before assuming it works.
