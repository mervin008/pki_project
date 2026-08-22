-- prelude.sql — run this once, before the migrations, on plain PostgreSQL.
--
-- CertPilot's schema was written against Supabase and migration 001 references
-- two things a plain PostgreSQL server does not have: the `auth.users` table
-- that Supabase's GoTrue creates, and the `authenticated` role its policies
-- grant to. Without them, `001_initial_schema.sql` fails on its first foreign
-- key and rolls back, which has been recorded as a known gap since the first
-- week and is the reason nothing has ever run the schema outside Supabase.
--
-- This file closes that. It is deliberately **not** in `migrations/`: the
-- migrator applies everything it finds there, and creating a stub `auth.jwt()`
-- on a real Supabase project would shadow the genuine one and quietly break
-- every row-level security policy in the database. It has to be a thing
-- somebody runs on purpose, on a server where it is right.
--
--   psql "$CERTPILOT_DB_URL" -f deploy/plain-postgres/prelude.sql
--   certpilot-core --migrate
--
-- **What this does not give you is Supabase's security model.** The policies in
-- migration 001 are written against `auth.jwt()`, and the stub below returns an
-- empty object — so `get_user_role()` finds no role and the restrictive
-- policies deny rather than allow. That is the safe direction, and it is also
-- why CertPilot's own connection should be the owner of these tables (owners
-- bypass RLS) while any other role that can reach this database should be
-- treated as having no access at all. Authorisation for people is enforced in
-- the API layer, which is where it is enforced on Supabase too; RLS there is a
-- second line, and on plain PostgreSQL you do not get the second line.

begin;

-- ── The identity Supabase would have provided ──────────────

create schema if not exists auth;

-- Referenced by `created_by` and `actor_id` columns across the schema. Only the
-- id is used — CertPilot never reads a name or an email out of this table, it
-- carries those itself on the rows that need them — so a bare key table is the
-- whole of what the foreign keys require.
create table if not exists auth.users (
  id uuid primary key,
  email text,
  created_at timestamptz not null default now()
);

-- The anonymous actor the API uses when authentication is disabled for local
-- development. Present so that a development run does not violate a foreign key
-- on its first audit entry.
insert into auth.users (id, email)
values ('00000000-0000-0000-0000-000000000001', 'anonymous@certpilot.local')
on conflict (id) do nothing;

-- ── The claims function the policies read ──────────────────

-- Returns an empty object, deliberately.
--
-- On Supabase this function returns the verified claims of the caller's JWT. A
-- stub cannot verify anything, so it must not pretend to: returning a role here
-- would hand every connection whatever role it named. An empty object means
-- `get_user_role()` resolves to nothing and the write policies refuse, which
-- fails closed.
create or replace function auth.jwt()
returns jsonb
language sql
stable
as $$ select '{}'::jsonb $$;

comment on function auth.jwt() is
  'Stub for plain PostgreSQL. Returns no claims, so RLS policies fail closed. Real authorisation is enforced in the CertPilot API.';

commit;

-- ── The realtime publication ───────────────────────────────
--
-- Migration 001 adds three tables to a publication called `supabase_realtime`,
-- which Supabase creates and a plain server does not. The migration guards on
-- the tables not already being in it, but not on the publication existing at
-- all, so it fails with `publication "supabase_realtime" does not exist`.
--
-- Created empty here. CertPilot does not use it — the live dashboard is fed by
-- the core's own event stream over SSE precisely so that it does not depend on
-- Supabase Realtime — so on a plain server this publication is a thing the
-- schema mentions and nothing reads. It exists so that migration 001 applies.
do $$
begin
  if not exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    create publication supabase_realtime;
  end if;
end
$$;

-- ── The role the grants and policies target ────────────────
--
-- Outside the transaction: CREATE ROLE cannot be rolled back in all versions
-- and the later migrations already guard on this role's existence, so a failure
-- here should not take the rest with it.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
end
$$;
