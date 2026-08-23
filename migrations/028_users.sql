-- 028_users.sql
--
-- Two changes that have to happen together: give CertPilot its own record of a
-- user, and make the actor columns able to hold what a real identity provider
-- actually issues.
--
-- ── Why the actor columns must widen ────────────────────────────────────────
--
-- Migration 005 severed the foreign keys to Supabase's auth.users so that any
-- OIDC provider could be used, but kept the columns as uuid on the reasoning
-- that "every OIDC provider worth deploying issues a uuid or an opaque string
-- that fits one". That is not true, and it is not close:
--
--   Okta      00u9vme99nxudvxZA0h7              refused
--   Google    110169484474386276334             refused
--   Auth0     auth0|507f1f77bcf86cd799439011    refused
--   Keycloak  a1b2c3d4-e5f6-7890-abcd-ef123...  accepted
--
-- Those are the real shapes, checked against this database. Three of the four
-- providers CertPilot claims to support cannot have their subject stored at
-- all. The failure is not cosmetic and not deferred: the core writes the `sub`
-- claim straight into created_by, so the first certificate issued by anyone
-- signed in through Okta or Google Workspace aborts with
--
--     invalid input syntax for type uuid: "00u9vme99nxudvxZA0h7"
--
-- and issuance stops for that user entirely. It has gone unnoticed because
-- development runs anonymously, and the anonymous subject is a hardcoded uuid.
--
-- text rather than a wider fixed type, because a subject is an opaque string
-- by specification — OpenID Connect Core 2.0 §2 says only that it is
-- case-sensitive, at most 255 ASCII characters, and locally unique to the
-- issuer. Assuming any more structure than that is what produced this bug.
--
-- No policy reads these columns, so widening cannot break row-level security;
-- checked against pg_policies before writing this.
--
-- ── Why a users table ───────────────────────────────────────────────────────
--
-- Roles have until now come from a `certpilot_role` claim on the token, which
-- means promoting a colleague requires an administrator of the identity
-- provider and takes effect only when that person's token is next refreshed.
-- For the team this product is for, that is the wrong place for the decision:
-- they own the CA hierarchy but rarely own Okta.
--
-- The identity provider stays the authority on *who someone is*. CertPilot
-- becomes the authority on *what they may do here*.

begin;

-- ── Widen every actor column ───────────────────────────────────────────────
--
-- Discovered rather than listed. A hand-written list is a snapshot that goes
-- stale the moment a migration adds a table, and the column it misses is the
-- one that fails in production — silently, because uuid columns accept the
-- development subject perfectly well.
do $$
declare
  col record;
begin
  for col in
    select c.table_name, c.column_name
    from information_schema.columns c
    join information_schema.tables t
      on t.table_schema = c.table_schema and t.table_name = c.table_name
    where c.table_schema = 'public'
      and t.table_type = 'BASE TABLE'
      and c.data_type = 'uuid'
      and (c.column_name like '%\_by' or c.column_name = 'actor_id')
  loop
    execute format(
      'alter table public.%I alter column %I type text using %I::text',
      col.table_name, col.column_name, col.column_name);
    raise notice 'widened %.% to text', col.table_name, col.column_name;
  end loop;
end $$;

-- ── The users table ────────────────────────────────────────────────────────

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),

  -- A subject is unique only within the issuer that minted it. Two providers
  -- can and do hand out the same string, so the pair is the identity and
  -- neither half is sufficient alone. Changing auth.issuer therefore creates
  -- new users rather than silently re-binding the old ones to whoever now
  -- holds the same subject, which is the correct and safer behaviour.
  issuer text not null,
  subject text not null,

  email text,
  display_name text,

  -- Mirrors middleware.Role* exactly. A constant the CHECK refuses is the
  -- oldest defect class in this store.
  role text not null default 'viewer'
    check (role in ('viewer', 'auditor', 'operator', 'admin')),

  -- Suspension is deliberately not deletion. Removing the row would orphan
  -- every audit entry attributed to that subject, and the audit log outliving
  -- the person is the entire point of keeping one.
  status text not null default 'ACTIVE'
    check (status in ('ACTIVE', 'SUSPENDED')),

  -- How the role was arrived at, so an operator reading the table can tell a
  -- deliberate grant from a default and from a bootstrap.
  role_source text not null default 'DEFAULT'
    check (role_source in ('DEFAULT', 'BOOTSTRAP', 'ASSIGNED')),

  last_seen_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint users_issuer_subject_key unique (issuer, subject)
);

-- Bootstrap matches on email, and the users screen will sort by it.
create index if not exists idx_users_email on public.users (lower(email));
create index if not exists idx_users_role on public.users (role);

comment on table public.users is
  'CertPilot''s own record of a person. The identity provider remains the '
  'authority on who they are; this table is the authority on what they may do.';

comment on column public.users.subject is
  'The sub claim, stored as text: OIDC Core 2.0 guarantees only that it is a '
  'case-sensitive string of at most 255 ASCII characters.';

-- Row-level security, consistent with every other table here. The core
-- connects as the owner and is unaffected; this protects direct PostgREST
-- access on a Supabase deployment.
alter table public.users enable row level security;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    -- Readable by signed-in callers, never writable through PostgREST: role
    -- assignment goes through the core, which audits it.
    if not exists (
      select 1 from pg_policies
      where schemaname = 'public' and tablename = 'users' and policyname = 'users_select'
    ) then
      create policy "users_select" on public.users
        for select to authenticated using (true);
    end if;
  end if;
end $$;

commit;
