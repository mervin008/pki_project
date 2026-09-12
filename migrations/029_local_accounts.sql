-- 029_local_accounts.sql
--
-- Passwords and sessions, so that CertPilot can be signed into without an
-- identity provider — and so that it can stop having an anonymous mode.
--
-- Anonymous access was a first-run convenience: no Authorization header meant
-- admin, gated to development mode on a loopback address. The gate was real,
-- but the shape of the thing is wrong for this product. Every screenshot,
-- every demo, every local reproduction ran as an unnamed superuser, which meant
-- the authorisation paths were the least exercised code in the system and the
-- audit log recorded a subject nobody could be asked about. The defect fixed in
-- 028 survived for exactly that reason: development wrote a hardcoded uuid, so
-- nothing ever tried a real subject.
--
-- ── Why sessions are rows and not signed tokens ─────────────────────────────
--
-- The alternative is for the core to mint a JWT on login. That requires it to
-- hold a key capable of forging an admin token, which is the specific criticism
-- this codebase already makes of the legacy auth.jwt_secret path, and it makes
-- a leaked token good until it expires because there is nothing to revoke.
--
-- An opaque random token, stored only as a SHA-256 hash and compared in
-- constant time, is the same design as display_tokens in migration 003. It is
-- revocable the instant somebody is suspended, and there is no signing key to
-- steal.
--
-- ── Why lockout is in the schema ────────────────────────────────────────────
--
-- CertPilot has no rate limiting. A password endpoint without one is an
-- unlimited guessing oracle, so the counter and the lock are columns rather
-- than an in-process map: the core runs as several replicas behind a load
-- balancer, and an attacker spreading attempts across them would otherwise
-- reset the count with every request.

begin;

-- ── Passwords on the existing users table ──────────────────────────────────

alter table public.users add column if not exists password_hash text;
alter table public.users add column if not exists password_set_at timestamptz;

-- Throttling state. Counted per account rather than per address because the
-- address an attacker comes from is the part they control.
alter table public.users add column if not exists failed_logins integer not null default 0;
alter table public.users add column if not exists locked_until timestamptz;

-- must_change_password marks a credential the account holder has not chosen —
-- the generated one printed at first start. It is not a security control on its
-- own; it is what lets the UI insist rather than hope.
alter table public.users add column if not exists must_change_password boolean not null default false;

comment on column public.users.password_hash is
  'Argon2id, encoded with its own parameters so that raising them later does '
  'not invalidate existing passwords. Null for accounts that sign in only '
  'through an identity provider.';

-- An account with a password is addressed by email, and two accounts sharing
-- one would make "who is signing in" ambiguous. Partial, because accounts
-- without an email — a provider that does not release the claim — are still
-- perfectly valid.
create unique index if not exists idx_users_email_unique
  on public.users (lower(email))
  where email is not null;

-- ── Sessions ───────────────────────────────────────────────────────────────

create table if not exists public.sessions (
  id uuid primary key default gen_random_uuid(),

  -- Cascade on purpose. A session is meaningless without its user, and the
  -- audit trail lives in audit_logs against the subject, not here.
  user_id uuid not null references public.users(id) on delete cascade,

  -- The raw token is never stored. What is presented in the cookie is compared
  -- by hash, in constant time, exactly as display tokens are.
  token_hash text not null unique,

  expires_at timestamptz not null,
  -- Set when somebody signs out, or when an administrator ends every session
  -- for an account. Kept rather than deleted so that "signed out at" is
  -- answerable.
  revoked_at timestamptz,

  -- Enough to recognise a session in use somewhere unexpected, and no more.
  last_seen_at timestamptz,
  last_seen_ip text,
  user_agent text,

  created_at timestamptz not null default now()
);

create index if not exists idx_sessions_user on public.sessions (user_id);
-- Expiry sweeps scan this; a partial index keeps it to the rows that can still
-- be used.
create index if not exists idx_sessions_live on public.sessions (expires_at)
  where revoked_at is null;

comment on table public.sessions is
  'Opaque browser sessions. Rows rather than signed tokens so that the core '
  'holds no key capable of forging one, and so that a session can be ended '
  'the moment an account is suspended.';

-- No policy is created for `authenticated`. Unlike users, a session row is a
-- credential's shadow: anything able to read this table through PostgREST
-- would learn which sessions are live and when, and nothing in the product
-- needs that. The core connects as the owner and is unaffected.

commit;
