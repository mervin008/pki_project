-- 003_display_tokens.sql
--
-- Kiosk display tokens: the credential a wall-mounted dashboard authenticates
-- with.
--
-- A browser's EventSource cannot set an Authorization header, so the live
-- monitoring stream is unreachable from an unattended screen using the ordinary
-- bearer flow. The alternative — leaving a real operator session logged in on a
-- machine in a corridor — is materially worse: that session can issue, revoke,
-- and export private keys.
--
-- This table backs a credential that deliberately cannot do any of those
-- things. It is read-only, viewer-scoped, expiring, and revocable, and every
-- use is recorded so a leaked token is visible rather than silent.
--
-- Unlike 001, nothing here references auth.users. That schema exists only on
-- Supabase, and a monitoring credential is exactly the kind of thing a plain
-- PostgreSQL deployment needs. created_by and revoked_by hold the subject claim
-- from the identity provider without a foreign key.

begin;

create table if not exists public.display_tokens (
  id uuid primary key default gen_random_uuid(),

  -- Names the screen, so revocation can be decided without guesswork:
  -- "the one in the 4th-floor corridor" is an answerable question.
  name text not null unique,

  -- SHA-256 of the raw token, hex encoded.
  --
  -- The raw token is shown once at creation and never stored, so a database
  -- dump does not yield working credentials. A plain hash rather than bcrypt or
  -- argon2 is correct here and not a shortcut: the token is 256 bits of CSPRNG
  -- output, so there is no dictionary to slow down, and lookup must be a single
  -- indexed equality rather than a scan of every row.
  token_hash text not null unique,

  -- NOT NULL by design. A kiosk credential with no expiry is the one that is
  -- still live five years after the screen was decommissioned.
  expires_at timestamptz not null,

  -- Recorded so a token in use somewhere unexpected is discoverable.
  last_seen_at timestamptz,
  last_seen_ip inet,

  -- Revocation is a soft delete: the record of a credential that had to be
  -- revoked is worth more than the row it frees.
  revoked_at timestamptz,
  revoked_by uuid,

  created_by uuid,
  created_at timestamptz not null default now(),

  constraint display_tokens_expiry_after_creation check (expires_at > created_at)
);

-- Every request from a screen resolves a token by hash; the unique constraint
-- already indexes it. This one supports the management list view.
create index if not exists idx_display_tokens_active
  on public.display_tokens (expires_at desc)
  where revoked_at is null;

-- Row-level security is enabled with no policies at all.
--
-- That is deny-by-default for every client role: nothing should ever read this
-- table through PostgREST or any other direct path. The core connects as the
-- table owner, which bypasses RLS, so it is unaffected.

commit;
