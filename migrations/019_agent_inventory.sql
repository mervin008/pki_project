-- 019_agent_inventory.sql
--
-- The last place certificates hide.
--
-- Migration 011 called cloud stores the third place, after what is served and
-- what was issued. This is the fourth, and it is the one none of the other
-- three can reach: **a file on a disk**.
--
-- A network scan finds what an address presents. Certificate Transparency finds
-- what a public CA issued. A cloud sync finds what a provider is holding. None
-- of them finds the certificate in /etc/nginx/ssl on a host behind two
-- firewalls, issued by an internal CA, on a port nobody scanned — which is
-- where a great deal of an enterprise's TLS actually lives.
--
-- But the reason this table exists is not "one more inventory". It is that a
-- process running *on* the host can see things no remote observer ever will,
-- and two of them are the sharpest findings in this system:
--
--   **The private key's permissions.** `server.key` at mode 0644 means every
--   account on that machine holds the key to that certificate. No scanner, no
--   CT log, and no cloud API can ever report that. An agent reads it with one
--   stat call.
--
--   **Whether the key matches the certificate.** A mismatched pair is a service
--   that will not come back after its next restart, sitting quietly until
--   something restarts it — a deploy, a kernel update, an unrelated outage at
--   three in the morning.
--
-- What is stored is a certificate, a path, and facts about a key. **Never a
-- key.** The agent parses one to derive its public half and compare, and there
-- is no field in the report it could travel in — the same property the agent's
-- own identity key has, applied to everything else it touches.
--
-- `kind` keeps trust stores from drowning the results. A host's
-- ca-certificates bundle holds well over a hundred roots that the distribution
-- manages and nobody in this organisation is responsible for; it is recorded as
-- one row that says so, rather than as a hundred findings.
--

begin;

create table if not exists public.agent_certificates (
  id uuid primary key default gen_random_uuid(),
  agent_id uuid not null references public.agents(id) on delete cascade,

  -- Where it is on that host. Unique per agent, which is what makes a repeated
  -- scan an update rather than a duplicate.
  path text not null,

  -- What the file is: a leaf, a CA, or a trust bundle. Findings apply to the
  -- first two.
  kind text not null default 'leaf'
    check (kind in ('leaf', 'ca', 'bundle')),
  certificate_count int not null default 1,

  common_name   text,
  subject_dn    text,
  issuer_dn     text,
  serial_number text,
  sans          jsonb not null default '[]'::jsonb,
  not_before    timestamptz,
  not_after     timestamptz,
  key_type      text,
  key_size      int,
  fingerprint_sha256 text,
  certificate_pem    text,

  -- What only something on the host can see.
  file_mode   text,
  file_owner  text,
  modified_at timestamptz,

  -- Facts about the private key. Not the key.
  private_key_path         text,
  private_key_mode         text,
  private_key_in_same_file boolean not null default false,
  private_key_matches      boolean not null default false,

  -- Which server configurations name this file. A heuristic, so an empty list
  -- means "not found by a text search", not "nothing uses this".
  referenced_by jsonb not null default '[]'::jsonb,

  management_state text not null default 'UNMANAGED'
    check (management_state in ('MANAGED', 'UNMANAGED')),
  matched_certificate_id uuid references public.certificates(id) on delete set null,

  findings jsonb not null default '[]'::jsonb,

  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  -- Set when a scan that succeeded no longer found it. Not deleted: a
  -- certificate file that disappeared is information, and a vanished row takes
  -- its own history with it.
  removed_at timestamptz,

  created_at timestamptz not null default now(),

  constraint agent_certificates_path_unique unique (agent_id, path)
);

create index if not exists idx_agent_certificates_agent
  on public.agent_certificates (agent_id, management_state);

create index if not exists idx_agent_certificates_fingerprint
  on public.agent_certificates (fingerprint_sha256)
  where fingerprint_sha256 is not null;

create index if not exists idx_agent_certificates_expiry
  on public.agent_certificates (not_after)
  where removed_at is null;

-- When a host last managed to report what is on it, and how much of it there
-- was. Kept on the agent rather than derived, for the reason every other
-- "last synced" column in this schema exists: a host that has not been scanned
-- since March must not read as a host with nothing on it.
alter table public.agents
  add column if not exists last_inventory_at timestamptz,
  add column if not exists certificates_seen int not null default 0,
  add column if not exists unmanaged_seen int not null default 0;

commit;
