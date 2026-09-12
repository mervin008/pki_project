-- 020_agent_issuance.sql
--
-- The key stops travelling.
--
-- Everything CertPilot has issued so far was issued by asking a gateway for a
-- certificate and a key together. That key was generated somewhere it did not
-- need to exist, travelled over gRPC, was sealed into this database, and — if
-- the certificate is ever deployed — travelled again to the host that serves
-- it. Three places, two journeys, for a secret whose entire security model is
-- that it stays in one place.
--
-- From here the agent generates the key on the host that will use it, signs a
-- CSR with it, and sends only the request. CertPilot never sees the key and
-- never can. That is the architectural claim of this whole product, and this
-- migration is where it becomes true of certificates rather than only of the
-- agent's own identity.
--
-- Two things.
--
-- **`agent_grants`** — what a host is allowed to ask for.
--
-- This is the security question that matters, and getting it wrong is worse
-- than not having an agent. An agent credential that can request any name is a
-- way to obtain a certificate for the payroll system from a compromised web
-- server, signed by the organisation's own CA, and it would look exactly like
-- every other issuance in the log. So nothing is issued to an agent that an
-- operator has not already granted, by name or by pattern, in advance.
--
-- A grant targets one agent or a set of labels. The labels come from the
-- enrolment token, not from the agent, which is what makes them worth trusting:
-- a host cannot label itself into a grant somebody wrote for a different tier.
-- Four hundred web servers enrolled with one token are one grant, and the
-- alternative — a grant per host, created by a script — is how a fleet ends up
-- with four hundred wildcards nobody reviewed.
--
-- **`certificates.key_custody`** — who actually holds the private key.
--
-- Until now, a certificate with no stored key meant one thing: it was
-- discovered or imported, and the key belongs to somebody we cannot name. That
-- is now ambiguous, because a certificate issued to an agent also has no key
-- here — deliberately, permanently, and as the better outcome.
--
-- Three states, because they are three different facts:
--
--   CERTPILOT — the key is sealed in this database. Exportable, and therefore
--               a thing that can be lost, copied, or subpoenaed.
--   AGENT     — the key is on a host and has never been anywhere else. CertPilot
--               could not produce it if ordered to.
--   EXTERNAL  — somebody holds it and it is not us. Discovered, imported, or
--               issued elsewhere.
--
-- "Which of our certificates have keys we could not export even if we wanted
-- to" is a question a security team should be able to answer, and this is the
-- column that answers it.
--

begin;

create table if not exists public.agent_grants (
  id uuid primary key default gen_random_uuid(),
  name text not null,

  -- The target: one specific agent, or every agent carrying these labels.
  -- Exactly one is set; the check below enforces it.
  agent_id uuid references public.agents(id) on delete cascade,
  label_selector jsonb not null default '{}'::jsonb,

  -- The names this grant permits, as exact hostnames or single-level
  -- wildcards. `*.example.com` matches `a.example.com` and deliberately not
  -- `a.b.example.com` — the same rule certificates themselves follow, so a
  -- grant means what somebody reading it thinks it means.
  names jsonb not null default '[]'::jsonb,

  -- Which CA account signs what this grant permits. Part of the grant rather
  -- than chosen by the agent: an agent that could pick its own issuer could
  -- pick the cheapest, the least logged, or the one with the widest trust.
  ca_account_id uuid not null references public.ca_accounts(id) on delete cascade,

  -- Floor on what the host may generate. A grant that permits a 1024-bit key
  -- is a grant that will eventually be used with one.
  min_key_size int not null default 256 check (min_key_size > 0),
  allowed_key_types jsonb not null default '["ECDSA", "RSA", "Ed25519"]'::jsonb,
  validity_days int not null default 0 check (validity_days >= 0),

  -- How much life must remain before the agent may ask for a replacement.
  -- The agent decides when to renew; this is the earliest it may.
  renew_before_days int not null default 30 check (renew_before_days > 0),

  is_enabled boolean not null default true,
  revoked_at timestamptz,
  revoked_by uuid,
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- A grant with neither target matches nothing and would sit in the list
  -- looking like permission somebody had given.
  constraint agent_grants_target_check check (
    (agent_id is not null) or (label_selector <> '{}'::jsonb)
  )
);

create index if not exists idx_agent_grants_agent
  on public.agent_grants (agent_id)
  where revoked_at is null;

create index if not exists idx_agent_grants_live
  on public.agent_grants (created_at desc)
  where revoked_at is null and is_enabled;

-- ── Who holds the key ──────────────────────────────────────

alter table public.certificates
  add column if not exists key_custody text not null default 'EXTERNAL'
    check (key_custody in ('CERTPILOT', 'AGENT', 'EXTERNAL')),
  -- Which host, when the answer is AGENT. Set null rather than cascading the
  -- delete: an agent being removed does not make the certificate stop existing,
  -- and the record that its key was never here has to survive.
  add column if not exists key_holder_agent_id uuid references public.agents(id) on delete set null;

-- Backfill from what is already true, once. Everything holding a sealed key is
-- in CertPilot's custody; everything else came from somewhere else, which is
-- exactly what EXTERNAL means and is already the column default.
update public.certificates
set key_custody = 'CERTPILOT'
where private_key_encrypted is not null and private_key_encrypted <> '';

create index if not exists idx_certificates_key_custody
  on public.certificates (key_custody);

commit;
