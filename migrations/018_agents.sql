-- 018_agents.sql
--
-- The host agent gets an identity.
--
-- Everything CertPilot has deployed so far has been to something that was
-- already reachable over the network and already had a credential somebody
-- configured. The agent is the opposite case, and it is the one that matters:
-- the servers where certificates actually live, that nothing can reach inwards,
-- and where the private key should never have travelled in the first place.
--
-- Which makes this the most security-critical table in the schema. An agent
-- credential will, by the end of this phase, be able to ask for a certificate
-- for a hostname and install it. Three decisions follow.
--
-- **The core stores a public key, not a secret.** The agent generates an
-- Ed25519 keypair on its own host during enrolment and sends the public half.
-- Every request it makes afterwards is signed. A database that leaks yields
-- nothing that can impersonate an agent — which is not true of a bearer token,
-- and it is the same argument that makes local key generation the point of the
-- agent in the first place. The identity key is the first key CertPilot never
-- sees; the certificate keys are the rest.
--
-- **Enrolment is a different credential from operation.** `agent_enrol_tokens`
-- exist to be handed to a machine that has never spoken to CertPilot, and they
-- are one-use and short-lived by default. A bootstrap secret and an operating
-- secret have different blast radii and must not be the same string: a
-- long-lived shared enrolment token pasted into a configuration management
-- template is a credential in a git repository, and it is how this kind of
-- system is usually broken.
--
-- **An agent that goes quiet is a problem, not an absence.** `last_seen_at` is
-- not decoration. A host whose agent stopped reporting three weeks ago still
-- has certificates on it, still has them expiring, and now has nothing
-- maintaining them — and it looks exactly like a healthy host on any screen
-- that only lists what is enrolled. Silence is never success, here as
-- everywhere else in this system.
--

begin;

-- ── Enrolment tokens ───────────────────────────────────────

create table if not exists public.agent_enrol_tokens (
  id uuid primary key default gen_random_uuid(),
  name text not null,

  -- SHA-256 of the raw token. The raw value is shown once, at creation, and is
  -- not recoverable — a credential the server can hand out again is a
  -- credential the server is storing.
  token_hash text not null unique,

  expires_at timestamptz not null,

  -- How many agents this token may enrol. One by default.
  --
  -- Widening it is allowed because a fleet built from one image has to bootstrap
  -- somehow, but it is a decision somebody makes explicitly rather than the
  -- default they get by not thinking about it.
  max_uses int not null default 1 check (max_uses > 0),
  uses     int not null default 0,

  -- Labels applied to every agent enrolled with this token, so a token issued
  -- for one purpose produces agents that can be told apart from another's.
  labels jsonb not null default '{}'::jsonb,

  revoked_at timestamptz,
  revoked_by uuid,
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_agent_enrol_tokens_live
  on public.agent_enrol_tokens (expires_at)
  where revoked_at is null;

-- ── Agents ─────────────────────────────────────────────────

create table if not exists public.agents (
  id uuid primary key default gen_random_uuid(),

  -- What to call it on screen. Defaults to the hostname the agent reports, and
  -- is not unique: two machines legitimately share a name more often than
  -- anybody expects, and refusing the second enrolment would leave a host with
  -- no agent rather than a name collision somebody can fix.
  name     text not null,
  hostname text,
  platform text,
  version  text,

  -- The public half of the key the agent generated. This is the whole
  -- credential as far as this database is concerned.
  public_key text not null,
  -- A short fingerprint of the above, for a human comparing what the agent
  -- printed on the host with what is stored here. Never used to look an agent
  -- up: a truncated hash is not an identifier.
  key_id text not null,

  status text not null default 'ACTIVE'
    check (status in ('ACTIVE', 'REVOKED')),

  labels jsonb not null default '{}'::jsonb,

  -- Where it came from, kept for the life of the agent. When an unexpected
  -- agent turns up, the first two questions are which token let it in and from
  -- what address.
  enrol_token_id uuid references public.agent_enrol_tokens(id) on delete set null,
  enrolled_at    timestamptz not null default now(),
  enrolled_from  text,

  -- Whether anything is still there. See the note at the top.
  last_seen_at timestamptz,
  last_seen_ip text,
  -- What the agent says its own reporting interval is, so staleness is measured
  -- against what this agent promised rather than against one global number that
  -- is wrong for every agent that was configured differently.
  heartbeat_interval_seconds int not null default 300 check (heartbeat_interval_seconds > 0),
  -- Set when an agent has been reported as missing, so the alert fires once
  -- rather than every time the sweep runs.
  stale_alerted_at timestamptz,

  revoked_at timestamptz,
  revoked_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_agents_status on public.agents (status);
create index if not exists idx_agents_last_seen
  on public.agents (last_seen_at)
  where status = 'ACTIVE';

commit;
