-- 022_agent_installs.sql
--
-- The agent stops holding certificates and starts installing them.
--
-- Steps 4a to 4c gave a host an identity, an inventory, and a certificate whose
-- private key CertPilot has never seen. All of it lands in the agent's own
-- state directory, which is not where nginx reads. This is the step that closes
-- that gap, and it is the first time the agent writes to a file another process
-- depends on.
--
-- That makes it the second thing in this system governed by phase 6's sentence:
--
--   Renewal creates new material. Deployment replaces material that is
--   currently carrying traffic.
--
-- Three decisions are baked into this schema, and each of them is a thing that
-- deliberately is not here.
--
-- **There is no command column.** Not on the target, not on the installation,
-- not sealed in a config blob. What a host runs after a certificate lands is
-- read from a file on that host, by the process that runs it, and only ever
-- travels upwards for display. A `reload_command` that the core could set would
-- make this table a queue for arbitrary code on every machine in the estate,
-- authenticated by whoever can write one row. The core names a certificate and
-- a place; the host decides what that means.
--
-- **An agent target is created by the agent reporting, not by an operator
-- filling in a form.** Four hundred hosts are four hundred targets, and a
-- product that asks somebody to create them by hand gets a script that creates
-- them by hand — which is the same reasoning that made agent grants match on
-- labels rather than on host ids.
--
-- **`deploys_private_key` is false for every agent target, and that is a fact
-- rather than a default.** The key was generated on that host and is already
-- there. Migration 017 put that column in so a security team could answer
-- "where does this organisation ship private keys" with a SELECT and no KEK;
-- agent hosts being absent from that answer is exactly the property step 4c
-- exists to create.
--

begin;

-- ── An agent is a place certificates go ────────────────────

-- Migration 001 fixed the target types in a check constraint, and this is the
-- third time this project has had to widen one of those. Recorded rather than
-- quietly patched: a check constraint listing values is a decision that the set
-- is closed, and every one of these widenings has been a case where it was not.
-- The others were `certificates.discovered_via` in 012 and again in 021.
alter table public.deployment_targets
  drop constraint if exists deployment_targets_target_type_check;

alter table public.deployment_targets
  add constraint deployment_targets_target_type_check
  check (target_type in ('filesystem', 'aws_acm', 'kubernetes', 'webhook', 'gcp_lb', 'azure_kv', 'agent'));

alter table public.deployment_targets
  add column if not exists agent_id uuid references public.agents(id) on delete cascade;

-- One target per agent. The host is the place; which file on it is the
-- binding's business.
--
-- ON DELETE CASCADE above rather than SET NULL: a target that used to be an
-- agent and is now a row with no agent is a target nothing can ever deploy to,
-- sitting in the list looking operable.
create unique index if not exists idx_deployment_targets_agent
  on public.deployment_targets (agent_id)
  where agent_id is not null;

-- ── What each host has actually installed ──────────────────

-- The host's own view, kept alongside the central one rather than instead of
-- it. `certificate_deployments` answers "what is this certificate's status at
-- that place" in the same shape as every other target type. This answers a
-- question that only exists for agents:
--
--   This machine is configured to install a certificate that nobody has
--   granted it, and nothing else in this system can see that.
--
-- A destination declared for a name the host was never granted matches no
-- certificate, holds no binding, and produces no row anywhere else in the
-- database. Usually it is one letter wrong, and it will be found at the next
-- renewal, at night, by an outage — unless something says so now. So an
-- unfulfilled destination is a row here with no certificate_id.
create table if not exists public.agent_installations (
  id uuid primary key default gen_random_uuid(),
  agent_id uuid not null references public.agents(id) on delete cascade,

  -- The destination's name in the host's spec: "nginx", "haproxy".
  name text not null,
  -- The certificate name the spec asks for, as written. Kept even when nothing
  -- matched it, because the unmatched string is the finding.
  certificate_name text not null,

  certificate_id uuid references public.certificates(id) on delete set null,
  fingerprint_sha256 text,
  not_after timestamptz,

  -- Which files this destination writes, in the order it writes them.
  paths jsonb not null default '[]'::jsonb,

  status text not null default 'UNFULFILLED'
    check (status in ('INSTALLED', 'FAILED', 'UNFULFILLED')),
  detail text,
  last_error text,

  -- Whether a failed attempt put the previous material back. Separate from the
  -- error: an install that failed and restored what was working is an
  -- inconvenience, and one that did not is an outage, and a single status
  -- cannot say which.
  rolled_back boolean not null default false,

  installed_at timestamptz,
  reloaded_at timestamptz,

  -- Reported for display only. There is deliberately no path by which the core
  -- can write these back down; see the note at the top.
  reload_command text,
  check_command text,

  reported_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint agent_installations_unique unique (agent_id, name)
);

create index if not exists idx_agent_installations_agent
  on public.agent_installations (agent_id);
create index if not exists idx_agent_installations_certificate
  on public.agent_installations (certificate_id)
  where certificate_id is not null;
-- The two queries a central team actually runs: what is broken, and what is
-- configured for something that does not exist.
create index if not exists idx_agent_installations_attention
  on public.agent_installations (status, updated_at desc)
  where status in ('FAILED', 'UNFULFILLED');

commit;
