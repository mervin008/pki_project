-- 017_deployment.sql
--
-- The other half of the job.
--
-- Phase 4 ended by being able to say, honestly, that a renewal had not reached
-- the server. This is where CertPilot can do something about it — and it is the
-- point where the risk profile of this system changes completely.
--
--   Renewal creates new material. Deployment replaces material that is
--   currently carrying traffic.
--
-- A renewal that goes wrong leaves a certificate nobody installed. A deployment
-- that goes wrong takes down a service that was working ten seconds earlier.
-- Everything below is shaped by that difference.
--
-- Three things.
--
-- **`deployment_targets` grows up.** The table has existed since migration 001
-- with no Go surface beyond CRUD nobody called. It gains the fields a target
-- needs in order to be operated rather than merely recorded: whether it is
-- enabled, what went wrong last time, and — the important one —
-- `deploys_private_key`.
--
-- That column is not derived at read time from the sealed config, on purpose.
-- "Which places does this organisation ship private keys to" is a question a
-- security team should be able to answer with a SELECT, without holding the
-- KEK and without decrypting anything. A boolean that is set when the target is
-- created makes that answerable. A config blob nobody can read does not.
--
-- **`certificate_deployments`** — the binding, and the reason this migration is
-- not three columns on `certificates`.
--
-- Migration 001 modelled this as `certificates.deployment_target_id`: one
-- certificate, one place. That is wrong about every estate this product is for.
-- A wildcard on six load balancers is six deployments with six outcomes, six
-- fingerprints, and six ways to be half-finished. A single `deployed_at` on the
-- certificate would average them into a number that is true of nowhere.
--
-- So state lives per binding. `deployed_fingerprint` is what that one place was
-- last confirmed to be holding — which is what makes "this certificate is
-- deployed" a claim with a subject rather than a mood.
--
-- **`deployment_jobs`** — durable, leased, retried, exactly like `renewal_jobs`
-- and for exactly the same reason: a process that dies mid-deploy must leave
-- behind something another process can pick up.
--
-- One difference from renewal, and it is the load-bearing one. The partial
-- unique index is on `deployment_id`, not `certificate_id`. Renewal allows one
-- outstanding job per certificate because a second renewal would issue a second
-- certificate. Deployment is the opposite case: one certificate going to six
-- targets is six jobs that must all be outstanding at once, and a constraint
-- copied from the renewal queue would have silently deployed to the first
-- target and quietly dropped the other five.
--

begin;

-- ── Targets ────────────────────────────────────────────────

alter table public.deployment_targets
  add column if not exists description text,
  add column if not exists is_enabled boolean not null default true,
  -- Attempted versus succeeded, the same split ct_monitors and
  -- cloud_connections carry. A target that has been failing for a week must not
  -- read as one nothing has needed lately.
  add column if not exists last_deployment_error text,
  add column if not exists last_success_at timestamptz,
  -- Whether this target receives the private key. See the note above: this is
  -- the inventory of where key material leaves CertPilot's custody, and it has
  -- to be readable without the KEK.
  add column if not exists deploys_private_key boolean not null default false;

-- ── Bindings ───────────────────────────────────────────────

create table if not exists public.certificate_deployments (
  id uuid primary key default gen_random_uuid(),
  certificate_id uuid not null references public.certificates(id) on delete cascade,
  target_id uuid not null references public.deployment_targets(id) on delete cascade,

  is_enabled boolean not null default true,

  -- Per-binding placement: which secret in which namespace, which path, which
  -- listener. Not sealed, and deliberately not a place for credentials — those
  -- belong to the target, which is the thing that holds a connection.
  options jsonb not null default '{}'::jsonb,

  -- What this place was last confirmed to be holding.
  --
  -- Confirmed by a deploy that returned success, which is a claim about what
  -- was sent, not evidence about what is being served. The evidence comes from
  -- the verifier in phase 4 step 4, which opens a connection and looks. The two
  -- are kept apart because conflating them is how a dashboard goes green over
  -- an estate that never picked the certificate up.
  deployed_fingerprint text,
  deployed_at timestamptz,

  last_status text
    check (last_status is null or last_status in ('PENDING', 'DEPLOYED', 'FAILED')),
  last_error text,

  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- One binding per certificate/target pair. Two rows would be two jobs
  -- deploying the same bytes to the same place and reporting separately.
  constraint certificate_deployments_unique unique (certificate_id, target_id)
);

create index if not exists idx_certificate_deployments_certificate
  on public.certificate_deployments (certificate_id);
create index if not exists idx_certificate_deployments_target
  on public.certificate_deployments (target_id);

-- ── Queue ──────────────────────────────────────────────────

create table if not exists public.deployment_jobs (
  id uuid primary key default gen_random_uuid(),
  deployment_id uuid not null references public.certificate_deployments(id) on delete cascade,
  -- Denormalised from the binding so the queue can be read, ordered, and
  -- reported on without a join to a row somebody may be editing.
  certificate_id uuid not null references public.certificates(id) on delete cascade,
  target_id uuid not null references public.deployment_targets(id) on delete cascade,

  -- RENEWAL is the automatic case, MANUAL is somebody pressing the button.
  reason text not null default 'MANUAL'
    check (reason in ('RENEWAL', 'MANUAL', 'RETRY', 'DRIFT')),

  status text not null default 'PENDING'
    check (status in ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),

  run_after timestamptz not null default now(),
  attempts  int not null default 0,

  locked_by    text,
  locked_until timestamptz,

  last_error text,
  attempt_log jsonb not null default '[]'::jsonb,

  -- What this job is trying to put there, captured at enqueue.
  --
  -- Not read back off the certificate at run time on purpose: a job enqueued by
  -- a renewal is for that renewal's certificate, and if a second renewal has
  -- happened since, the job is stale and there will be a newer one behind it.
  fingerprint text,
  -- The expiry being raced, so the queue can be ordered by urgency without a
  -- join, exactly as the renewal queue is.
  not_after timestamptz,

  escalated_at timestamptz,

  triggered_by uuid,
  actor_email  text,

  started_at   timestamptz,
  completed_at timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- At most one outstanding job per binding — per place, not per certificate.
-- See the note at the top: this is the one line where copying the renewal queue
-- would have been wrong.
create unique index if not exists idx_deployment_jobs_one_outstanding
  on public.deployment_jobs (deployment_id)
  where status in ('PENDING', 'RUNNING');

create index if not exists idx_deployment_jobs_claimable
  on public.deployment_jobs (run_after, not_after)
  where status in ('PENDING', 'RUNNING');

create index if not exists idx_deployment_jobs_certificate
  on public.deployment_jobs (certificate_id, created_at desc);

commit;
