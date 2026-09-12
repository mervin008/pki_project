-- 013_renewal_jobs.sql
--
-- Renewal becomes a row somebody owns, rather than a call the scheduler makes.
--
-- Until now a renewal existed only as a function on a goroutine. A core that
-- restarted mid-renewal left nothing behind: no record that an attempt had been
-- made, no record of why it failed, and no way for another process to pick it
-- up. The next scan would try again from nothing, an hour later, forever, and a
-- certificate that had been failing to renew for six days looked exactly like
-- one that had never been due.
--
-- Renewal is the only part of this system that changes the world. Everything
-- else observes. A discovery scan that runs twice wastes a few seconds; a
-- renewal that runs twice on two replicas issues two certificates against a
-- rate limit counted per week.
--
-- Three things in this table do the work.
--
-- **The partial unique index.** At most one outstanding job per certificate, so
-- two replicas scanning at the same second cannot enqueue the same renewal
-- twice. This — with `FOR UPDATE SKIP LOCKED` on the claim — is why there is no
-- leader election here. Every replica is an equal worker, and none of them is a
-- single point of failure with a failover gap during which nothing renews.
--
-- **The lease.** `locked_by` and `locked_until`. A worker that is killed does
-- not need to be cleaned up after; its claim simply expires and another worker
-- takes the job. This is the difference between "the process died" and "that
-- certificate is now stuck forever".
--
-- **The attempt log.** Every attempt with its error, not only the most recent.
-- "This has failed eleven times in six days with the same DNS error" is a
-- sentence somebody can act on. "Last error: timeout" is not, because it cannot
-- distinguish a blip from a fortnight of silence.
--

begin;

create table if not exists public.renewal_jobs (
  id uuid primary key default gen_random_uuid(),
  certificate_id uuid not null references public.certificates(id) on delete cascade,

  -- Why this job exists. SCHEDULED is the lead-time sweep, MANUAL is somebody
  -- pressing the button, ARI is the CA asking for it (phase 4 step 3).
  reason text not null default 'SCHEDULED'
    check (reason in ('SCHEDULED', 'MANUAL', 'ARI', 'RETRY')),

  status text not null default 'PENDING'
    check (status in ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),

  -- When this job may next be attempted. Retries move it forward; nothing else
  -- does.
  run_after timestamptz not null default now(),
  attempts  int not null default 0,

  -- The lease. See above: a dead worker's claim expires rather than needing to
  -- be reaped.
  locked_by    text,
  locked_until timestamptz,

  last_error text,
  -- Every attempt: when, how long, and what went wrong. Bounded in the
  -- application so a job retrying for weeks does not grow without limit.
  attempt_log jsonb not null default '[]'::jsonb,

  -- The deadline this job is racing, copied from the certificate when the job
  -- was created. Denormalised on purpose: the queue is ordered by it on every
  -- claim, and a job needs to be able to say how much runway is left without a
  -- join to a table that may have been updated underneath it.
  not_after timestamptz,

  -- What the certificate was when the job was created.
  --
  -- This is the crash guard. A worker that finalised an order and died before
  -- writing the result would otherwise issue a second certificate on the retry.
  -- Instead the next attempt compares: if the certificate's fingerprint has
  -- moved on its own, the renewal already happened and the job is complete.
  -- Verifying the outcome beats trusting an idempotency key, because it is true
  -- however the world changed.
  fingerprint_at_enqueue text,

  -- Set when a job reaches a state a person should look at, so alerting does
  -- not have to re-derive it from attempt counts.
  escalated_at timestamptz,

  triggered_by uuid,
  actor_email  text,

  started_at   timestamptz,
  completed_at timestamptz,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- At most one outstanding job per certificate. The whole multi-replica story
-- rests on this: an enqueue that would duplicate work fails the constraint and
-- is discarded, rather than being prevented by electing somebody.
create unique index if not exists idx_renewal_jobs_one_outstanding
  on public.renewal_jobs (certificate_id)
  where status in ('PENDING', 'RUNNING');

-- The claim query's index: ready jobs, most urgent first.
create index if not exists idx_renewal_jobs_claimable
  on public.renewal_jobs (run_after, not_after)
  where status in ('PENDING', 'RUNNING');

create index if not exists idx_renewal_jobs_certificate
  on public.renewal_jobs (certificate_id, created_at desc);

commit;
