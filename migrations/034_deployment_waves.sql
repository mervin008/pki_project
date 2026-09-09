-- 034: let deployment order be declared.
--
-- Deployment is the operation that changes the world under live traffic:
-- renewal creates new material, deployment replaces material that is currently
-- carrying requests. Until now the order it happened in was whatever the queue
-- reached first — `not_after ASC, run_after ASC`, which says nothing about
-- environment. "Staging, then production" could not be expressed at all.
--
-- The queue already paused a rollout once a job for the same certificate had
-- failed, which is a real safety net and stays. But it is a reaction, not a
-- plan: before anything fails, every replica claims a job, so the first attempt
-- lands on as many targets at once as there are workers. That is a canary of
-- one-per-worker, and on three replicas a certificate that installs wrongly
-- breaks three listeners rather than one.
--
-- Waves make the order a declaration. A target names when it goes, a job
-- carries that number, and a wave does not start until every earlier wave has
-- finished. A canary is then a target on its own in the lowest wave — one
-- target, exactly one attempt, said out loud rather than inferred.

begin;

alter table public.deployment_targets
  -- Lower goes first. Zero is the default, which is what every existing target
  -- already effectively has, so nothing changes for a deployment that does not
  -- ask for ordering.
  add column if not exists deploy_order int not null default 0;

comment on column public.deployment_targets.deploy_order is
  'Rollout wave. Lower deploys first; a wave waits for every earlier wave to finish.';

alter table public.deployment_jobs
  -- Denormalised from the target at enqueue, for the same reason target_id
  -- already is: the claim runs on every poll from every worker, and it must be
  -- able to order and gate on this without joining a row somebody is editing.
  --
  -- It is also the honest value. A job carries the plan as it stood when the
  -- rollout began; re-reading the target mid-rollout would let somebody
  -- reorder a wave that is halfway through, which is how production gets a
  -- certificate that staging never accepted.
  add column if not exists deploy_order int not null default 0;

-- The claim's gate: "is anything for this certificate still outstanding in an
-- earlier wave". Ordered by wave within a certificate, which is the exact shape
-- of that question.
create index if not exists idx_deployment_jobs_wave
  on public.deployment_jobs (certificate_id, deploy_order)
  where status in ('PENDING', 'RUNNING');

commit;
