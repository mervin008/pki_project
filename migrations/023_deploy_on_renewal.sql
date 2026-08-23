-- 023_deploy_on_renewal.sql
--
-- The loop closes.
--
-- Phase 4 ended by being able to say, honestly, that a renewal had not reached
-- the server. Step 1 made deployment a durable job somebody could press a
-- button for. This is where the button presses itself, and it is the single
-- most dangerous change in the deployment phase:
--
--   Automatic deployment on renewal is the feature that turns one mistake into
--   a fleet-wide one.
--
-- Everything here is a brake rather than an accelerator.
--
-- **`deploy_on_renewal` defaults to true, and every existing binding is set to
-- false.** Those two sentences look contradictory and are not. A binding
-- created from now on is created by somebody who knows this feature exists, and
-- "install this certificate there" obviously includes "when it changes". A
-- binding that already exists was created under a regime where nothing deployed
-- by itself, and an upgrade that silently began writing to production servers
-- would be exactly the fleet-wide mistake above — delivered by an apt-get.
--
-- The discoverability cost of that is real: a switch nobody turns on is a
-- feature nobody has. It is paid for in words rather than in defaults. The
-- binding summary says "none of which will be updated when it renews", which is
-- a sentence somebody acts on.
--
-- **There is no `deploy_order` column, and its absence is deliberate.** Waves
-- were designed and dropped in favour of something that needs no configuration
-- at all: the queue refuses to start a *fresh* job for a certificate while
-- another job for that certificate is failing. The first target attempted
-- becomes the canary automatically, on every certificate, with nobody having
-- declared anything. Explicit ordering is a real feature and a later one;
-- shipping it alongside this would have been two half-built controls instead of
-- one working one.
--
-- Applies to plain PostgreSQL as well as Supabase.

begin;

alter table public.certificate_deployments
  add column if not exists deploy_on_renewal boolean not null default true;

-- The upgrade brake. See the note above: new bindings deploy automatically,
-- bindings that predate the feature do not until somebody says so.
--
-- Guarded on the column having just been added, so re-running this migration on
-- a database where an operator has since switched bindings on does not switch
-- them back off. Migrations are append-only here and the migrator checksums
-- them, but "this ran twice" is a thing that happens to people and the cost of
-- being wrong is somebody's estate quietly ceasing to deploy.
do $$
begin
  if not exists (
    select 1 from public.schema_migrations where version = '023'
  ) then
    update public.certificate_deployments set deploy_on_renewal = false;
  end if;
exception when undefined_table then
  update public.certificate_deployments set deploy_on_renewal = false;
end
$$;

-- The halt predicate reads "is any job for this certificate currently failing",
-- on every claim, from every worker. A job that has been attempted and is
-- waiting to retry is the whole of what it looks for.
create index if not exists idx_deployment_jobs_failing
  on public.deployment_jobs (certificate_id)
  where status = 'PENDING' and attempts > 0;

commit;
