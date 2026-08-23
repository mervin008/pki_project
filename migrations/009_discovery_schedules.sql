-- 009_discovery_schedules.sql
--
-- Turns discovery from something someone runs into something that runs.
--
-- A scan performed once is a snapshot, and a snapshot of an estate is out of
-- date by the afternoon. The finding discovery exists to produce — an endpoint
-- serving a certificate nobody told CertPilot about — is created continuously,
-- by deployments nobody mentioned and appliances nobody registered. Catching it
-- means looking again, on a schedule, without anyone remembering to.
--
-- Two things are added.
--
-- **`discovery_schedules`** — what to scan and how often. Deliberately not a
-- cron expression: an interval is what a PKI team actually wants ("this range,
-- daily"), and a cron field is a small language whose mistakes are silent. A
-- schedule that was meant to run nightly and instead runs yearly looks
-- identical on screen to one that works.
--
-- **An index for reconciliation.** The second run of a scan is not worth much
-- as a list — it is worth what it says has *changed* since the first. Answering
-- "what was this endpoint serving last time" means finding the newest earlier
-- result for a host and port, once per endpoint scanned, so it has to be an
-- index hit and not a scan of every result ever recorded.
--
-- Applies to plain PostgreSQL as well as Supabase.

begin;

create table if not exists public.discovery_schedules (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  -- The targets as typed: "10.0.0.0/24", not the 254 addresses it becomes. A
  -- schedule is edited by the person who wrote it, and re-reading an expansion
  -- is not editing.
  targets jsonb not null,
  ports   jsonb not null default '[443]'::jsonb,

  -- Minutes between runs. Floored in the application rather than here, because
  -- the reason for the floor — an interval short enough to be indistinguishable
  -- from a denial of service against your own estate — is not a schema concern.
  interval_minutes int not null check (interval_minutes > 0),
  is_enabled boolean not null default true,

  -- last_run_at is when a run last *started*, not finished: it is what the next
  -- run is computed from, and a long scan must not push its own schedule later
  -- every time it runs.
  last_run_at  timestamptz,
  next_run_at  timestamptz,
  last_scan_id uuid references public.discovery_scans(id) on delete set null,
  -- The outcome of the last run, kept on the schedule so a list of schedules
  -- can say which one has quietly stopped working. A schedule that errors every
  -- night and is never read is worse than no schedule: it is the appearance of
  -- coverage.
  last_error text,

  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- The scheduler's only query: which schedules are due. Partial, because a
-- disabled schedule is never due and there is no reason to carry it in the
-- index the loop hits every minute.
create index if not exists idx_discovery_schedules_due
  on public.discovery_schedules (next_run_at)
  where is_enabled;

alter table public.discovery_schedules enable row level security;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'grant select, insert, update, delete on public.discovery_schedules to authenticated';
  end if;
exception when others then
  raise notice 'skipping grants: %', sqlerrm;
end
$$;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'discovery_schedules' and policyname = 'discovery_schedules_select'
  ) then
    create policy "discovery_schedules_select" on public.discovery_schedules
      for select to authenticated using (true);
  end if;
end
$$;

-- ── Reconciliation ─────────────────────────────────────────────────────────

-- "What was this endpoint serving last time" — one lookup per endpoint scanned,
-- so on a 254-address range this runs 254 times and cannot be a sequential scan.
create index if not exists idx_discovery_results_endpoint_history
  on public.discovery_results (host, port, scanned_at desc);

commit;
