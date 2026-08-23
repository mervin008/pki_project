-- 010_ct_monitoring.sql
--
-- Watches Certificate Transparency for certificates issued in your name.
--
-- Network scanning answers "what is being served on the addresses I told you
-- about". Certificate Transparency answers a different and larger question:
-- **what has been issued for our domains at all** — by any CA, to anyone,
-- whether or not it was ever deployed, whether or not the endpoint is reachable
-- from CertPilot, whether or not anyone here knows the machine exists.
--
-- A developer who obtained a certificate for `api.corp.example.com` with a
-- personal ACME account appears in no scan of any range. They appear in CT
-- within minutes, because every publicly-trusted CA is required to log there
-- and browsers reject certificates that are not.
--
-- Two tables.
--
-- **`ct_monitors`** — the domains being watched. Note the two timestamps:
-- `last_checked_at` is when a check was last *attempted*, `last_success_at`
-- when one last *answered*. Collapsing them is the failure this whole product
-- exists to prevent, in miniature: a monitor that has been unable to reach the
-- log for a week would otherwise look exactly like a monitor that has found
-- nothing for a week, and one of those means you are not being told about
-- certificates issued in your name.
--
-- **`ct_certificates`** — what the logs reported. Each carries the same verdict
-- a scan result does: managed, or not. `UNMANAGED` here is a stronger signal
-- than on a scan — a certificate valid for your domain exists, somebody holds
-- its private key, and nothing in this system issued it.
--
-- Applies to plain PostgreSQL as well as Supabase.

begin;

create table if not exists public.ct_monitors (
  id uuid primary key default gen_random_uuid(),
  domain text not null,
  -- Whether `*.example.com` is watched alongside `example.com`. On by default:
  -- the subdomain nobody registered is the one worth finding.
  include_subdomains boolean not null default true,
  is_enabled boolean not null default true,

  -- Minutes between checks. The floor is enforced in the application, and it
  -- is higher than a scan's: the logs are queried through a free community
  -- service, and polling it hard is how everyone loses access to it.
  check_interval_minutes int not null default 360 check (check_interval_minutes > 0),

  -- Attempted, versus answered. See the note above; this split is the point.
  last_checked_at timestamptz,
  last_success_at timestamptz,
  next_check_at   timestamptz,
  last_error      text,

  -- The newest log entry already seen, so a later check asks for what is new
  -- rather than re-reading years of history every time.
  last_entry_id bigint,
  -- Running totals, so a list of monitors can say which one is finding things
  -- without counting rows behind it.
  certificates_seen     int not null default 0,
  unmanaged_seen        int not null default 0,

  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint ct_monitors_domain_unique unique (domain)
);

create index if not exists idx_ct_monitors_due
  on public.ct_monitors (next_check_at)
  where is_enabled;

create table if not exists public.ct_certificates (
  id uuid primary key default gen_random_uuid(),
  monitor_id uuid not null references public.ct_monitors(id) on delete cascade,

  -- The log entry this came from. Unique per monitor so a re-check that
  -- overlaps the previous window does not report the same certificate twice.
  entry_id bigint,
  logged_at timestamptz,

  -- Identity. A certificate is identified by issuer and serial; the SHA-256
  -- fingerprint is not in the log index, so serial is what inventory is
  -- matched on.
  serial_number text,
  issuer_dn     text,
  common_name   text,
  sans          jsonb not null default '[]'::jsonb,
  not_before    timestamptz,
  not_after     timestamptz,

  -- Whether CertPilot issued or already knows about it.
  management_state text not null default 'UNMANAGED'
    check (management_state in ('MANAGED', 'UNMANAGED')),
  matched_certificate_id uuid references public.certificates(id) on delete set null,

  -- A precertificate and its final certificate are two log entries for one
  -- certificate. Recorded rather than filtered out, because "this was
  -- pre-logged then issued" is real information, but flagged so a count of
  -- findings is not silently doubled.
  is_precertificate boolean not null default false,

  first_seen_at timestamptz not null default now(),
  created_at    timestamptz not null default now(),

  constraint ct_certificates_entry_unique unique (monitor_id, entry_id)
);

create index if not exists idx_ct_certificates_monitor_state
  on public.ct_certificates (monitor_id, management_state);

create index if not exists idx_ct_certificates_serial
  on public.ct_certificates (serial_number)
  where serial_number is not null;

alter table public.ct_monitors enable row level security;
alter table public.ct_certificates enable row level security;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    execute 'grant select, insert, update, delete on public.ct_monitors to authenticated';
    execute 'grant select, insert, update, delete on public.ct_certificates to authenticated';
  end if;
exception when others then
  raise notice 'skipping grants: %', sqlerrm;
end
$$;

do $$
begin
  if not exists (select 1 from pg_policies
                 where schemaname = 'public' and tablename = 'ct_monitors'
                   and policyname = 'ct_monitors_select') then
    create policy "ct_monitors_select" on public.ct_monitors for select to authenticated using (true);
  end if;
  if not exists (select 1 from pg_policies
                 where schemaname = 'public' and tablename = 'ct_certificates'
                   and policyname = 'ct_certificates_select') then
    create policy "ct_certificates_select" on public.ct_certificates for select to authenticated using (true);
  end if;
end
$$;

commit;
