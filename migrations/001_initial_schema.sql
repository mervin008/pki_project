-- CertPilot Initial Schema
-- PostgreSQL 17 / Supabase Migration

-- 1. Helper function for RBAC role checking
create or replace function public.get_user_role()
returns text
language sql
security invoker
set search_path = ''
stable
as $$
  select coalesce(
    auth.jwt() -> 'app_metadata' ->> 'certpilot_role',
    'viewer'
  );
$$;

-- 2. CA Accounts (Gateway Connection Configurations)
create table if not exists public.ca_accounts (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  provider_type text not null check (provider_type in ('acme', 'vault', 'selfsigned', 'gcp_cas', 'aws_pca', 'digicert', 'sectigo', 'step_ca')),
  gateway_addr text not null,        -- gRPC address: localhost:9091
  config_encrypted text,             -- Encrypted JSON
  is_default boolean default false,
  status text not null default 'DISCONNECTED' check (status in ('CONNECTED', 'DISCONNECTED', 'ERROR')),
  last_health_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_ca_accounts_created_by on public.ca_accounts(created_by);

-- 3. CA Authorities (Root, Intermediate, and Issuing CAs)
create table if not exists public.ca_authorities (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  ca_type text not null check (ca_type in ('ROOT', 'INTERMEDIATE', 'ISSUING')),
  subject_dn text not null,
  issuer_dn text not null,
  serial_number text,
  not_before timestamptz not null,
  not_after timestamptz not null,
  days_remaining int default 0,
  key_type text not null check (key_type in ('RSA', 'ECDSA', 'Ed25519')),
  key_size int not null,
  fingerprint_sha256 text not null unique,
  certificate_pem text not null,

  -- Chain
  parent_ca_id uuid references public.ca_authorities(id) on delete set null,

  -- Health monitoring
  crl_distribution_url text,
  ocsp_responder_url text,
  is_crl_fresh boolean default false,
  crl_last_checked timestamptz,
  is_ocsp_responsive boolean default false,
  ocsp_last_checked timestamptz,
  certificates_issued_count bigint default 0,

  -- Alerting
  alert_thresholds jsonb default '[365, 180, 90, 30, 14, 7]'::jsonb,
  last_alert_sent_at timestamptz,
  last_alert_threshold int,

  -- Status
  status text not null default 'UNKNOWN' check (status in ('HEALTHY', 'WARNING', 'CRITICAL', 'EXPIRED', 'UNKNOWN')),

  -- Provider link
  ca_account_id uuid references public.ca_accounts(id) on delete set null,

  tags jsonb default '[]'::jsonb,
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_ca_authorities_parent on public.ca_authorities(parent_ca_id);
create index if not exists idx_ca_authorities_status on public.ca_authorities(status);
create index if not exists idx_ca_authorities_not_after on public.ca_authorities(not_after);
create index if not exists idx_ca_authorities_ca_account on public.ca_authorities(ca_account_id);

-- 4. Deployment Targets (Where certs are installed)
create table if not exists public.deployment_targets (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  target_type text not null check (target_type in ('filesystem', 'aws_acm', 'kubernetes', 'webhook', 'gcp_lb', 'azure_kv')),
  config_encrypted text,
  last_deployment_at timestamptz,
  last_deployment_status text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_deployment_targets_created_by on public.deployment_targets(created_by);

-- 5. Certificates (Managed Inventory)
create table if not exists public.certificates (
  id uuid primary key default gen_random_uuid(),
  fingerprint_sha256 text not null unique,
  common_name text not null,
  sans jsonb default '[]'::jsonb,
  serial_number text,
  issuer_dn text,
  not_before timestamptz,
  not_after timestamptz,
  days_remaining int default 0,
  key_type text check (key_type in ('RSA', 'ECDSA', 'Ed25519')),
  key_size int,
  status text not null default 'PENDING' check (status in ('PENDING', 'ISSUED', 'EXPIRING', 'EXPIRED', 'REVOKED', 'RENEWAL_FAILED')),

  -- Automation
  auto_renew boolean default true,
  renewal_lead_days int default 30,
  last_renewal_attempt timestamptz,
  renewal_error text,
  renewal_count int default 0,

  -- Relationships
  ca_account_id uuid references public.ca_accounts(id) on delete set null,
  ca_authority_id uuid references public.ca_authorities(id) on delete set null,
  deployment_target_id uuid references public.deployment_targets(id) on delete set null,

  -- Storage
  private_key_encrypted text,
  certificate_pem text,
  chain_pem text,

  -- Provenance
  discovered_via text default 'MANUAL' check (discovered_via in ('MANUAL', 'SCAN', 'CT_LOG', 'IMPORT', 'REQUESTED')),

  -- Metadata
  environment text check (environment in ('production', 'staging', 'development')),
  team text,
  tags jsonb default '[]'::jsonb,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_certificates_status on public.certificates(status);
create index if not exists idx_certificates_not_after on public.certificates(not_after);
create index if not exists idx_certificates_ca_account on public.certificates(ca_account_id);
create index if not exists idx_certificates_ca_authority on public.certificates(ca_authority_id);
create index if not exists idx_certificates_deployment_target on public.certificates(deployment_target_id);
create index if not exists idx_certificates_created_by on public.certificates(created_by);
create index if not exists idx_certificates_common_name on public.certificates(common_name);

-- 6. Policies (Rules for key size, allowed CAs, etc.)
create table if not exists public.policies (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  is_enabled boolean default true,
  rule_type text not null check (rule_type in ('key_size', 'key_type', 'ca_restriction', 'max_lifetime', 'naming', 'approval_required')),
  rule_config jsonb not null,
  domain_pattern text,
  severity text default 'WARNING' check (severity in ('INFO', 'WARNING', 'BLOCK')),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_policies_created_by on public.policies(created_by);

-- 7. Notification Channels
create table if not exists public.notification_channels (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  channel_type text not null check (channel_type in ('email', 'slack', 'teams', 'webhook', 'pagerduty')),
  config_encrypted text,
  is_enabled boolean default true,
  last_sent_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_notification_channels_created_by on public.notification_channels(created_by);

-- 8. Audit Logs (Immutable)
create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  action text not null,
  entity_type text not null,
  entity_id uuid,
  actor_id uuid references auth.users(id) on delete set null,
  actor_email text,
  details jsonb,
  ip_address inet,
  created_at timestamptz not null default now()
);

create index if not exists idx_audit_logs_entity on public.audit_logs(entity_type, entity_id);
create index if not exists idx_audit_logs_actor on public.audit_logs(actor_id);
create index if not exists idx_audit_logs_created on public.audit_logs(created_at desc);

-- 9. Discovery Scans & Results
create table if not exists public.discovery_scans (
  id uuid primary key default gen_random_uuid(),
  scan_type text not null check (scan_type in ('network', 'ct_log', 'cloud')),
  targets jsonb not null,
  status text not null default 'PENDING' check (status in ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
  results_count int default 0,
  started_at timestamptz,
  completed_at timestamptz,
  error text,
  triggered_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_discovery_scans_triggered_by on public.discovery_scans(triggered_by);

create table if not exists public.discovery_results (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.discovery_scans(id) on delete cascade,
  host text not null,
  port int not null,
  common_name text,
  sans jsonb,
  issuer_dn text,
  not_after timestamptz,
  fingerprint_sha256 text,
  certificate_pem text,
  is_imported boolean default false,
  imported_certificate_id uuid references public.certificates(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_discovery_results_scan on public.discovery_results(scan_id);
create index if not exists idx_discovery_results_imported_cert on public.discovery_results(imported_certificate_id);

-- 10. Enable Row-Level Security on all tables
alter table public.ca_authorities enable row level security;
alter table public.ca_accounts enable row level security;
alter table public.certificates enable row level security;
alter table public.deployment_targets enable row level security;
alter table public.policies enable row level security;
alter table public.notification_channels enable row level security;
alter table public.audit_logs enable row level security;
alter table public.discovery_scans enable row level security;
alter table public.discovery_results enable row level security;

-- 11. Define RLS Policies
--
-- PostgreSQL has no `create policy if not exists`, and every other statement in
-- this file is idempotent. Without this the file can only ever be applied to a
-- virgin database: rerunning it against one where the schema already exists
-- fails on the first policy, rolls the whole script back, and reports a problem
-- that has nothing to do with what the operator was trying to change.
--
-- So this file is treated as the source of truth for the policies on the tables
-- it defines: whatever is there is dropped, and the declarations below are
-- reinstated. A policy added by hand outside this file will not survive a
-- rerun, which is the intended behaviour — the alternative is a database whose
-- access rules cannot be reproduced from the repository.
do $$
declare
  pol record;
begin
  for pol in
    select policyname, tablename
    from pg_policies
    where schemaname = 'public'
      and tablename in (
        'ca_authorities', 'ca_accounts', 'certificates', 'deployment_targets',
        'policies', 'notification_channels', 'audit_logs',
        'discovery_scans', 'discovery_results'
      )
  loop
    execute format('drop policy %I on public.%I', pol.policyname, pol.tablename);
  end loop;
end
$$;

create policy "certificates_select" on public.certificates for select to authenticated using (true);
create policy "certificates_insert" on public.certificates for insert to authenticated with check (public.get_user_role() in ('admin', 'operator'));
create policy "certificates_update" on public.certificates for update to authenticated using (public.get_user_role() in ('admin', 'operator')) with check (public.get_user_role() in ('admin', 'operator'));
create policy "certificates_delete" on public.certificates for delete to authenticated using (public.get_user_role() = 'admin');

create policy "ca_authorities_select" on public.ca_authorities for select to authenticated using (true);
create policy "ca_authorities_insert" on public.ca_authorities for insert to authenticated with check (public.get_user_role() in ('admin', 'operator'));
create policy "ca_authorities_update" on public.ca_authorities for update to authenticated using (public.get_user_role() in ('admin', 'operator')) with check (public.get_user_role() in ('admin', 'operator'));
create policy "ca_authorities_delete" on public.ca_authorities for delete to authenticated using (public.get_user_role() = 'admin');

create policy "ca_accounts_select" on public.ca_accounts for select to authenticated using (true);
create policy "ca_accounts_insert" on public.ca_accounts for insert to authenticated with check (public.get_user_role() in ('admin', 'operator'));
create policy "ca_accounts_update" on public.ca_accounts for update to authenticated using (public.get_user_role() in ('admin', 'operator')) with check (public.get_user_role() in ('admin', 'operator'));
create policy "ca_accounts_delete" on public.ca_accounts for delete to authenticated using (public.get_user_role() = 'admin');

create policy "deployment_targets_select" on public.deployment_targets for select to authenticated using (true);
create policy "deployment_targets_insert" on public.deployment_targets for insert to authenticated with check (public.get_user_role() in ('admin', 'operator'));
create policy "deployment_targets_update" on public.deployment_targets for update to authenticated using (public.get_user_role() in ('admin', 'operator')) with check (public.get_user_role() in ('admin', 'operator'));
create policy "deployment_targets_delete" on public.deployment_targets for delete to authenticated using (public.get_user_role() = 'admin');

create policy "policies_select" on public.policies for select to authenticated using (true);
create policy "policies_insert" on public.policies for insert to authenticated with check (public.get_user_role() in ('admin', 'operator'));
create policy "policies_update" on public.policies for update to authenticated using (public.get_user_role() in ('admin', 'operator')) with check (public.get_user_role() in ('admin', 'operator'));
create policy "policies_delete" on public.policies for delete to authenticated using (public.get_user_role() = 'admin');

create policy "notification_channels_select" on public.notification_channels for select to authenticated using (true);
create policy "notification_channels_insert" on public.notification_channels for insert to authenticated with check (public.get_user_role() = 'admin');
create policy "notification_channels_update" on public.notification_channels for update to authenticated using (public.get_user_role() = 'admin') with check (public.get_user_role() = 'admin');
create policy "notification_channels_delete" on public.notification_channels for delete to authenticated using (public.get_user_role() = 'admin');

create policy "audit_logs_select" on public.audit_logs for select to authenticated using (public.get_user_role() in ('admin', 'auditor', 'operator'));
create policy "audit_logs_insert" on public.audit_logs for insert to authenticated with check (true);

create policy "discovery_scans_select" on public.discovery_scans for select to authenticated using (true);
create policy "discovery_scans_insert" on public.discovery_scans for insert to authenticated with check (public.get_user_role() in ('admin', 'operator'));
create policy "discovery_scans_update" on public.discovery_scans for update to authenticated using (public.get_user_role() in ('admin', 'operator')) with check (public.get_user_role() in ('admin', 'operator'));
create policy "discovery_scans_delete" on public.discovery_scans for delete to authenticated using (public.get_user_role() = 'admin');

create policy "discovery_results_select" on public.discovery_results for select to authenticated using (true);
create policy "discovery_results_insert" on public.discovery_results for insert to authenticated with check (public.get_user_role() in ('admin', 'operator'));
create policy "discovery_results_update" on public.discovery_results for update to authenticated using (public.get_user_role() in ('admin', 'operator')) with check (public.get_user_role() in ('admin', 'operator'));
create policy "discovery_results_delete" on public.discovery_results for delete to authenticated using (public.get_user_role() = 'admin');

-- 12. Enable Realtime Publications
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'certificates') then
    alter publication supabase_realtime add table public.certificates;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'ca_authorities') then
    alter publication supabase_realtime add table public.ca_authorities;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'audit_logs') then
    alter publication supabase_realtime add table public.audit_logs;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'discovery_scans') then
    alter publication supabase_realtime add table public.discovery_scans;
  end if;
end $$;
