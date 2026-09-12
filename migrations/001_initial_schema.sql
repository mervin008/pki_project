-- CertPilot Initial Schema
-- PostgreSQL 17

-- 1. CA Accounts (Gateway Connection Configurations)
create table if not exists public.ca_accounts (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  provider_type text not null check (provider_type in ('acme', 'vault', 'selfsigned', 'gcp_cas', 'aws_pca', 'digicert', 'sectigo', 'step_ca')),
  gateway_addr text not null,        -- gRPC address: localhost:9091
  config_encrypted text,             -- Encrypted JSON
  is_default boolean default false,
  status text not null default 'DISCONNECTED' check (status in ('CONNECTED', 'DISCONNECTED', 'ERROR')),
  last_health_at timestamptz,
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_ca_accounts_created_by on public.ca_accounts(created_by);

-- 2. CA Authorities (Root, Intermediate, and Issuing CAs)
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

-- 3. Deployment Targets (Where certs are installed)
create table if not exists public.deployment_targets (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  target_type text not null check (target_type in ('filesystem', 'aws_acm', 'kubernetes', 'webhook', 'gcp_lb', 'azure_kv')),
  config_encrypted text,
  last_deployment_at timestamptz,
  last_deployment_status text,
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_deployment_targets_created_by on public.deployment_targets(created_by);

-- 4. Certificates (Managed Inventory)
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
  created_by uuid,
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

-- 5. Policies (Rules for key size, allowed CAs, etc.)
create table if not exists public.policies (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  is_enabled boolean default true,
  rule_type text not null check (rule_type in ('key_size', 'key_type', 'ca_restriction', 'max_lifetime', 'naming', 'approval_required')),
  rule_config jsonb not null,
  domain_pattern text,
  severity text default 'WARNING' check (severity in ('INFO', 'WARNING', 'BLOCK')),
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_policies_created_by on public.policies(created_by);

-- 6. Notification Channels
create table if not exists public.notification_channels (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  channel_type text not null check (channel_type in ('email', 'slack', 'teams', 'webhook', 'pagerduty')),
  config_encrypted text,
  is_enabled boolean default true,
  last_sent_at timestamptz,
  created_by uuid,
  created_at timestamptz not null default now()
);

create index if not exists idx_notification_channels_created_by on public.notification_channels(created_by);

-- 7. Audit Logs (Immutable)
create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  action text not null,
  entity_type text not null,
  entity_id uuid,
  actor_id uuid,
  actor_email text,
  details jsonb,
  ip_address inet,
  created_at timestamptz not null default now()
);

create index if not exists idx_audit_logs_entity on public.audit_logs(entity_type, entity_id);
create index if not exists idx_audit_logs_actor on public.audit_logs(actor_id);
create index if not exists idx_audit_logs_created on public.audit_logs(created_at desc);

-- 8. Discovery Scans & Results
create table if not exists public.discovery_scans (
  id uuid primary key default gen_random_uuid(),
  scan_type text not null check (scan_type in ('network', 'ct_log', 'cloud')),
  targets jsonb not null,
  status text not null default 'PENDING' check (status in ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
  results_count int default 0,
  started_at timestamptz,
  completed_at timestamptz,
  error text,
  triggered_by uuid,
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
