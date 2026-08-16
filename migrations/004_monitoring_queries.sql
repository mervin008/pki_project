-- 004_monitoring_queries.sql
--
-- Makes the monitoring data queryable rather than merely stored.
--
-- Everything the CA health sweep records has been reaching the audit log since
-- migration 001, but there was no way to ask for it: `ListAuditLogs` took only
-- a limit and an offset, so retrieving CA expiry alerts meant paging through
-- every certificate issued that day and filtering in Go. This migration adds
-- the index that makes filtering by action cheap, and gives notification
-- channels the two columns they need to decide what is worth sending.
--
-- Applies to plain PostgreSQL as well as Supabase: nothing here references
-- auth.users or auth.jwt().

begin;

-- ── Audit log: query by action ──────────────────────────────
--
-- The leading column is `action` because that is the equality predicate;
-- `created_at desc` follows so the ordering comes from the index rather than a
-- sort. Postgres can also read this index backwards, so `created_at asc` costs
-- nothing extra.
--
-- This is the only index in this migration. `ca_authorities` holds tens of rows
-- in the deployments this targets, where a sequential scan beats an index
-- lookup — an index on `status` or `not_after` there would be cargo cult.
-- `audit_logs` is the table that actually grows.
create index if not exists idx_audit_logs_action_created
  on public.audit_logs (action, created_at desc);

-- ── Notification channels: routing rules ────────────────────
--
-- Without these two columns a channel is all-or-nothing, and a channel that
-- pages someone for every routine renewal gets muted within a week — after
-- which the CA expiry alert it also carries reaches nobody. Being able to say
-- "this channel gets CRITICAL only" is what keeps the important messages
-- deliverable.

-- Created here as well as in 001 so this migration stands alone. 001 is
-- Supabase-only (it references auth.users); anyone on plain PostgreSQL gets a
-- usable table from this file.
create table if not exists public.notification_channels (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  channel_type text not null,
  config_encrypted text,
  is_enabled boolean default true,
  last_sent_at timestamptz,
  created_by uuid,
  created_at timestamptz not null default now()
);

-- Minimum severity this channel will deliver. INFO means everything.
alter table public.notification_channels
  add column if not exists severity_threshold text not null default 'WARNING';

-- Event topics this channel accepts, as a JSON array of strings. An empty
-- array means every topic — the useful default, because a channel that
-- silently matches nothing is indistinguishable from one that is working.
alter table public.notification_channels
  add column if not exists topics jsonb not null default '[]'::jsonb;

alter table public.notification_channels
  add column if not exists updated_at timestamptz not null default now();

alter table public.notification_channels
  drop constraint if exists notification_channels_severity_threshold_check;
alter table public.notification_channels
  add constraint notification_channels_severity_threshold_check
  check (severity_threshold in ('INFO', 'WARNING', 'CRITICAL'));

alter table public.notification_channels
  drop constraint if exists notification_channels_topics_is_array;
alter table public.notification_channels
  add constraint notification_channels_topics_is_array
  check (jsonb_typeof(topics) = 'array');

-- 001 permitted 'teams' and 'pagerduty'. Neither is implemented and neither is
-- planned, and a channel of a type nothing can deliver is worse than no channel
-- at all: it looks configured on the dashboard and silently drops every alert
-- routed to it. Narrow the constraint to the types that have a notifier.
alter table public.notification_channels
  drop constraint if exists notification_channels_channel_type_check;
alter table public.notification_channels
  add constraint notification_channels_channel_type_check
  check (channel_type in ('email', 'slack', 'webhook'));

alter table public.notification_channels enable row level security;

commit;
