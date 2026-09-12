-- 006_ownership_and_acknowledgement.sql
--
-- Answers two questions the dashboard cannot currently answer about a CA in
-- trouble: **who owns this**, and **has anyone already looked at it**.
--
-- Without the second one, an alerting dashboard becomes wallpaper within a
-- month. The same red row is on the screen every morning, nobody can tell
-- whether it is being handled, and the team stops reading it — which is the
-- exact failure state CertPilot exists to prevent, arrived at by a different
-- route.
--
-- The governing rule, and the reason this is not simply a "dismiss" button:
--
--   **Silencing suppresses delivery, never display.**
--
-- An acknowledged CA still appears on the dashboard and in the wall view,
-- marked as acknowledged and by whom. Hiding a problem because someone clicked
-- a button is how CAs expire in organisations that believed they were
-- monitoring them. What acknowledgement buys is quiet in Slack, not a clean
-- screen.

begin;

-- ── Ownership ────────────────────────────────────────────
--
-- Recorded on the authority rather than in a separate table: a CA has one
-- owning team, the dashboard reads it on every row, and a join for two text
-- columns buys nothing. Both are free text on purpose — team names and
-- distribution lists do not live in CertPilot, and a foreign key to something
-- it does not own would mean either an import step or a wrong answer.

alter table public.ca_authorities
  add column if not exists owner_team text;

alter table public.ca_authorities
  add column if not exists owner_email text;

-- Answering "what does this team own" is the question asked during a handover
-- or an incident, and it is asked of the whole estate at once.
create index if not exists idx_ca_authorities_owner_team
  on public.ca_authorities(owner_team)
  where owner_team is not null;

-- ── Acknowledgement ──────────────────────────────────────
--
-- One row per (entity, threshold) acknowledgement, appended rather than
-- updated. Who acknowledged what and when is exactly the record an incident
-- review needs, and an UPDATE would overwrite it with whoever clicked last.
create table if not exists public.alert_acknowledgements (
  id uuid primary key default gen_random_uuid(),

  entity_type text not null check (entity_type in ('ca_authority', 'certificate')),
  entity_id uuid not null,

  -- The expiry threshold this acknowledgement covers, in days.
  --
  -- This is the field that makes acknowledgement safe. Acknowledging a CA at
  -- its 30-day threshold must NOT silence the 7-day one: the situation has
  -- materially worsened, and the earlier "yes, we know" was an answer to a
  -- different question. Null means the acknowledgement is not tied to a
  -- threshold at all and covers whatever is current.
  threshold integer,

  acknowledged_by uuid,
  acknowledged_by_email text,
  acknowledged_at timestamptz not null default now(),

  -- Why it is acknowledged. The single most useful field here: "replacement
  -- issued, cutover Thursday" turns a red row from an unanswered alarm into a
  -- status, and is what stops the next person re-investigating it.
  note text,

  -- Suppress *delivery* until this instant. Null means acknowledged but not
  -- silenced — the alert stops being new, but still goes out.
  silence_until timestamptz,

  -- Set when an acknowledgement is explicitly withdrawn, so the record of it
  -- having been made survives. A CA that was acknowledged in error and then
  -- un-acknowledged is a thing an incident review wants to see, not a row that
  -- quietly disappeared.
  revoked_at timestamptz,
  revoked_by uuid,

  created_at timestamptz not null default now()
);

-- The dispatcher asks "is this entity acknowledged right now" on the delivery
-- path, so it has to be one index hit and not a scan.
create index if not exists idx_alert_ack_entity
  on public.alert_acknowledgements(entity_type, entity_id, acknowledged_at desc);

-- "What is currently silenced" — for the dashboard, and for anyone asking why
-- an alert they expected never arrived.
create index if not exists idx_alert_ack_silenced
  on public.alert_acknowledgements(silence_until)
  where silence_until is not null and revoked_at is null;

commit;
