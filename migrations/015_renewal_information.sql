-- 015_renewal_information.sql
--
-- Lets the CA say when to renew, and lets it change its mind.
--
-- RFC 9773 (ACME Renewal Information) has the CA publish a window during which
-- it would like each certificate replaced. The ACME gateway has read those
-- windows since phase 2. Nothing in the core has ever acted on one, so the
-- advice was fetched, logged, and thrown away.
--
-- Two reasons it matters, and they are not equally interesting.
--
-- Routinely, it lets the CA spread renewal load. A lead time of thirty days
-- means every certificate issued in the same week renews in the same week
-- forever; a window the client picks a random instant inside of breaks that up.
--
-- In an incident, it is the only automated warning you get. When a CA has to
-- revoke certificates in bulk — a CAA rechecking bug, a mis-issued
-- intermediate, a compromised validation path — it pulls the affected renewal
-- windows into the past. Clients that read ARI replace their certificates
-- within hours. Clients that do not find out by email, if the address on the
-- account is still someone's, and otherwise find out when the certificate stops
-- working.
--
-- `renewal_scheduled_at` is the instant this certificate should be renewed,
-- chosen at random inside the window rather than at its start. That randomness
-- is the point of the window and not an implementation detail: if every client
-- renewed at the start, ARI would move the thundering herd rather than disperse
-- it.
--
-- `ari_supported` is deliberately three-valued. NULL means nobody has asked
-- yet; false means the CA was asked and does not publish renewal information.
-- Collapsing those would make a CA that has never been checked look identical
-- to one that has nothing to say, which is the same mistake as a monitor with
-- one timestamp.
--

begin;

alter table public.certificates
  -- When to renew, whoever decided it. Null means nobody has been told
  -- anything and the lead time applies.
  add column if not exists renewal_scheduled_at timestamptz,

  add column if not exists ari_window_start timestamptz,
  add column if not exists ari_window_end   timestamptz,
  -- The CA's link to a human-readable explanation. Set when a window has been
  -- brought forward, which is exactly when somebody wants to know why.
  add column if not exists ari_explanation_url text,
  add column if not exists ari_checked_at   timestamptz,
  -- From the CA's own Retry-After. Polling harder than asked is how a client
  -- gets rate limited off the endpoint that would have warned it.
  add column if not exists ari_next_check_at timestamptz,
  -- NULL: never asked. false: asked, and this CA does not publish it.
  add column if not exists ari_supported boolean;

-- The renewal sweep reads this on every pass.
create index if not exists idx_certificates_renewal_scheduled
  on public.certificates (renewal_scheduled_at)
  where auto_renew and renewal_scheduled_at is not null;

-- The ARI poller's own queue.
create index if not exists idx_certificates_ari_due
  on public.certificates (ari_next_check_at)
  where auto_renew;

commit;
