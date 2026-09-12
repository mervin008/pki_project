-- 016_renewal_verification.sql
--
-- A renewal is not done when the certificate is stored. It is done when the
-- thing serving it is serving it.
--
-- Until now a successful renewal wrote a new certificate, incremented the
-- count, set the status to ISSUED, and published "certificate renewed". All of
-- which can be true while the server in front of the users is still presenting
-- the old certificate — and still expiring on the old certificate's schedule.
--
-- That is the sharpest possible version of the failure this product exists to
-- prevent, produced by this product: a green dashboard over an expiring estate.
-- The inventory says ninety days remaining. The endpoint says twenty.
--
-- CertPilot does not deploy anything yet (that is phase 6), so "renewed but not
-- deployed" is not an edge case here, it is the normal state. Reporting it is
-- the difference between a renewal engine and a renewal engine somebody can
-- trust.
--
-- The endpoints checked are the ones **discovery has actually observed serving
-- this certificate**. Not the SANs: probing hostnames read out of certificate
-- data would have CertPilot making outbound connections nobody asked for, to
-- names that may not resolve to anything it should be touching. When discovery
-- has never seen a certificate anywhere, that is recorded honestly as
-- NO_ENDPOINTS rather than guessed at — "we cannot verify this" is a useful
-- sentence and a fabricated verification is not.
--

begin;

alter table public.certificates
  -- PENDING   — renewed, inside the grace period before the first check
  -- VERIFIED  — every endpoint known to serve this certificate serves the new one
  -- STALE     — an endpoint is still serving the certificate this replaced
  -- UNREACHABLE — endpoints are known and none of them answered
  -- NO_ENDPOINTS — discovery has never observed this certificate being served
  add column if not exists verification_state text
    check (verification_state is null or verification_state in
      ('PENDING', 'VERIFIED', 'STALE', 'UNREACHABLE', 'NO_ENDPOINTS')),

  -- When the next check may run. Set on a successful renewal to now plus a
  -- grace period, because a deployment that happens by hand does not happen in
  -- the same second as the issuance.
  add column if not exists verify_after timestamptz,
  add column if not exists last_verified_at timestamptz,
  add column if not exists verification_attempts int not null default 0,
  -- A sentence naming the endpoints and what they were serving, so the state
  -- does not have to be interpreted from a code.
  add column if not exists verification_detail text,
  -- The fingerprint this certificate replaced, captured at renewal.
  --
  -- This is what makes "still serving the old one" distinguishable from "some
  -- other certificate is here" — and the second is a different problem, worth
  -- different words.
  add column if not exists previous_fingerprint text;

create index if not exists idx_certificates_verify_due
  on public.certificates (verify_after)
  where verify_after is not null;

commit;
