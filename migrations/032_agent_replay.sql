-- 032: refuse a replayed agent request.
--
-- An agent request is authenticated by an Ed25519 signature over the method,
-- path, timestamp and a hash of the body, accepted within five minutes of that
-- timestamp. Nothing stopped the same request being sent twice. The security
-- document called that deliberate, on the grounds that the requests are
-- idempotent reports and a nonce table would add a write per heartbeat across a
-- fleet to prevent a replay that changes nothing.
--
-- That reasoning was right about heartbeats and wrong about the fleet API as a
-- whole. `POST /agent/certificates` issues a certificate. Replaying one
-- captured off the wire gets a second certificate signed for the same names —
-- against the CA's rate limit, into the certificate inventory, and for a public
-- CA into the CT logs. `POST /agent/deployments/claim` leases work. Neither is
-- a report and neither changes nothing.
--
-- There is no new header and no protocol version, because a nonce was already
-- being sent: Ed25519 is deterministic, so two identical requests carry
-- identical signatures, and the signature is unique to the method, path,
-- timestamp and body it covers. Storing the signature *is* the nonce store, and
-- it works with agents already deployed.
--
-- The row is written only after the signature verifies. Writing first would let
-- anybody who can reach the endpoint fill this table with unsigned garbage,
-- which turns a replay defence into a way to exhaust the disk.

begin;

create table if not exists public.agent_request_signatures (
  agent_id uuid not null references public.agents(id) on delete cascade,

  -- SHA-256 of the signature header, not the signature itself. Fixed width for
  -- the index, and there is nothing to gain from storing the original: this
  -- column is only ever compared for equality.
  signature_hash bytea not null,

  -- The instant after which this row cannot possibly be needed, being the
  -- request's own timestamp plus the tolerance window. Past it the timestamp
  -- check refuses the request on its own, so the row is pure overhead and the
  -- sweep can drop it.
  expires_at timestamptz not null,

  primary key (agent_id, signature_hash)
);

-- The sweep's index. Deliberately not on (expires_at) alone across the whole
-- table — this is the only query that reads by expiry, and it reads in order.
create index if not exists idx_agent_request_signatures_expiry
  on public.agent_request_signatures (expires_at);

commit;
