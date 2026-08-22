-- 026_gateway_authorities.sql
--
-- `GetCAInfo` has been in the gateway contract since the first proto file and
-- nothing has ever called it. The Vault gateway is the first CA that can
-- actually answer it — a PKI mount will name its issuers, hand over their
-- certificates and say when they expire — and until the core writes that down,
-- the answer goes nowhere.
--
-- Which leaves the inventory the wrong way round. CertPilot tracks the
-- certificates and monitors, alerts and renews them; the CA that signed all of
-- them is the one whose expiry takes the estate down at once, and it was
-- visible only for as long as somebody was looking at an account validation
-- screen.
--
-- Two columns, because importing raises two questions the existing schema
-- cannot answer:
--
-- `source` — whether a row was registered by a person or discovered through a
-- gateway. The importer refreshes what a certificate says about itself and must
-- never touch what an operator decided: the name they gave it, the thresholds
-- they tuned, the team they put on it. Knowing which rows it created is how it
-- stays out of the way of the ones it did not.
--
-- `last_seen_at` — when a gateway last reported this CA as one of its issuers.
-- A rotated-out issuer is not deleted, and deleting it would be wrong: it
-- signed certificates that are still being served, and its expiry is still the
-- date those stop working. But "Vault no longer offers this issuer" and "this
-- CA is current" are different facts, and a row that cannot tell them apart
-- will be read as the second one.
begin;

alter table public.ca_authorities
  add column if not exists source text not null default 'MANUAL';

alter table public.ca_authorities
  add column if not exists last_seen_at timestamptz;

-- Guarded rather than written as ADD CONSTRAINT IF NOT EXISTS, which PostgreSQL
-- does not have. Migration 002 learned this the expensive way: it was not
-- rerunnable for twenty-three migrations, and nothing noticed until a
-- conformance suite applied the whole schema twice.
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'ca_authorities_source_check'
  ) then
    alter table public.ca_authorities
      add constraint ca_authorities_source_check
      check (source in ('MANUAL', 'GATEWAY'));
  end if;
end
$$;

comment on column public.ca_authorities.source is
  'MANUAL: registered by a person, and the importer only ever refreshes facts derived from the certificate itself. GATEWAY: discovered by asking a CA account''s gateway for its issuers.';

comment on column public.ca_authorities.last_seen_at is
  'When a gateway last reported this CA among its issuers. Null on a hand-registered row. An old value means the CA has been rotated out of the mount it came from — it is not deleted, because it signed certificates that are still being served.';

commit;
