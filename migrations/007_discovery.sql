-- 007_discovery.sql
--
-- Gives the discovery tables enough columns to answer the only question
-- discovery exists to answer.
--
-- Migration 001 created `discovery_scans` and `discovery_results` and nothing
-- has ever written to them. The columns it chose describe a certificate —
-- common name, issuer, expiry — which is what a scanner *finds*. But a central
-- PKI team scanning its own estate already knows about most of what comes back.
-- The finding worth waking someone for is the endpoint serving a certificate
-- that is in nobody's inventory, and 001 has no column that can express it.
--
-- So this migration adds three groups of columns:
--
--   1. **Verdicts** — `management_state` and `trust_state`. Whether CertPilot
--      already manages this certificate, and whether it chains to anything the
--      organisation trusts. These are what the results list is sorted and
--      filtered by; everything else on the row is evidence for them.
--
--   2. **The handshake** — TLS version, cipher suite, key exchange group, ALPN.
--      Recorded on every scan because it is the raw material for the
--      cryptographic-posture work, and because it cannot be recovered later:
--      the connection is gone, and a certificate on its own says nothing about
--      how it was negotiated. "142 of your endpoints do not negotiate
--      X25519MLKEM768" is a sentence that requires this column to have been
--      filled in months ago.
--
--   3. **Findings** — a jsonb array of what is wrong with the endpoint, each
--      with a code, a severity, and a sentence a human can act on. Kept as data
--      rather than derived at read time so that a result stays true to what was
--      observed at the moment of the scan, not to what today's rules would say
--      about a certificate that has since been replaced.
--
-- Every added column is nullable or defaulted, so this applies to a database
-- that already holds rows without rewriting them. In practice there are none:
-- nothing has ever written to these tables.
--

begin;

-- ── discovery_scans ────────────────────────────────────────────────────────

alter table public.discovery_scans
  -- Denormalised counts. A scan list is the first screen someone opens after
  -- a run, and it has to say "found 3 nobody knew about" without reading a
  -- thousand result rows to work it out.
  add column if not exists unmanaged_count  int not null default 0,
  add column if not exists managed_count    int not null default 0,
  -- Endpoints that did not answer. Counted rather than dropped: a scan that
  -- reached nothing at all and a scan that found nothing are the same empty
  -- results list, and only one of them means the estate is clean.
  add column if not exists unreachable_count int not null default 0,
  add column if not exists actor_email       text;

-- The scan list is always "most recent first". Without this it is a sort of
-- the whole table on every page load.
create index if not exists idx_discovery_scans_created
  on public.discovery_scans (created_at desc);

-- ── discovery_results ──────────────────────────────────────────────────────

alter table public.discovery_results
  -- Reachability. A row exists for every endpoint that was asked, including
  -- the ones that refused, so that "we looked and got nothing" is a recorded
  -- fact rather than an absence indistinguishable from never having looked.
  add column if not exists reachable boolean not null default true,
  add column if not exists error     text,

  -- The verdicts.
  add column if not exists management_state text not null default 'UNMANAGED'
    check (management_state in ('MANAGED', 'UNMANAGED', 'UNREACHABLE')),
  add column if not exists trust_state text not null default 'UNKNOWN'
    check (trust_state in ('PUBLIC', 'INTERNAL', 'SELF_SIGNED', 'UNTRUSTED', 'UNKNOWN')),
  -- The managed certificate this result matched, by fingerprint. Distinct from
  -- imported_certificate_id, which 001 already has: one records that we
  -- recognised the certificate, the other that someone chose to adopt it.
  add column if not exists matched_certificate_id uuid
    references public.certificates(id) on delete set null,

  -- Certificate detail 001 left out.
  add column if not exists subject_dn    text,
  add column if not exists serial_number text,
  add column if not exists not_before    timestamptz,
  add column if not exists key_type      text,
  add column if not exists key_size      int,
  add column if not exists is_ca         boolean not null default false,
  add column if not exists chain_pem     text,
  -- How many certificates the server actually sent. A server presenting only
  -- its leaf works in a browser that has cached the intermediate and fails on
  -- a fresh machine, which is why it is worth recording separately from the
  -- chain itself.
  add column if not exists chain_length int not null default 0,

  -- The handshake.
  add column if not exists tls_version  text,
  add column if not exists cipher_suite text,
  add column if not exists key_exchange text,
  add column if not exists alpn         text,

  -- Findings, newest schema wins: [{"code":…,"severity":…,"detail":…}, …].
  add column if not exists findings jsonb not null default '[]'::jsonb,
  add column if not exists scanned_at timestamptz not null default now();

-- The two questions asked of a result set, in the order they are asked:
-- "what did this scan find that we do not manage", then "have we seen this
-- certificate anywhere else".
create index if not exists idx_discovery_results_scan_state
  on public.discovery_results (scan_id, management_state);

create index if not exists idx_discovery_results_fingerprint
  on public.discovery_results (fingerprint_sha256)
  where fingerprint_sha256 is not null;

commit;
