-- 002_crypto_agility.sql
--
-- Removes the hardcoded algorithm allow-lists and adds the columns needed to
-- report cryptographic posture.
--
-- The original schema pinned key_type to ('RSA', 'ECDSA', 'Ed25519'). That
-- constraint is precisely what blocks ML-DSA, SLH-DSA, and composite
-- certificates, so it has to go before any post-quantum work can land — and it
-- is far cheaper to change now than once there are rows to migrate.
--
-- Nothing here removes data. Existing rows keep their key_type values and
-- acquire sensible defaults for the new columns.

begin;

-- ── Algorithm reference table ────────────────────────────────────────────
--
-- A table rather than an enum or a CHECK constraint: new algorithms arrive by
-- insert, and adding one must not require a migration or an application
-- deploy. Composite and hybrid schemes are first-class rather than special
-- cases, because a certificate carrying two signatures is the expected shape
-- of the transition, not an exception to it.

create table if not exists key_algorithms (
  name text primary key,
  family text not null check (family in ('classical', 'post_quantum', 'composite')),
  -- Whether this algorithm is believed to resist a cryptographically relevant
  -- quantum computer.
  quantum_resistant boolean not null default false,
  -- NIST security category (1-5) for post-quantum algorithms; null otherwise.
  nist_level int,
  -- Set when an algorithm should no longer be used for new issuance.
  deprecated boolean not null default false,
  notes text
);

insert into key_algorithms (name, family, quantum_resistant, nist_level, deprecated, notes) values
  -- Classical.
  ('RSA',      'classical', false, null, false, 'Key size carries the strength; below 2048 bits is not acceptable'),
  ('ECDSA',    'classical', false, null, false, 'P-256, P-384, P-521'),
  ('Ed25519',  'classical', false, null, false, 'Not issued by publicly trusted CAs today; usable in private PKI'),
  ('DSA',      'classical', false, null, true,  'Deprecated; retained only so discovered legacy certificates can be recorded'),

  -- Post-quantum signatures (FIPS 204 / FIPS 205).
  ('ML-DSA-44',    'post_quantum', true, 2, false, 'FIPS 204, formerly Dilithium2'),
  ('ML-DSA-65',    'post_quantum', true, 3, false, 'FIPS 204, formerly Dilithium3'),
  ('ML-DSA-87',    'post_quantum', true, 5, false, 'FIPS 204, formerly Dilithium5'),
  ('SLH-DSA-128s', 'post_quantum', true, 1, false, 'FIPS 205, hash-based; large signatures, very conservative assumptions'),
  ('SLH-DSA-192s', 'post_quantum', true, 3, false, 'FIPS 205'),
  ('SLH-DSA-256s', 'post_quantum', true, 5, false, 'FIPS 205'),
  ('Falcon-512',   'post_quantum', true, 1, false, 'FN-DSA, standardization pending'),
  ('Falcon-1024',  'post_quantum', true, 5, false, 'FN-DSA, standardization pending'),

  -- Composite: a classical and a post-quantum signature in one certificate,
  -- so the certificate stays valid to verifiers that understand only one.
  ('ECDSA-P256+ML-DSA-44', 'composite', true, 2, false, 'Composite signature, IETF LAMPS'),
  ('ECDSA-P384+ML-DSA-65', 'composite', true, 3, false, 'Composite signature, IETF LAMPS'),
  ('RSA3072+ML-DSA-44',    'composite', true, 2, false, 'Composite signature, IETF LAMPS')
on conflict (name) do nothing;

-- ── Drop the algorithm allow-lists ───────────────────────────────────────

alter table certificates   drop constraint if exists certificates_key_type_check;
alter table ca_authorities drop constraint if exists ca_authorities_key_type_check;

-- Referential integrity replaces the CHECK constraint: still validated, but now
-- extensible without a schema change.
-- Guarded on the catalogue rather than written plainly, because PostgreSQL has
-- no `add constraint if not exists` and every migration in this project is
-- meant to be rerunnable — a rule migration 001 states and this file broke on
-- the day it was written. Applying it to an already-migrated database failed
-- here and rolled back the whole file.
--
-- Nothing ever noticed, because the migrator records what it has applied and
-- never re-applies it. What this actually protects is the person running the
-- SQL by hand against a database that already has the schema, which is exactly
-- the situation migration 001's own note was written about.
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'certificates_key_type_fkey') then
    alter table certificates
      add constraint certificates_key_type_fkey
      foreign key (key_type) references key_algorithms(name)
      on update cascade
      not valid;
  end if;

  if not exists (select 1 from pg_constraint where conname = 'ca_authorities_key_type_fkey') then
    alter table ca_authorities
      add constraint ca_authorities_key_type_fkey
      foreign key (key_type) references key_algorithms(name)
      on update cascade
      not valid;
  end if;
end
$$;

-- NOT VALID means existing rows are not checked on creation, so this cannot
-- fail against a populated table. New and updated rows are checked from now on.
-- Validate separately when convenient:
--   alter table certificates validate constraint certificates_key_type_fkey;

-- ── Cryptographic posture columns ────────────────────────────────────────
--
-- These are what a CBOM export and a quantum-readiness score are built from.
-- The signature algorithm matters independently of the key algorithm: a
-- certificate can carry an ECDSA key signed with SHA-1, and only one of those
-- two facts is visible from key_type.

alter table certificates
  add column if not exists signature_algorithm text,
  add column if not exists public_key_algorithm text,
  -- Quantum readiness, 0-100. Null until the certificate has been assessed.
  add column if not exists quantum_readiness_score int
    check (quantum_readiness_score is null or quantum_readiness_score between 0 and 100),
  add column if not exists quantum_assessed_at timestamptz;

alter table ca_authorities
  add column if not exists signature_algorithm text,
  add column if not exists public_key_algorithm text;

-- ── Observed TLS posture ─────────────────────────────────────────────────
--
-- Recorded during discovery, which already completes a TLS handshake. The
-- negotiated key exchange group is the single most useful post-quantum signal
-- available today: hybrid key exchange (X25519MLKEM768) is what protects
-- traffic against harvest-now-decrypt-later, and unlike PQC signatures it is
-- deployed and observable right now.

create table if not exists endpoint_tls_posture (
  id uuid primary key default gen_random_uuid(),
  host text not null,
  port int not null,
  certificate_id uuid references certificates(id) on delete set null,

  tls_version text,
  cipher_suite text,
  -- The negotiated key exchange group, e.g. 'X25519MLKEM768' or 'x25519'.
  key_exchange_group text,
  -- True when the negotiated group is a post-quantum hybrid.
  hybrid_key_exchange boolean not null default false,

  supports_tls13 boolean,
  observed_at timestamptz not null default now(),

  unique (host, port)
);

create index if not exists idx_tls_posture_hybrid on endpoint_tls_posture(hybrid_key_exchange);
create index if not exists idx_tls_posture_observed on endpoint_tls_posture(observed_at desc);

-- ── Reporting view ───────────────────────────────────────────────────────
--
-- The question a team actually asks — "what breaks when the algorithms change,
-- and how long do I have?" — answered directly rather than assembled by every
-- caller.

create or replace view certificate_crypto_posture as
select
  c.id,
  c.common_name,
  c.key_type,
  c.key_size,
  c.signature_algorithm,
  c.not_after,
  c.environment,
  c.team,
  coalesce(a.quantum_resistant, false) as quantum_resistant,
  a.family as algorithm_family,
  a.deprecated as algorithm_deprecated,
  case
    when a.quantum_resistant then 'ready'
    when c.key_type = 'RSA' and c.key_size < 2048 then 'critical'
    when a.deprecated then 'critical'
    else 'classical'
  end as posture,
  p.hybrid_key_exchange,
  p.key_exchange_group,
  p.tls_version
from certificates c
left join key_algorithms a on a.name = c.key_type
left join endpoint_tls_posture p on p.certificate_id = c.id;

comment on view certificate_crypto_posture is
  'Per-certificate cryptographic posture: algorithm family, quantum resistance, and observed TLS key exchange. Backs CBOM export and readiness reporting.';

commit;
