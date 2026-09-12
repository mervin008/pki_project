-- 025_crypto_posture.sql
--
-- Migration 002 laid this schema in the first week of the project and nothing
-- has ever written to it. `certificates.signature_algorithm`,
-- `quantum_readiness_score`, the whole of `endpoint_tls_posture` — all present,
-- all null, for twenty-three migrations. This is the one that fills them.
--
-- What the columns are for is one distinction, and it is the one most
-- reporting on this subject gets backwards:
--
--   A classical signature is a problem in the 2030s. A classical key exchange
--   is a problem this afternoon.
--
-- Nobody forges a handshake that already happened, so an RSA-signed certificate
-- expiring in ninety days is not a quantum risk — it will be replaced many
-- times before a relevant quantum computer exists. But traffic protected by a
-- classical key exchange can be recorded today and decrypted whenever that
-- machine arrives, and the fix for that is already shipping in every current
-- browser.
--
-- Which is why the interesting table here is the one about *handshakes* rather
-- than the columns about certificates. An inventory can tell you what your
-- certificates are signed with. Only a real connection to a real server can
-- tell you what it negotiates.
--
-- **`offered_hybrid` is the load-bearing column**, and it looks like the least
-- important one. "This endpoint did not negotiate a post-quantum group" is a
-- finding about the server only if CertPilot offered one; if it did not, the
-- same row is a finding about CertPilot. Go enables X25519MLKEM768 by default
-- and that default could change in a release, so what was offered is recorded
-- per observation rather than assumed from the code that made it.
--

begin;

-- ── What a handshake actually did ──────────────────────────

alter table public.endpoint_tls_posture
  -- Whether CertPilot offered a post-quantum group at all. See the note above:
  -- without this the row cannot be read.
  add column if not exists offered_hybrid boolean not null default false,
  add column if not exists alpn text,
  -- The verdict and the sentence, stored rather than recomputed on read, so
  -- that a report of what an estate looked like in March does not silently
  -- change when the assessment rules improve.
  add column if not exists verdict text,
  add column if not exists summary text,
  add column if not exists requirements jsonb not null default '[]'::jsonb,
  add column if not exists scan_id uuid references public.discovery_scans(id) on delete set null;

create index if not exists idx_tls_posture_verdict
  on public.endpoint_tls_posture (verdict, observed_at desc);

-- ── What a certificate is made of ──────────────────────────

alter table public.certificates
  add column if not exists posture_verdict text,
  add column if not exists posture_summary text,
  add column if not exists posture_requirements jsonb not null default '[]'::jsonb;

create index if not exists idx_certificates_posture
  on public.certificates (posture_verdict)
  where posture_verdict is not null;

-- Migration 002 added a foreign key from certificates.key_type to
-- key_algorithms, NOT VALID, with a note to validate it when convenient. It is
-- still not convenient and is now actively unwanted: a certificate discovered
-- on somebody's appliance carrying an algorithm this table has never heard of
-- must still be recordable, because the whole point of finding it is that
-- nobody knew it was there. A scan that dropped rows it could not classify
-- would be a scan that hides exactly what it exists to surface.
--
-- Recorded here rather than left as a stale TODO in a file nobody reopens.
comment on constraint certificates_key_type_fkey on public.certificates is
  'Deliberately NOT VALID and deliberately never validated: an unrecognised algorithm found on a host must be recordable, or discovery hides what it exists to find.';

commit;
