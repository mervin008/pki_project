-- 030_revocation.sql
--
-- Records that a certificate was revoked, and why.
--
-- Until now the core had no revocation route at all. All three gateways
-- implement RevokeCertificate and the status CHECK has permitted 'REVOKED'
-- since migration 001, but nothing could reach either — so the only way to get
-- rid of a certificate was DELETE /certificates/:id, which removed CertPilot's
-- record and left the certificate live at the CA, valid until its own notAfter.
--
-- That is the worst possible shape for this product. A compromised key is
-- exactly the case a PKI team reaches for this tool over, and the operation
-- that looked like it dealt with the problem was the one that made the problem
-- invisible: the certificate stopped appearing in the estate while continuing
-- to authenticate.
--
-- Three columns rather than the status alone, because "revoked" is not the
-- interesting part of the record. When and why are what an incident review
-- reads, and who did it is what the audit log has to be able to corroborate.

begin;

alter table public.certificates
  add column if not exists revoked_at timestamptz,
  -- RFC 5280 CRLReason. Stored as the integer the standard defines rather than
  -- a local string, because it is what goes on the CRL and into the OCSP
  -- response; a private vocabulary here would have to be mapped back at every
  -- boundary and would eventually be mapped wrongly at one.
  add column if not exists revocation_reason integer,
  -- The subject claim, matching every other actor column. Text since 028.
  add column if not exists revoked_by text;

-- The reasons ACME permits, which is the narrowest of the three gateways and
-- therefore the set that works everywhere. certificateHold (6) is deliberately
-- absent: it is reversible, nothing in CertPilot can lift a hold, and offering
-- it would let somebody believe they had suspended a certificate that this
-- system can never un-suspend.
alter table public.certificates
  drop constraint if exists certificates_revocation_reason_check;
alter table public.certificates
  add constraint certificates_revocation_reason_check
  check (revocation_reason is null or revocation_reason in (0, 1, 3, 4, 5, 9));

-- The two facts have to agree. A row marked REVOKED with no timestamp cannot
-- be reported honestly, and a row carrying a revocation timestamp while still
-- reading ISSUED is worse — it is the disagreement that makes somebody trust
-- the wrong one.
alter table public.certificates
  drop constraint if exists certificates_revocation_consistent;
alter table public.certificates
  add constraint certificates_revocation_consistent
  check ((status = 'REVOKED') = (revoked_at is not null));

-- Revoked certificates are read together: an incident review asks what was
-- revoked in a window, not whether one particular row was.
create index if not exists idx_certificates_revoked_at
  on public.certificates (revoked_at desc)
  where revoked_at is not null;

comment on column public.certificates.revocation_reason is
  'RFC 5280 CRLReason: 0 unspecified, 1 keyCompromise, 3 affiliationChanged, '
  '4 superseded, 5 cessationOfOperation, 9 privilegeWithdrawn.';

commit;
