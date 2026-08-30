-- 033: record what the OCSP responder actually said.
--
-- `is_ocsp_responsive` was set by a bare GET to the responder's base URL, with
-- the result taken to be healthy if the status code was under 500. That is not
-- an OCSP request — there is no request in it at all — and a real responder
-- answers it with 400. So the column read "responsive" for any web server
-- reachable at that address, including a captive portal, a proxy error page, or
-- a host that had been repurposed years ago.
--
-- The check now builds a real OCSP request and verifies the signature on the
-- response against the issuing CA. Having done that, throwing away the answer
-- would be strange, so it is recorded here.
--
-- The answer worth having is about the CA certificate itself. The OCSP URL in a
-- certificate's authority information access extension is the responder for
-- *that* certificate, answered by its parent — so asking it tells CertPilot
-- whether this issuing CA has been revoked by the authority above it. That is
-- the highest-consequence fact in a hierarchy and nothing here could see it.

begin;

alter table public.ca_authorities
  -- GOOD, REVOKED or UNKNOWN, as the responder gave it. NULL means never asked
  -- — deliberately distinct from UNKNOWN, which is the responder saying it has
  -- no record of this certificate and is usually a misconfiguration rather than
  -- good news.
  add column if not exists ocsp_status text
    check (ocsp_status is null or ocsp_status in ('GOOD', 'REVOKED', 'UNKNOWN')),

  -- When the CA above this one revoked it, as the responder reported.
  add column if not exists ocsp_revoked_at timestamptz,

  -- Why the last check could not produce a verified answer, in the words an
  -- operator will read at 2am. Kept as text rather than a flag because "the
  -- responder is down" and "something answered and it was not the CA" are
  -- different problems with different responses, and a boolean cannot say
  -- which.
  add column if not exists ocsp_last_error text;

-- A revoked issuing CA is the single most serious state this table can hold,
-- and it is worth being able to find every one of them without a sequential
-- scan when somebody asks the question at 3am.
create index if not exists idx_ca_authorities_ocsp_revoked
  on public.ca_authorities (ocsp_status) where ocsp_status = 'REVOKED';

commit;
