-- 012_cloud_provenance.sql
--
-- Lets a certificate record say it was found in a cloud store.
--
-- `certificates.discovered_via` has carried a check constraint since migration
-- 001 listing MANUAL, SCAN, CT_LOG, IMPORT, and REQUESTED. Adopting a
-- certificate found in ACM, a Key Vault, a GCP load balancer, or a Kubernetes
-- secret is none of those, and the insert was rejected outright.
--
-- Found by running the import against a real database. The in-memory store
-- enforces no check constraints, so every test of that path passed.
--
-- The lazy fix would have been to write 'IMPORT' and move on. That column
-- exists for exactly one question — "which of these did we issue, and which did
-- we merely find?" — and answering it with the same word for a PEM somebody
-- pasted and a certificate discovered sitting in a production Key Vault throws
-- away the more interesting half.
--
-- Applies to plain PostgreSQL as well as Supabase.

begin;

alter table public.certificates
  drop constraint if exists certificates_discovered_via_check;

alter table public.certificates
  add constraint certificates_discovered_via_check
  check (discovered_via in ('MANUAL', 'SCAN', 'CT_LOG', 'CLOUD', 'IMPORT', 'REQUESTED'));

commit;
