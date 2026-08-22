-- 021_agent_provenance.sql
--
-- Widens `certificates_discovered_via_check` to admit 'AGENT'.
--
-- The same three lines as migration 012, for the same reason, one source later.
-- That is worth naming rather than repeating quietly: **this constraint needs
-- widening every time a certificate can arrive from somewhere new**, and it has
-- now been the last thing to notice twice — once when cloud inventory learned
-- to import, and again when a host learned to ask.
--
-- Both times the fix was to widen it rather than to reuse an existing value.
-- 'IMPORT' would have passed the constraint and thrown away the answer to the
-- only question the column exists for. A certificate whose key was generated on
-- the host that serves it and has never been anywhere else is not the same
-- thing as one somebody pasted into a form, and the difference is the whole
-- point of the agent.
--
-- Both times it was found by running rather than by testing, because the
-- in-memory store enforces no constraints. That is the fifth defect of this
-- shape in this project; a container-backed test suite remains the fix and
-- remains unwritten.
--
-- Applies to plain PostgreSQL as well as Supabase.

begin;

alter table public.certificates
  drop constraint if exists certificates_discovered_via_check;

alter table public.certificates
  add constraint certificates_discovered_via_check
  check (discovered_via in ('MANUAL', 'SCAN', 'CT_LOG', 'IMPORT', 'REQUESTED', 'CLOUD', 'AGENT'));

commit;
