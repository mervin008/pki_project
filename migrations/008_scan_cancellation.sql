-- 008_scan_cancellation.sql
--
-- Lets a scan be recorded as cancelled rather than failed.
--
-- A range scan takes minutes, so stopping one has to be possible — and once it
-- is, the status it lands in matters. `FAILED` and `CANCELLED` are different
-- facts: one says something went wrong, the other says somebody changed their
-- mind. Folding the second into the first makes the scan history read as a
-- string of failures, which is how a team stops trusting the one screen that
-- tells them whether discovery is running at all.
--
-- A cancelled scan keeps everything it found before it stopped. That is why
-- `results_count` stays meaningful on a cancelled row, and why `error` carries
-- how far it got rather than a failure message.

-- It also adds `target_count`: how many endpoints the run set out to reach,
-- after `10.0.0.0/24` expanded into 254 addresses. Without it a running scan
-- can say how many endpoints have answered but not out of how many, so there is
-- no progress to show — and a scan whose end nobody can see is one people
-- cancel out of doubt rather than intent. It is also what makes "cancelled
-- after 40 of 254" sayable at all.

begin;

alter table public.discovery_scans
  add column if not exists target_count int not null default 0;

alter table public.discovery_scans
  drop constraint if exists discovery_scans_status_check;

alter table public.discovery_scans
  add constraint discovery_scans_status_check
  check (status in ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'));

commit;
