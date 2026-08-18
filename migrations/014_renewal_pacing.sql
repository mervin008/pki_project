-- 014_renewal_pacing.sql
--
-- Two changes, both about the difference between "this failed" and "we chose
-- not to try yet".
--
-- **`renewal_jobs.ca_account_id`** — denormalised from the certificate at
-- enqueue, for the same reason `not_after` is: it is read on every pacing
-- decision, and a join to a table that may have been edited underneath the job
-- is the wrong source of truth for "which CA's rate limit does this spend".
--
-- **Rate limits on `ca_accounts`** — because a CA's limits are a property of
-- the account, not of this deployment. Let's Encrypt allows a fixed number of
-- certificates per registered domain per week; an internal CA usually allows
-- whatever you ask for. Getting this wrong in the generous direction suspends
-- issuance for the whole organisation for a week, and it does so at exactly
-- the moment somebody is trying to fix an outage by reissuing.
--
-- The window is deliberately expressed in hours rather than as a named period.
-- Providers do not agree on what a period is — some count a rolling week, some
-- a rolling three hours for orders — and a rolling window measured in hours is
-- the only shape that describes all of them without lying about any of them.
--
-- A limit of 0 means unlimited, which is the right default: inventing a
-- conservative limit for a CA whose real limits nobody has entered would delay
-- renewals for a constraint that does not exist, and a certificate that expired
-- because this tool was being cautious is the worst possible outcome.
--
-- Applies to plain PostgreSQL as well as Supabase.

begin;

alter table public.renewal_jobs
  add column if not exists ca_account_id uuid references public.ca_accounts(id) on delete set null;

-- The pacing query: how many renewals has this CA account completed inside the
-- window, and when does the oldest of them age out.
create index if not exists idx_renewal_jobs_ca_recent
  on public.renewal_jobs (ca_account_id, completed_at)
  where status = 'SUCCEEDED';

alter table public.ca_accounts
  -- Certificates this account may successfully renew inside the window.
  -- 0 means unlimited.
  add column if not exists renewal_rate_limit int not null default 0
    check (renewal_rate_limit >= 0),
  -- The rolling window, in hours. A week by default, matching the period the
  -- public CAs most commonly count in.
  add column if not exists renewal_rate_window_hours int not null default 168
    check (renewal_rate_window_hours > 0);

commit;
