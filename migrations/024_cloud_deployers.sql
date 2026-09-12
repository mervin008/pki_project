-- 024_cloud_deployers.sql
--
-- The deployers that need no agent, and the fourth widening of the same
-- constraint.
--
-- Migration 022 widened `deployment_targets_target_type_check` for `'agent'`
-- and wrote down the rule that fell out of three occurrences:
--
--   A check constraint that enumerates a domain of "kinds of thing" will need
--   widening; one that enumerates a lifecycle will not.
--
-- One migration later, here it is again. Recorded rather than patched quietly,
-- because being right about a prediction is only useful if somebody notices.
--
-- Two values go in. `f5` is new. `azure_key_vault` is new *as a target type*
-- and is not new to this schema — migration 001 spelled the same provider
-- `azure_kv` in this constraint, while migration 011 spelled it
-- `azure_key_vault` in `cloud_connections.provider`. Nothing noticed, because
-- until now nothing ever compared the two.
--
-- Now something does. A cloud deployment target borrows the credentials of a
-- cloud connection rather than storing a second copy, and the check that the
-- connection is the right kind of account compares those two strings directly.
-- Two spellings of one provider is a bug that had been sitting in the schema
-- since migration 001, waiting for the first join.
--
-- `azure_kv` is left in the list rather than removed. It is unused, and
-- dropping a permitted value from a check constraint is a thing that fails on
-- somebody's database at three in the morning because one row somewhere has it.
--

begin;

alter table public.deployment_targets
  drop constraint if exists deployment_targets_target_type_check;

alter table public.deployment_targets
  add constraint deployment_targets_target_type_check
  check (target_type in (
    'filesystem', 'aws_acm', 'kubernetes', 'webhook', 'gcp_lb',
    -- Superseded by azure_key_vault, kept because removing a permitted value is
    -- how a constraint change fails on somebody else's data.
    'azure_kv',
    'azure_key_vault', 'f5', 'agent'));

-- Which deployment targets borrow which account's credentials.
--
-- A plain column and not part of the sealed config, for the same reason
-- `deploys_private_key` is: "which cloud accounts can this system write to" has
-- to be answerable with a SELECT, by somebody who does not hold the KEK. A
-- credential reference buried in an encrypted blob is a fact only something
-- that can decrypt every credential in the system is allowed to know.
alter table public.deployment_targets
  add column if not exists cloud_connection_id uuid
    references public.cloud_connections(id) on delete restrict;

create index if not exists idx_deployment_targets_connection
  on public.deployment_targets (cloud_connection_id)
  where cloud_connection_id is not null;

commit;
