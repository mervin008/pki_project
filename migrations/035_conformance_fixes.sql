-- 035: two divergences the conformance suite found on its first run against a
-- real database.
--
-- discovery_test.go and cloud_test.go had always called NewMemoryStore()
-- directly rather than going through forEachStore, so every assertion in them
-- had only ever been made against the in-memory store. Running them against
-- PostgreSQL is what surfaced both of these.
--
-- The management_state half was a code fix — the writers passed an explicit
-- empty string, which overrides `default 'UNMANAGED'` rather than falling back
-- to it, and the CHECK then refused the row. This file is the other half.

begin;

-- A cloud connection's name is unique case-insensitively.
--
-- The in-memory store had always compared names without regard to case, and
-- PostgreSQL's plain unique constraint had not — so "prod-eu" and "PROD-EU"
-- were one connection in tests and two in production. Two rows differing only
-- in case is not a naming choice anybody makes on purpose; it is a duplicate
-- somebody creates by accident and then cannot tell apart on a screen, while
-- both sync the same account and report separately.
--
-- Matching the rule already used for user email addresses, and for the same
-- reason: the uniqueness people assume is the one that ignores case.
drop index if exists idx_cloud_connections_name_ci;
alter table public.cloud_connections drop constraint if exists cloud_connections_name_unique;
create unique index if not exists idx_cloud_connections_name_ci
  on public.cloud_connections (lower(name));

commit;
