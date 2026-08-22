# Running CertPilot against a database

The core keeps everything in memory when no connection string is configured.
That is fine for a first look and useless for anything else: the seeded CAs and
certificates are demonstration data, and every restart discards whatever you
did. Once you want the dashboard to mean something, point it at PostgreSQL.

Supabase is the smoothest target, because it is PostgreSQL and because the
schema was written against it. Nothing in the Go store layer knows Supabase
exists — it is `pgx` talking to `public.*` — so anything else that speaks
PostgreSQL 15+ works the same way.

---

## 1. Get a connection string

In the Supabase dashboard: **Project Settings → Database → Connection string**.
Three are offered, and the choice matters more than it looks.

| | Host / port | Use it? |
|:---|:---|:---|
| **Session pooler** | `…pooler.supabase.com:5432` | **Yes — start here** |
| Transaction pooler | `…pooler.supabase.com:6543` | Only with the extra parameters below |
| Direct connection | `db.<ref>.supabase.co:5432` | Only if your network has IPv6 |

**Session pooler** is the default recommendation for two reasons. It is reachable
over IPv4, whereas the direct connection is IPv6-only on projects without the
IPv4 add-on — on a network without IPv6 that fails as `network is unreachable`,
which looks like a credentials problem and is not. And it holds one server
connection per client session, so prepared statements behave normally.

That second point is the one that bites. `pgx` uses the extended query protocol
and caches prepared statements per connection. A transaction-mode pooler hands
your next query to a different backend, where that statement was never prepared.
If you must use port 6543, disable the cache explicitly:

```
postgres://…:6543/postgres?sslmode=require&default_query_exec_mode=exec&statement_cache_capacity=0
```

Add `sslmode=require` in all cases. Supabase will negotiate TLS anyway; saying so
means a misconfiguration fails instead of quietly downgrading.

**Connect as `postgres`** — the role in the pooler's `postgres.<project-ref>`
username. Read [row-level security](#row-level-security) before you decide to use
anything else, because the failure mode there is silent.

---

## 2. Set the key encryption key

```bash
export CERTPILOT_KEK=$(make -s generate-kek | cut -d= -f2-)
```

Certificate private keys and CA credentials are sealed with this before they
reach the database, so the core refuses to start against a database without one.
Put it in a secret manager. **Losing it makes every stored secret unrecoverable**
— the rows survive and nothing can read them.

---

## 3. Apply the schema

```bash
export CERTPILOT_DB_URL='postgres://postgres.<ref>:<password>@<host>:5432/postgres?sslmode=require'
make migrate
```

```
  applied  001_initial_schema.sql
  applied  002_crypto_agility.sql
  applied  003_display_tokens.sql
  applied  004_monitoring_queries.sql
  applied  005_identity_decoupling.sql
  applied  006_ownership_and_acknowledgement.sql
  applied  007_discovery.sql
  applied  008_scan_cancellation.sql
  applied  009_discovery_schedules.sql
  applied  010_ct_monitoring.sql
  applied  011_cloud_inventory.sql
  applied  012_cloud_provenance.sql
  applied  013_renewal_jobs.sql
  applied  014_renewal_pacing.sql
  applied  015_renewal_information.sql
  applied  016_renewal_verification.sql
  applied  017_deployment.sql
  applied  018_agents.sql
  applied  019_agent_inventory.sql
  applied  020_agent_issuance.sql
  applied  021_agent_provenance.sql

Applied 21 migration(s).
```

Applied files are recorded in `public.schema_migrations` with a checksum, so
rerunning is a no-op and editing a migration that has already run is reported
rather than silently ignored or silently rerun. Concurrent runs serialise on a
Postgres advisory lock.

The server never migrates on startup. A schema change should be something an
operator decides to do, not a side effect of one replica restarting mid-deploy
while the others still read the old shape. Run it as a job, an init container, or
by hand.

If you would rather paste the SQL into the Supabase SQL editor, apply the files
in numeric order. `004`, `006`, `007`, `008`, and `012` add columns to or alter
constraints on tables `001` creates.

### Migration 005 is not optional

`001` declared every actor column as `references auth.users(id)` —
`certificates.created_by`, `audit_logs.actor_id`, and five more. But the core does
not authenticate against Supabase Auth; it verifies OIDC tokens against whatever
`auth.jwks_url` points at, which is as likely to be Keycloak or Okta, and stores
that provider's `sub`. Those subjects are not rows in `auth.users`.

The result is not a cosmetic inconsistency. Issuing a certificate raises a
foreign key violation and fails. Local development hits it on the first request,
because anonymous access writes a fixed subject that deliberately is not a real
user.

`005` drops those constraints and keeps the columns. Migration `003` had already
taken this position for `display_tokens`; `005` applies it to the tables that
predate it.

---

## 4. Start the core

```bash
make run-core          # picks up CERTPILOT_DB_URL
```

or `--db=postgres://…`. Resolution order is `--db`, then `CERTPILOT_DB_URL`, then
`DATABASE_URL`.

You should see:

```
INFO connected to PostgreSQL/Supabase database
```

The dashboard will show zeros, because the database is empty and the sample data
lived only in memory. That is the correct output, and being able to trust it is
the point.

---

## Row-level security

Every table from `001` has RLS enabled with policies written for Supabase's
`authenticated` role. The core is unaffected because it connects as `postgres`,
which owns the tables, and PostgreSQL does not apply RLS to a table's owner
unless the table is set to `force row level security`. None are.

This is load-bearing, and it fails in the worst possible direction:

> **A policy that denies a `SELECT` does not raise an error. It returns zero
> rows.**

A core connected as some other role would start cleanly, answer every request,
and report an estate with no certificates, no CAs, and nothing expiring — which
on a wall display is indistinguishable from an organisation whose PKI is in
perfect health. That is precisely the failure this product exists to prevent,
arriving through its own database connection.

So the core checks at startup, in `store.Preflight`, and refuses to run rather
than serve a reassuring lie:

```
failed to connect to the database: row-level security would silently hide rows
in ca_authorities, certificates from this connection, so the dashboard would
show an empty, healthy-looking estate. Connect as the role that owns these
tables (on Supabase that is `postgres`), or grant the current role BYPASSRLS
```

The same check refuses an unmigrated or half-migrated database, for the same
reason — an empty dashboard is a plausible-looking dashboard.

If you do create a dedicated role for the core, it needs `BYPASSRLS` (or
ownership of the tables). The RLS policies stay useful either way: they still
govern anything reaching the database through PostgREST, which is a different
path with a different threat model.

---

## Plain PostgreSQL

Migrations `002` through `010` apply anywhere. **`001` does not**: it defines
`get_user_role()` in terms of `auth.jwt()` and its RLS policies grant to the
`authenticated` role, neither of which exists outside Supabase. A portable `001`
is a known gap, tracked in the README.

Until then, on vanilla PostgreSQL, create the schema from `001` with the
`auth.users` references and the RLS block removed. `005` is then a no-op, which
is the intended behaviour rather than an accident — it drops constraints by
searching for foreign keys into the `auth` schema, and finds none.

---

## Troubleshooting

| Symptom | Cause |
|:---|:---|
| `network is unreachable` | Direct connection on an IPv4-only network. Use the session pooler. |
| `prepared statement "stmtcache_…" already exists` / `does not exist` | Transaction pooler without `default_query_exec_mode=exec`. |
| `the database has none of CertPilot's tables` | Run `make migrate`. |
| `row-level security would silently hide rows…` | Connected as a non-owner role. See above. |
| `insert or update on table … violates foreign key constraint` naming `auth.users` | Migration `005` has not been applied. |
| `CERTPILOT_KEK is required` | See step 2. |
| Dashboard shows zeros | Expected on a fresh database. Preflight has already ruled out the two ways this could be a lie. |

---

## What running this for the first time found

Everything above was verified against a live Supabase project (PostgreSQL 17,
session pooler, `eu-north-1`): all five migrations applied and reapplied
idempotently, three CAs registered, a certificate issued through the self-signed
gateway, renewed with key rotation, its private key exported and checked against
the certificate, six health sweeps run, and a kiosk display token exercised on
every route it is allowed and refused.

Four defects surfaced that the in-memory store could not express, which is worth
recording because it is the argument for a container-backed test suite:

1. **Issuance failed outright.** `certificates.environment` is nullable with a
   `CHECK` constraint. The Go field is a plain `string`, so a request that did
   not name an environment wrote `''` — and a CHECK passes on NULL but fails on
   `''`. Every certificate request without an explicit environment was rejected
   by the database.
2. **The CA expiry window never worked.** `not_after <= now() + ($1 || ' days')`
   leaves both sides of `||` untyped, so PostgreSQL resolved it as `text || text`
   and reported the parameter as text while the driver held an int. Now
   `make_interval(days => $1)`.
3. **Empty lists serialized as `null`, not `[]`** — pgx leaves a slice nil when a
   query returns no rows. The dashboard calls `.map()` on that, so an empty
   estate would have rendered as a crash rather than as zeros.
4. **A single NULL could take out an entire list endpoint.** Several nullable
   columns scan into non-pointer Go fields, and pgx fails the whole query rather
   than the row. One hand-inserted or bulk-imported certificate with a null
   `key_size` would have blanked the certificate list. Both read projections now
   `COALESCE`.

Migration 001 also had to be made rerunnable: `create policy` has no
`if not exists`, so applying the file to a database that already had the schema
failed on the first policy and rolled back everything.

### Migration 012 exists because a check constraint outlived its list

`001` constrained `certificates.discovered_via` to `MANUAL`, `SCAN`, `CT_LOG`,
`IMPORT`, and `REQUESTED`. Adopting a certificate found in a cloud store is none
of those, and the insert was rejected outright.

It is worth recording alongside the four defects below, because it is the same
lesson arriving from a different direction: **the in-memory store enforces no
check constraints**, so every automated test of the import path passed. It was
found by importing a certificate against the real database.

The tempting fix was to write `IMPORT` and move on. `discovered_via` exists to
answer one question — which of these did we issue, and which did we merely find?
— and answering it with the same word for a PEM somebody pasted and a
certificate discovered sitting in a production Key Vault throws away the more
interesting half.

Migrations are append-only for the same reason the migrator checksums them: an
edit to `001` would have left this database recording a file it no longer
matches. Editing an applied migration prints a warning on every subsequent run,
which is the migrator working correctly and worth not silencing.

### Migration 013 replaces leader election with two constraints

`renewal_jobs` is the one table in this schema that exists to make concurrency
safe rather than to record something. Two things in it do that work, and both
are cheaper and more robust than the advisory-lock leader the roadmap originally
called for:

```sql
create unique index idx_renewal_jobs_one_outstanding
  on public.renewal_jobs (certificate_id)
  where status in ('PENDING', 'RUNNING');
```

At most one outstanding job per certificate. Every replica can run the renewal
sweep; the second one to enqueue a given certificate loses the race on this
index and its insert is discarded by `ON CONFLICT … DO NOTHING`.

```sql
SELECT id FROM public.renewal_jobs
WHERE (status = 'PENDING' AND run_after <= $3)
   OR (status = 'RUNNING' AND locked_until < $3)
ORDER BY not_after ASC NULLS LAST, run_after ASC
FOR UPDATE SKIP LOCKED
LIMIT 1
```

`SKIP LOCKED` means two workers claiming at the same instant never collide —
the second takes the next row rather than blocking or duplicating. The second
`OR` arm is the lease: a worker that was killed releases its job when
`locked_until` passes, with nothing needing to notice it died.

A leader would have given one replica all the work and a failover window during
which no certificate renews at all. These two lines give N equal workers and no
window.

### Migration 023 and a default that does not apply to existing rows

`certificate_deployments.deploy_on_renewal` defaults to `true`, and the same
migration sets every row that already existed to `false`. Those two statements
look like a mistake and are the point of the migration.

A binding created from here on is created by somebody who knows that renewals
now install by themselves. A binding that already existed was created under a
regime where nothing deployed without a person pressing something, and turning
it on at upgrade time would mean a package manager deciding to write to
production servers. `ADD COLUMN ... DEFAULT true` backfills, so the `UPDATE`
undoing it for existing rows is deliberate and is guarded on the migration not
having been recorded as applied before — migrations here are append-only and
checksummed, but "this ran twice" happens to people, and the cost of being
wrong is an estate that quietly stops deploying.

There is no `deploy_order` column, and its absence is also a decision. Waves
were designed and dropped in favour of a rule that needs no configuration: the
queue will not start a job for a certificate while another job for that
certificate has failed. That lives entirely in the claim predicate, and the one
index this migration adds is what makes it cheap.

### Migration 022 and the third widening of a closed list

`deployment_targets.target_type` refused `'agent'`, for exactly the reason
`certificates.discovered_via` refused `'CLOUD'` and then `'AGENT'`: a check
constraint listing values is a decision that the set is closed, and every one of
these widenings has been a case where it was not.

Three times is a pattern rather than a coincidence, so it is written down here
rather than patched quietly each time. The rule that falls out of it: **a check
constraint that enumerates a domain of "kinds of thing" will need widening; one
that enumerates a lifecycle (`PENDING`, `RUNNING`, `SUCCEEDED`) will not.** The
first is an inventory of the world, which grows. The second is a state machine,
which is designed.

Migration 022 also carries the first table in this schema deliberately shaped by
what it must *not* be able to hold. `agent_installations` has `reload_command`
and `check_command` columns, and there is no path anywhere in the Go layer by
which the core can write them: they arrive from the host, for display. A column
the core could set would make this table a queue for arbitrary code on every
machine in the estate, authenticated by whoever can write one row.

### Migration 021, and a constraint that has now been the last to notice twice

`certificates_discovered_via_check` refused `'AGENT'`. Migration 012 widened the
same constraint for `'CLOUD'`, in the same circumstances, found the same way.

Worth naming rather than repeating quietly: **this constraint needs widening
every time a certificate can arrive from somewhere new**, and both times the
temptation was to reuse an existing value instead. `'IMPORT'` would have passed
and thrown away the answer to the only question the column exists for — a
certificate whose key was generated on the host that serves it and has never
been anywhere else is not the same thing as one somebody pasted into a form, and
the difference is the entire point of the agent.

Both times it was found by running rather than testing, because the in-memory
store enforces no constraints. That is now six defects of this shape, and the
list has stopped being a coincidence:

| Migration | What only PostgreSQL knew |
|:---|:---|
| 012 | `discovered_via` refused `'CLOUD'` |
| 016 | `UpdateCertificate`'s explicit column list silently dropped new writes |
| 018 | An untyped `$1` in `$1 - <interval>` was inferred as an interval |
| 021 | `discovered_via` refused `'AGENT'` |
| 022 | `deployment_targets.target_type` refused `'agent'` |

(The remaining one was a deployment binding summary that read as an all-clear over a
failing target — not a constraint, but the same root: the in-memory store cannot
express what the database enforces, so the tests could not fail.) A
container-backed suite remains the fix and remains unwritten.

### Migration 018 and a parameter PostgreSQL typed as an interval

The agent staleness predicate is one expression used by two queries — the fleet
list and the alert sweep — written once so a dashboard cannot disagree with the
message that woke somebody up. The list interpolates `now()`; the sweep binds
the instant as `$1`.

The version with `now()` worked. The version with `$1` failed at runtime:

```
ERROR: operator does not exist: timestamp with time zone < interval (SQLSTATE 42883)
```

PostgreSQL infers a bound parameter's type from its context, and the only
context here was `$1 - <interval>` — which resolves perfectly happily as
interval arithmetic. The parameter came out as an `interval`, the whole
right-hand side became an `interval`, and the comparison had nothing to do with
timestamps at all. Fixed with an explicit `(…)::timestamptz` and by switching to
`make_interval(secs => …)`, which removes the precedence question entirely.

Every test passed throughout: the in-memory store computes staleness in Go.
That is the fourth defect in this project that only a real database run has
found, after migration 012's check constraint, migration 016's dropped column
list, and the deployment binding summary. The pattern is consistent enough to be
a rule — **the in-memory store cannot express what the database enforces**, and
a container-backed suite remains the fix.

### Migration 017 and an index that had to differ from the one above it

`deployment_jobs` is `renewal_jobs` with one line changed, and that line is the
whole design.

Renewal's partial unique index is on `certificate_id`: at most one outstanding
renewal per certificate, because a second one issues a second certificate
against a weekly quota. Deployment is the opposite case. A wildcard bound to six
load balancers needs six jobs outstanding at once, so the index is on
`deployment_id` — the *binding*, the place — and copying the renewal queue
verbatim would have produced a system that deployed to whichever target got
there first and discarded the other five without an error, a log line, or a row.

The same reasoning is why `certificate_deployments` exists at all rather than
three more columns on `certificates`. Migration 001 modelled deployment as
`certificates.deployment_target_id`: one certificate, one place. Six places have
six outcomes and six fingerprints, and a single `deployed_at` averages them into
a value that is true of nowhere. That column survives — nothing in the
deployment path reads it — and is listed in the roadmap's known gaps for
removal.

### Migration 016 and a column list that quietly dropped writes

`UpdateCertificate` writes an explicit column list. Adding `previous_fingerprint`
and the verification columns to the Go model without adding them to that list
meant the renewal set them, the update ran, and the values never reached the
database — no error, no warning.

Every test passed. The in-memory store keeps whole structs, so it cannot express
a dropped column at all; this is the same lesson as migration 012's check
constraint, arriving from the other direction. Found by renewing a real
certificate and watching `previous_fingerprint` come back empty.

The fix was not to widen `UpdateCertificate`. Verification state is written
through its own narrow writer, because the verifier runs concurrently with
everything else and a whole-row write from a stale copy would undo a renewal
that completed while it was probing. `previous_fingerprint` is coalesced there
rather than overwritten: it is set once by the renewal that scheduled the check
and every later pass has to keep it.
