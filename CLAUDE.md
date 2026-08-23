# CertPilot — working notes

Open-source PKI and certificate lifecycle management. **The audience is a central
PKI team inside an organisation**: the group that owns the CA hierarchy and gets
paged when something expires. That audience decides most arguments in this
codebase — the UI is not a convenience layer over a CLI, it is the product
surface, because an expiring issuing CA takes down everything it ever signed and
no amount of certificate automation helps once that has happened.

This file is what a new session needs before touching anything. Depth lives in
[`docs/`](docs/README.md); it is written and current, prefer reading it over
re-deriving from source.

---

## Traps that will cost you tool calls

**The Bash working directory persists between calls.** A `cd core` in one call
is still in effect in the next one. Prefix commands with
`cd /Volumes/Mervin/pki_project` when the location matters. This has bitten
repeatedly, most memorably by making a heredoc write a file into the wrong
directory and silently succeed.

**`go build ./...` from the repo root does nothing useful.** This is a Go
workspace with six modules. Build and test from inside a module, or use the
Makefile, which loops over them.

**The frontend dev server is Vite on `:3000`, not 5173.** It proxies `/api` and
`/healthz` to `:8080`.

**`config.dev.yaml` is gitignored** and does not exist on a fresh clone; the core
falls back to built-in development defaults. Do not assume its contents.

**Zsh is the shell.** Unquoted globs that match nothing are a hard error, not a
literal — `grep foo *.go` fails when there are no `.go` files in the cwd.

---

## Layout

Six Go modules in a workspace (`go.work`, Go 1.26.6) plus a Vue frontend.

| Path | What it is |
|:---|:---|
| `pkg/` | Shared: `x509util`, `secrets` (envelope encryption), `grpckit` (mTLS), generated protobuf |
| `core/` | The control plane. API, store, plugin manager, and ten engines |
| `gateways/{selfsigned,acme,vault}/` | CA adapters, each its own module and process, speaking one gRPC contract |
| `agent/` | Host agent: generates keys locally, sends CSRs, installs and reloads |
| `frontend/` | Vue 3 + Vite + Tailwind 4 + Pinia |
| `migrations/` | 27 numbered `.sql` files, applied by `certpilot-core --migrate` |
| `docs/` | Written, current, and worth reading |

**The API reference is published as a separate site** from
[`mervin008/certpilot-docs`](https://github.com/mervin008/certpilot-docs)
(VitePress, GitHub Pages). Its endpoint tables are *generated* from
`core/api/router.go` by `scripts/extract-routes.py` into `docs/routes.json`,
which CI checks for staleness — so **run `make routes` after adding a route**.
`docs/api-reference.md` stays here as the deeper per-resource guide.

`core/engine/` holds the ten background engines: `pki` (CA health and issuer
import), `renewal`, `discovery`, `ctlog`, `cloudsync`, `deploy`, `fleet`,
`notifications`, `policy`, `posture`. They are started by `core/server` and
publish to an in-process broker (`core/events`) that feeds the SSE endpoint.

`core/api/` is 21 handler files behind ~101 routes in `router.go`.

---

## Commands

```bash
make dev      # PostgreSQL + self-signed gateway + API + frontend, one terminal
make seed     # fill a running instance with a realistic estate; idempotent
make test     # all six modules
make lint     # gofmt + go vet + staticcheck
make migrate  # apply outstanding migrations (never run automatically)
make routes   # regenerate docs/routes.json after changing the router
make help     # the rest
```

`make dev` starts the local Homebrew PostgreSQL if it is not running, creates
`certpilot_dev`, applies the plain-PostgreSQL prelude and all migrations,
generates a development KEK once into `.certpilot/dev-kek` and reuses it, then
runs the gateway (`:9091`), the API (`:8080`) and the frontend (`:3000`).
Ctrl-C stops everything and stops PostgreSQL only if the script started it.

Export `CERTPILOT_DB_URL` first to use a different database; the entire
bootstrap is skipped when you do.

**The demo data is meant to stay.** Do not clear the database at the end of a
task. `make seed` is idempotent and deletes nothing, so re-run it rather than
starting from empty.

---

## Things that are true and non-obvious

**Migration 001 was written against Supabase.** It references `auth.users`, the
`authenticated` role, and the `supabase_realtime` publication. Plain PostgreSQL
needs [`deploy/plain-postgres/prelude.sql`](deploy/plain-postgres/prelude.sql)
run once first. That file is deliberately **not** in `migrations/` — the migrator
applies everything it finds there, and installing a stub `auth.jwt()` on a real
Supabase project would shadow the genuine one and silently break every RLS
policy. Never move it, and never run it against a database you did not create.

**The server never migrates itself.** A schema change is something an operator
runs, not a side effect of a replica restarting mid-deploy.

**Private keys and CA credentials are sealed with `CERTPILOT_KEK`** before they
reach the database (`pkg/secrets`, envelope encryption, `CPS1` magic). Losing the
KEK makes every stored secret unrecoverable. The core refuses to start against a
database without one.

**The identity provider says who you are; CertPilot says what you may do.**
Roles live in the `users` table keyed on `(issuer, subject)`, not in a token
claim — `app_metadata.certpilot_role` is ignored when a directory is wired in.
A sign-in never writes a role, so `auth.bootstrap_admins` grants a first one and
never maintains it. A subject is opaque text, **not a uuid**: Okta, Google and
Auth0 all issue non-uuid subjects, which is what migration 028 widened every
actor column for. `GET /me` is the only honest source of a role for the UI.

**`key_custody` on a certificate says who holds the private key** — `CERTPILOT`,
`AGENT`, or `EXTERNAL`. Provenance (`discovered_via`) cannot answer that
question: a CSR-signed certificate is `REQUESTED` like any other and CertPilot
holds no key for it. Anything deciding whether a key can be exported must read
custody.

**`lib/severity.ts` and `core/engine/pki/ca_monitor.go` are the only places that
decide severity.** Four copies of that mapping once drifted apart across views;
two panels disagreeing about whether a CA is in trouble is a correctness bug, not
a cosmetic one.

**The core is the authority on severity, and the UI mirrors it.** Prefer the
API's `days_remaining` over recomputing from `not_after`. The exception, and it
is deliberate: a certificate's *urgency* combines its status with its own
`renewal_lead_days`, because the core leaves a certificate `ISSUED` until a
renewal sweep moves it while `/dashboard/stats` already counts it as expiring.

**Durable queues** (renewal, deployment) use a partial unique index plus
`ON CONFLICT DO NOTHING` and `FOR UPDATE SKIP LOCKED`. No leader election; any
replica can run them.

---

## House style

Prose comments that say **why**, not what. The codebase is full of comments
explaining the failure a piece of code prevents, often naming the bug that
motivated it. Match that; it is the most valuable thing in the repo.

Commit messages are long and explain the reasoning, the failure mode, and what
was verified. Look at recent history before writing one.

British spelling in prose and comments. Proper nouns keep their capitals in
error strings, which is why `ST1005` is disabled in `staticcheck.conf`.

Errors are written for the operator who will read them at 2am. Name the cause,
not just the symptom.

---

## Verification norms

**Unit tests passing is not evidence the thing works.** This project has a
history of green suites over broken behaviour:

- `sys/health` was decoded through the wrong envelope, so every real Vault
  reported "not initialized" — and the fake wrapped it the same way, so the
  tests agreed.
- `GetCAChain` had been broken against any real database since migration 006;
  the in-memory store had no such column and never noticed.
- The store conformance suite fabricates the Supabase objects migration 001
  needs, so it never noticed that the schema cannot be created without them.

So: **run it against the real thing.** The stack starts in about ten seconds and
`make seed` gives it something to work on. For UI work, screenshot it — headless
Chrome is at `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
and screenshotting has caught real defects that reading the code did not
(uncoloured severity cells losing a CSS specificity fight, a red chip labelled
"ISSUED", sentences rendered in an uppercase tracked label style).

**The four store defect classes**, all found the hard way, all worth checking
when touching the store: a Go constant a CHECK constraint refuses; a model field
a writer silently drops; empty string versus NULL; a parameter PostgreSQL types
differently than expected. See [`docs/database.md`](docs/database.md).

---

## Frontend

Vue 3, Pinia, Tailwind 4, daisyUI (being removed), chart.js, lucide icons.

**The design is an operations console, not an admin template.** Three rules, all
enforced in `src/assets/styles/main.css`:

1. **Colour means severity.** Warm colour only where something needs a person; a
   cool blue (`--signal`) for what is interactive or alive. Healthy green is
   deliberately desaturated — at full saturation it is the loudest thing on a
   screen where almost everything is fine.
2. **Time is the organising dimension.** Monospace is the primary face with
   tabular numerals throughout. Type sizes come from `--fs-micro/label/small/body`;
   never hard-code a pixel size.
3. **Sharp edges, tight density.** 2px radius. Roughly thirty-five rows on a
   27-inch screen.

The hero on the dashboard is `ExpiryHorizon.vue`: one **logarithmic** time axis
from now to ten years, authorities above and certificates below. Log spacing is
the whole design — on a linear axis everything expiring inside a quarter
collapses into the first two percent of the width.

Severity utility classes are tripled (`.sev-critical.sev-critical.sev-critical`)
to win specificity fights against `.tbl tbody td` and scoped component styles.
That is deliberate; do not "simplify" it.

Sign-in is OpenID Connect, authorization code with PKCE, in `lib/oidc.ts`. The
frontend reads the issuer and client id from `/auth/config` rather than from
build-time environment variables, so one instance is described by one file.

**Converted to the console idiom:** `DashboardView`, `CaHealthView`,
`CertificatesView`, plus the shell (`CommandRail`), `DataState`, and the `ui/`
and `metadata/` components.
**Still daisyUI:** `PkiOverviewView`, `GatewaysView`, `DiscoveryView`,
`PoliciesView`, `SettingsView`, `DisplayView`. They follow the palette because
daisyUI's theme tokens were overridden, but they are proportional-font and airy.

`DisplayView` is the unattended wall screen: no chrome, authenticates with a
kiosk display token, and must degrade loudly when the feed dies.

---

## Rules that look like details and are not

**A dashboard that stops updating must look broken, not healthy.** A frozen
screen showing green manufactures false confidence. `.surface-stale` drains the
colour out of the content when the SSE feed goes stale; the wall display gets a
pulsing band. Do not soften either.

**Acknowledging never hides anything.** An acknowledged CA stays exactly where it
was in the urgency order, marked. Filtering it out is how CAs expire in
organisations that believed they were monitoring them.

**An empty state must not read as a healthy one.** "No CAs are being monitored"
says explicitly that the page is empty because nothing was imported, not because
everything is fine.

**A failed fetch must never render as an empty list.** `useAsyncData` makes an
error a first-class state; `DataState` shows it even when stale data is still on
screen.

**Required metadata is enforced at issuance only**, never on an edit — otherwise
adding a required field makes the whole estate unsaveable.

---

## Known gaps

Documented, not secretly broken. Do not "discover" these as findings.

- **The refresh token is in `localStorage`.** An access token is held in memory
  only, but surviving a page reload needs something persistent and a page with
  no backend of its own has no option a script cannot read. The fix is a
  backend-for-frontend with an httpOnly cookie; that is a deployment change.
- **No user-management UI yet.** Roles are stored and enforced, and
  `SetUserRole` / `SetUserStatus` exist in the store, but nothing exposes them —
  changing a role means a SQL update. The Settings → Users screen is the next
  step.
- **No certificate revocation endpoint.** Both gateways implement it; the core
  exposes no route. `DELETE /certificates/:id` deletes the record and leaves the
  certificate live at the CA. This is the largest hole in the product.
- Audit log is not hash-chained.
- No agent nonce store (replay window bounded by timestamp only).
- OCSP checking is a bare GET, not a signed-response validation.
- Key Vault and F5 deployers are unit-tested only.
- The KEK lives in an environment variable.
- No API rate limiting.
- Deployment ordering is not expressible.
- Discovery, CT and cloud-sync tables are thinly covered by the conformance suite.
- Docker assets were fixed but never built — no container runtime on this machine.
- The light theme ships but has never been verified in a rendered screenshot;
  this machine is in system dark mode and headless Chrome inherits it.

---

## Secrets

`.env` is gitignored and holds `CERTPILOT_DB_URL` (a Supabase project) and
`CERTPILOT_KEK`. **`make dev` does not read it** — it uses the local PostgreSQL
instead, and no Go code loads `.env`. Never print, commit, or echo its contents.

Two items the owner has deferred: the Supabase database password has not been
rotated, and `CERTPILOT_KEK` is not stored anywhere durable.
