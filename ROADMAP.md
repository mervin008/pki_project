# Roadmap

## Who this is for

A **central PKI team inside an organisation** — the group that owns the private
CA hierarchy, answers for every certificate the company serves, and gets paged
when something expires.

That audience determines the design more than any other decision here:

- **The dashboard is the product surface, not a convenience.** A central PKI
  team runs a wall display. They need CA health, expiry countdowns, and chain
  state visible without asking for it. An answer that requires someone to run a
  command is an answer nobody sees at 2am on a Sunday.
- **CA expiry is the catastrophic failure, not certificate expiry.** An expired
  leaf certificate breaks one service. An expired issuing CA breaks everything
  it ever signed, all at once, and no amount of certificate automation helps
  once it has happened. CA monitoring is therefore load-bearing.
- **Any CA, public and private.** These teams run internal PKI *and* buy public
  certificates. A tool that handles only one half doubles their tooling instead
  of halving it.
- **The API and CLI serve automation, not humans.** They matter, but they are
  not how the team perceives the state of their estate.

## Forcing function

CA/Browser Forum [ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)
takes maximum TLS validity to **200 days in March 2026, 100 days in March 2027,
and 47 days in March 2029**, with domain validation reuse dropping to 10 days.

At 47 days, ten thousand certificates means roughly 670 renewals a day. Anything
that requires a human in the loop stops working well before then.

---

## Done

**Phase 0 — Honest foundations**
Accurate README, algorithm constraints removed from the schema, secrets kept out
of version control.

**Phase 1 — Security floor**
- `pkg/secrets`: AES-256-GCM envelope encryption, per-record data keys,
  context-bound ciphertexts, incremental key rotation
- Mutual TLS on the core-to-gateway channel, with one-command dev setup
- OIDC via JWKS, pinned algorithms, no development auth fallback
- Private keys sealed at rest, never serialized, admin-only audited export
- RBAC enforced per route

**Phase 2 — An ACME gateway that issues certificates**
- Full RFC 8555 order flow
- `dns-01` via Cloudflare and a generic signed webhook; `http-01` via a built-in
  listener
- Persistent ACME account keys, External Account Binding
- Real revocation
- RFC 9773 renewal information

**Phase 2.5 — CA monitoring actually runs**
The health sweep is now scheduled rather than manual, and threshold crossings
are recorded to the audit log so they reach the dashboard instead of stdout.

---

## In progress

### Phase 3 — A monitoring surface a team can leave on a screen

The largest gap between what exists and what a central PKI team needs. The data
is already being collected; almost none of it reaches a human unprompted.

| Step | | |
|:---|:---|:---|
| 0 | Truth pass over the existing dashboard | ✅ |
| 1 | In-process event broker | ✅ |
| 2 | `GET /api/v1/events` — Server-Sent Events | ✅ |
| 3 | Kiosk display tokens | ✅ |
| 4 | Store filtering: audit log by action, CA filters, an index | ✅ |
| 5 | Frontend event stream and connection indicator | ✅ |
| 6 | CA health view, then fullscreen wall mode | ✅ |
| 7 | Alert delivery: Slack, webhook, SMTP | |
| 8 | Acknowledgement and ownership | |

**Step 0** was a prerequisite rather than cleanup: the dashboard computed CA
distribution with `Math.random()` inside a `computed`, fell back to invented
numbers when the API returned nothing, and bound field names the backend never
emitted. Two forms had never once worked. Live updates over that would have
produced a dashboard that flickered *and* lied.

**Steps 1–2** put changes on a stream. The broker drops the oldest event for a
slow consumer rather than applying backpressure, so a wall display on a flaky
link can never stall the CA health sweep; a client that falls behind is told to
resynchronise rather than fed deltas onto a stale base.

**Step 3** made the stream reachable from a screen nobody is sitting at, without
that screen holding credentials worth stealing.

**Step 4** made the collected data answerable. Audit logs can now be queried by
action, so `ca.expiry_alert` is reachable instead of buried under a day's
issuance; CAs can be filtered by status and expiry window and sorted by urgency,
which is what the health view is built on. Looking for the gaps turned up three
defects worth naming, all of the same kind — a store layer that quietly dropped
what it was handed:

- `UpdateCertificate` never wrote `private_key_encrypted`, so a renewal that
  rotated the key stored the new certificate against the old one.
- `GetCertificate` never read the column either, so private key export answered
  "no private key is stored" for every certificate on PostgreSQL.
- The in-memory store returned live pointers into its own maps, making the
  health sweep and the event stream race over the same records.

**Step 5** connected the UI to the stream. It is built on `fetch` rather than
`EventSource`, which cannot set headers and so cannot carry a bearer token, and
whose reconnect cannot be controlled beyond the server's `retry:` directive. The
load-bearing part is not the transport but the watchdog: a half-open TCP
connection raises no error and a browser will sit on a dead socket for minutes,
so staleness is judged on **data age**, not socket state. Thirty-five seconds
without a byte and the surface degrades — a chip for whoever is at the keyboard,
a banner naming the last confirmed time, and the colour draining out of the
content for whoever is across the room.

**Step 6** turned that into the two views a PKI team actually watches: a CA
health list sorted by urgency with days-remaining as the largest thing on each
row, and `/display`, a fullscreen wall mode that authenticates from a kiosk
token in its launch URL. Nothing needing attention is ever below the fold —
rows that do not fit are counted in the footer rather than silently truncated —
and an empty estate says it is empty rather than showing a calm green screen.

Building chain position first required fixing `ChainResolver`, which had two
defects of the kind that never announce themselves. It assigned depth while
ranging over its input, so a grandchild seen before its parent reported the
wrong depth, and since the input came from a map, identical data gave different
answers on different requests. Worse, a loop in `parent_ca_id` produced a
structure `json.Marshal` refuses to encode *after* Gin had sent the 200, so one
bad row turned the hierarchy endpoint into a successful empty response for the
whole estate — with the CAs in the loop absent from it entirely. A CA that
quietly fails to render is the one nobody notices expiring.

The rest:

- **Chain visualisation.** Each CA now states its position and lineage, and a
  malformed hierarchy is flagged rather than hidden. The tree itself — root →
  intermediate → issuing drawn as a tree, with health carried up it, because a
  healthy issuing CA under an expiring root is not healthy — is not drawn yet.
- **Alerting that reaches people.** Slack, email over SMTP, and a signed generic
  webhook. Today `notifications/dispatcher.go` can POST a webhook and nothing
  calls it. An alert that only lands in an audit table is only marginally better
  than a log line.
- **Acknowledgement and ownership.** Who owns this CA, who was told, who
  silenced it and until when. Without this, an alerting dashboard becomes
  wallpaper within a month. The CA health view has deliberately left both
  columns out rather than filling them with placeholders: `last_alert_threshold`
  records what CertPilot *sent*, not what anyone *saw*, and labelling it
  "acknowledged" would misreport the one thing the view exists for.
- **Expiry timeline.** What breaks in the next 7 / 30 / 90 days, grouped by team
  and environment.

### Phase 4 — A renewal engine that survives 47-day certificates

- Durable job queue with leader election (Postgres advisory locks)
- Exponential backoff with jitter, per-CA rate limiting, idempotency keys
- Renewal scheduled from the CA's ARI window where published, lead time otherwise
- Post-renewal verification: re-scan the endpoint and confirm the new
  certificate is actually being served

### Phase 5 — Discovery that finds what nobody told you about

- CIDR expansion with a worker pool
- **CT log monitoring** — the highest-signal, cheapest addition available, and
  the only way to find certificates issued outside the team's knowledge
- Cloud inventory: ACM, GCP, Azure Key Vault, Kubernetes secrets
- Record full TLS handshake details during the scan, which is what the
  post-quantum posture work is built on

### Phase 6 — Deployment, then the agent

Renewal that does not reach the server is only half the job, and this is where
the commercial tools earn their price.

- Agentless deployers first: Kubernetes, ACM, Azure Key Vault, F5, generic webhook
- Then the agent: one binary that enrols over mTLS, inventories certificate
  stores (filesystem, Java keystore, Windows store, nginx/Apache/HAProxy, IIS),
  **generates keys locally so private keys never traverse the network**,
  submits CSRs, installs renewals, and runs a reload hook

Local key generation is what makes this architecturally safer than the
incumbents rather than merely cheaper.

### Phase 7 — More CAs

HashiCorp Vault PKI first — it is what most organisations running private PKI
already have. Then Microsoft AD CS, AWS Private CA, Google Cloud CAS, EJBCA,
DigiCert, Sectigo.

One gateway that genuinely works beats five stubs.

### Phase 8 — Cryptographic posture

Deliberately **not** "issue ML-DSA certificates". For public TLS that is not yet
possible: the CA/Browser Forum has not updated the Baseline Requirements, and in
February 2026 Google stated Chrome has no near-term plan to accept post-quantum
algorithms in traditional X.509 certificates in its root store, pursuing
[Merkle Tree Certificates](https://datatracker.ietf.org/wg/plants/about/)
instead. The urgent quantum risk — harvest-now-decrypt-later — is already
addressed by hybrid key exchange that browsers ship today.

The useful work is knowing where your cryptography lives and what breaks when it
changes:

- **CBOM export** (CycloneDX 1.6) from the existing inventory
- **Quantum-readiness scoring** per certificate and endpoint, mapped to CNSA 2.0
- **Hybrid key exchange visibility** — "142 of your endpoints do not negotiate
  X25519MLKEM768" is a sentence no open-source tool can produce today
- **ML-DSA and composite issuance in the private-CA gateways**, where it is
  legal and usable now

[Migration 002](migrations/002_crypto_agility.sql) already lays the schema.

---

## Known gaps

Tracked honestly rather than quietly:

- Audit log is an ordinary table — not hash-chained, so a database writer can
  rewrite history
- Renewal has no retry, backoff, or distributed lock; two replicas will renew
  the same certificate concurrently
- The OCSP responder check is an HTTP GET, not an RFC 6960 request, and reports
  responders as healthy that are not
- `migrations/001_initial_schema.sql` references `auth.users` and `auth.jwt()`
  and applies only to Supabase. The Go store layer is plain `pgx` with no
  Supabase dependency; the schema is the only coupling
- Policy is evaluated on issuance only, not renewal; `key_type`, `naming`, and
  `approval_required` rule types are accepted by the schema but not implemented
- `PostgresStore` is verified by hand end to end but has no automated tests; the
  suite runs against the in-memory implementation, which cannot express the
  defects the manual run turned up. A container-backed suite is the fix
- After a long outage the stream's backoff is capped at 30 seconds, so a display
  can take that long to notice the core is back. Deliberate — the alternative is
  a floor of wall displays stampeding a core the instant it restarts

## Deliberately out of scope

- **Being a CA.** EJBCA, step-ca, and Vault do that well. CertPilot manages CAs;
  it does not become one.
- **Replacing cert-manager inside Kubernetes.** Integrate with it instead.
