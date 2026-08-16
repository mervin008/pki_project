# Roadmap

What is built, what is next, and why in that order. Replaces the original
`plan.md`, whose ordering was right but whose timeline compressed roughly six
months of work into what read like a fortnight.

The [README](README.md) has the authoritative capability table. This document
covers sequence and reasoning.

## The forcing function

CA/Browser Forum [ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)
takes maximum TLS certificate validity to **200 days (March 2026)**,
**100 days (March 2027)**, and **47 days (March 2029)**, with domain validation
reuse falling to 10 days over the same period.

At 47 days, renewing at the one-third mark means every certificate renews about
every 15 days. Ten thousand certificates is roughly 670 renewals a day — one
every two minutes, continuously. That number is what determines the architecture
of phases 3 through 5.

## Done

### Phase 0 — Accurate claims

The README described features that did not exist. Corrected, along with removing
a stray file, fixing `.gitignore` so private key material cannot be committed,
and removing the live Supabase project reference from the example config.

### Phase 1 — Security floor

- **`pkg/secrets`** — AES-256-GCM envelope encryption. Per-record data keys
  wrapped by a KEK, ciphertexts bound to their field via additional
  authenticated data, incremental key rotation via `CERTPILOT_KEK_RETIRED`.
- **Mutual TLS** on the core-to-gateway channel, required by default, reflection
  off, with `make dev-certs` so enabling it is one command rather than a reason
  to disable it.
- **Authentication** — the dev-mode fallback that granted admin on an *invalid*
  token is gone. JWKS verification, pinned signing algorithms, expiry required,
  roles read only from `app_metadata`.
- **Key persistence** — issued certificates now store their private key, sealed.
  Previously the core never read `private_key_pem` from the gateway, so every
  certificate it issued was unusable.
- **Fail closed** — a policy engine that cannot be consulted blocks issuance; a
  gateway returning anything other than a certificate produces an error rather
  than a record marked `ISSUED`.
- **Config validation** — production mode refuses anonymous access, an insecure
  gateway channel, and wildcard CORS.

### Phase 2 — Working ACME

Full RFC 8555: authorize, solve, finalize, download chain. Plus persistent
account keys (the previous code registered a new ACME account on every
issuance), External Account Binding for ZeroSSL and Google Trust Services, real
revocation, `dns-01` via Cloudflare or a generic signed webhook, `http-01` via a
built-in listener, and wildcards.

**RFC 9773 (ARI)** is implemented — certificate identifier derivation, window
parsing, and randomised selection within the window. Renewing at window start
would relocate a thundering herd rather than disperse it.

ARI matters more than it first appears. In March 2026 Let's Encrypt ran a
mass-revocation simulation across three million production certificates and
found 94% of clients were not listening. It is the mechanism by which the
ecosystem survives a revocation event, and it costs about two hundred lines.

### Phase 6a — PQC groundwork

[Migration 002](migrations/002_crypto_agility.sql) removes the
`key_type IN ('RSA','ECDSA','Ed25519')` constraints that would otherwise block
post-quantum work entirely, replaces them with an extensible `key_algorithms`
table covering ML-DSA, SLH-DSA, Falcon and composite schemes, and adds tables
for observed TLS posture. Done early because it is a five-minute change now and
a migration against live data later.

---

## Next

### Phase 3 — A renewal engine that survives 47-day certificates

The current scheduler renews serially in a bare loop on `context.Background()`:
no timeout, no retry, no backoff, no concurrency limit, no distributed lock. One
hung gateway blocks every remaining renewal, and two core replicas will renew
the same certificate simultaneously.

- Durable job queue, backed by the PostgreSQL that is already a dependency
- Leader election via advisory lock
- Exponential backoff with jitter; per-CA rate limiting
- Idempotency keys, so a retry cannot double-issue
- Consume ARI windows for scheduling rather than a fixed lead time
- Post-renewal verification: re-scan the endpoint and confirm the new
  certificate is actually being served

Also here: hash-chain the audit log, so "immutable" is true rather than
aspirational.

### Phase 4 — Discovery that finds things

Discovery is currently one function scanning one `host:port`, and results are
never persisted.

- CIDR expansion with a bounded worker pool
- **CT log monitoring** — the highest-signal, cheapest addition available,
  because it surfaces certificates nobody knew had been issued
- Cloud inventory: ACM, GCP, Azure Key Vault
- Kubernetes secrets
- **Record the TLS handshake** — negotiated group, cipher suite, protocol
  version. The scanner already completes a handshake; capturing what it
  negotiated is what makes the posture reporting in phase 6 possible
- Persist to `discovery_scans` and `discovery_results`, which means adding
  discovery methods to the store interface

### Phase 5 — The agent

The largest piece, and the one that decides whether this is a real product.

Getting a certificate is a solved problem. What nobody has, open source, is
*"renew four thousand certificates across nginx boxes, F5s, Java keystores,
three Kubernetes clusters, ACM and IIS without an outage."* Keyfactor's moat is
its orchestrator agent. CertPilot currently has zero lines of one.

A single Go binary that:

- Enrolls over mTLS with a bootstrap token
- Inventories certificate stores — filesystem, Java keystore, Windows
  certificate store, nginx/apache/haproxy configuration, IIS
- **Generates keys locally and submits CSRs, so private keys never traverse the
  network.** This is the architectural argument for choosing CertPilot over the
  incumbents rather than merely a cheaper version of them
- Installs renewed certificates and runs a reload hook

Plus agentless deployers for Kubernetes, ACM, Azure Key Vault, F5, and a generic
webhook.

### Phase 6 — Crypto-agility posture

The schema is ready; the reporting is not.

- **CBOM export** (CycloneDX 1.6) generated from the inventory
- **Quantum-readiness scoring** per certificate and endpoint, mapped against
  CNSA 2.0 and NIST migration deadlines
- **Hybrid key exchange reporting** — *"142 of your endpoints do not negotiate
  X25519MLKEM768"* is a sentence no open-source tool can currently produce
- **ML-DSA and composite issuance** in the private-CA gateways, where it is
  usable today

On the deliberate omission: this is not "issue ML-DSA certificates for public
TLS", because that is not currently possible. The CA/Browser Forum has not
updated the Baseline Requirements to permit ML-DSA, and in February 2026 Google
stated Chrome has no near-term plan to accept post-quantum algorithms in
traditional X.509 certificates in its root store — it is pursuing
[Merkle Tree Certificates](https://datatracker.ietf.org/wg/plants/about/)
instead, and Let's Encrypt has committed to that direction.

Meanwhile the quantum risk with an actual deadline — harvest-now-decrypt-later —
is already addressed by hybrid key exchange that browsers deploy by default.
Signature forgery cannot be applied retroactively, so PQC signatures are a
migration problem, not an emergency.

MTC is tracked as a research spike, not a roadmap item. Being the open-source
tool that already models cryptographic posture when it lands is a better
position than betting early on a moving specification.

---

## Deliberately not doing yet

**More gateways.** One that genuinely works beats five stubs. ACME plus Vault
covers the large majority of real deployments; the plugin contract should earn
the rest from contributors.

**More frontend.** The Vue app is already further along than the backend
justifies. A CLM tool wins on its engine.

**Moving off PostgreSQL.** `001_initial_schema.sql` is coupled to Supabase
through `auth.users` and `auth.jwt()`, which needs fixing — but the Go store
layer is plain `pgx` and already portable.

## Also outstanding

- The OCSP responder check issues a plain GET rather than an RFC 6960 request,
  and reports responders as healthy when it should not
- Policy `key_type`, `naming`, and `approval_required` rule types are accepted
  by the schema but not implemented
- Policy is evaluated on issuance only, never on renewal
- Notifications are a bare webhook POST that nothing calls
- A CLI (`certpilot list --expiring 30`, `certpilot renew <id>`,
  `certpilot scan 10.0.0.0/24`) would likely do more for adoption than any
  further UI work
