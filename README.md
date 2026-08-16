# CertPilot

**Open-source PKI and certificate lifecycle management.**

Built for the **central PKI team** — the group that owns the CA hierarchy and
answers for every certificate the organisation serves. One place to watch every
CA and certificate across any authority, public or private, with automated
renewal, CA health monitoring, policy enforcement, and cryptographic posture
reporting.

The dashboard is the point. A central PKI team runs a wall display: CA health
and expiry countdowns have to be visible without anyone asking. An expiring
issuing CA is the failure that takes down everything it ever signed, so the
health sweep runs on a timer and threshold crossings are recorded where a human
will see them.

> **Status: early development.** The core, the gateway plugin architecture, and
> the ACME and self-signed gateways work end to end. Deployment to servers, the
> host agent, network discovery at scale, and the PQC posture reporting are not
> built yet. The [feature table](#what-works-today) below is accurate; anything
> not listed there does not exist. Do not run this in production.

## Why

Certificate validity is collapsing. The CA/Browser Forum schedule
([ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/))
takes maximum TLS certificate lifetime to **200 days in March 2026, 100 days in
March 2027, and 47 days in March 2029**, with domain validation reuse falling to
10 days on the same schedule. At 47 days, ten thousand certificates means
roughly 670 renewals a day, continuously. Manual tracking stopped being viable
some time ago; spreadsheet-and-calendar tracking is already broken.

The open-source ecosystem is good at *getting* a certificate — certbot, lego,
cert-manager, step-ca all do it well. What is missing is everything around it:
knowing what you already have, where it is installed, whether it complies with
your policy, and getting the renewed certificate onto the machine that serves
it. That gap is where the commercial tools live, and it is what CertPilot is
aimed at.

## Architecture

Every CA provider runs as its own process — a *gateway* — speaking gRPC to the
core. You run only the gateways you need, and adding support for a new CA means
writing a plugin rather than patching the platform.

```
                    ┌──────────────────────────┐
                    │      Vue 3 Frontend      │
                    └────────────┬─────────────┘
                                 │ HTTPS
                    ┌────────────▼─────────────┐
                    │     CertPilot Core       │
                    │  REST API · PKI engine   │
                    │  Renewal · Policy        │
                    │  Plugin manager          │
                    └──┬──────────────────┬────┘
                       │  mutual TLS      │
              ┌────────▼──────┐   ┌───────▼────────┐
              │ ACME gateway  │   │ Self-signed    │
              │ RFC 8555      │   │ gateway (dev)  │
              └───────────────┘   └────────────────┘
                       │
              Let's Encrypt, ZeroSSL,
              BuyPass, Google Trust
              Services, step-ca
```

The core-to-gateway channel carries certificate signing requests, private keys,
and CA credentials, so it is **mutually authenticated by default**. Running it
unauthenticated is possible for local development but has to be asked for
explicitly.

## What works today

| Capability | State | Notes |
|:---|:---|:---|
| ACME issuance (RFC 8555) | ✅ | Full order flow: authorize, solve, finalize, download chain |
| ACME challenges | ✅ | `dns-01` via Cloudflare or a generic webhook; `http-01` via a built-in listener |
| Wildcard certificates | ✅ | Over `dns-01` |
| External Account Binding | ✅ | Required by ZeroSSL, Google Trust Services, SSL.com |
| ACME revocation | ✅ | Real revocation; already-revoked is treated as success |
| Renewal information (RFC 9773) | ✅ | Reads the CA's suggested renewal window where published |
| Self-signed gateway | ✅ | Development and testing |
| Secrets encrypted at rest | ✅ | AES-256-GCM envelope encryption, context-bound, rotatable |
| Mutual TLS, core ↔ gateway | ✅ | Required by default; `make dev-certs` to get started |
| OIDC authentication | ✅ | Any provider, via JWKS; legacy shared-secret path also supported |
| RBAC | ✅ | admin / operator / auditor / viewer, enforced per route |
| Audit log | ⚠️ | Recorded, but the table is not yet tamper-evident |
| Automated renewal | ⚠️ | Works; no retry, backoff, or distributed locking yet |
| CA health monitoring | ⚠️ | Scheduled sweep, expiry thresholds, and CRL freshness are real; the OCSP check is not a real OCSP request |
| CA expiry alerting | ⚠️ | Threshold crossings recorded to the audit log; no Slack/email/PagerDuty delivery yet |
| Live dashboard updates | ⚠️ | The core streams over Server-Sent Events; the Vue frontend does not consume it yet |
| Kiosk display tokens | ✅ | Read-only, viewer-scoped, expiring, revocable credentials for a wall display |
| Policy engine | ⚠️ | `key_size`, `max_lifetime`, `ca_restriction`; other rule types are not implemented |
| Discovery | ⚠️ | Single `host:port` scan only. No CIDR, CT logs, or cloud inventory |
| Notifications | ⚠️ | Generic webhook only. No Slack, Teams, email, or PagerDuty |
| Deployment to servers | ❌ | Not started |
| Host agent | ❌ | Not started |
| PQC posture / CBOM | ❌ | Schema is ready ([002](migrations/002_crypto_agility.sql)); reporting is not built |
| Vault, GCP CAS, AWS PCA, DigiCert, Sectigo gateways | ❌ | Not started |

## Quick start

Requires Go 1.22+ and Node 20+. No database or cloud account needed to try it —
the core runs with an in-memory store seeded with sample data.

```bash
git clone https://github.com/your-org/certpilot.git
cd certpilot
make dev-certs
```

That writes development mTLS material into `.certpilot/pki/`. Then, in separate
terminals:

```bash
make run-gateway-selfsigned
```

```bash
cp config.example.yaml config.dev.yaml
export CERTPILOT_KEK=$(make -s generate-kek | cut -d= -f2-)
make run-core
```

```bash
make run-frontend
```

The API is on `:8080`, the frontend on `:5173`.

### Persisting to a database

The in-memory store is seeded demonstration data and is discarded on every
restart. To keep what you do, point the core at PostgreSQL — Supabase or
otherwise:

```bash
export CERTPILOT_DB_URL='postgres://postgres.<ref>:<password>@<host>:5432/postgres?sslmode=require'
make migrate
make run-core
```

The dashboard then starts at zero, because a fresh database is empty. Two ways
that could be a lie rather than a fact — an unmigrated schema, and a connection
that row-level security silently filters to nothing — are refused at startup
instead of rendered as green tiles.

[docs/database.md](docs/database.md) covers which Supabase connection string to
use and why the choice matters, why migration 005 is not optional, and what to do
on plain PostgreSQL.

### Issue a certificate

```bash
curl -X POST localhost:8080/api/v1/ca-accounts -H 'Content-Type: application/json' -d '{
  "name": "selfsigned-dev",
  "provider_type": "selfsigned",
  "gateway_addr": "localhost:9091",
  "server_name": "localhost",
  "config": {"validity_days": 90}
}'
```

```bash
curl -X POST localhost:8080/api/v1/certificates -H 'Content-Type: application/json' -d '{
  "common_name": "test.example.local",
  "sans": ["www.test.example.local"],
  "ca_account_id": "<id from above>",
  "key_type": "ECDSA",
  "key_size": 256
}'
```

### Against a real CA

Point the ACME gateway at Let's Encrypt staging and configure `dns-01`:

```bash
make run-gateway-acme
```

```bash
curl -X POST localhost:8080/api/v1/ca-accounts -H 'Content-Type: application/json' -d '{
  "name": "letsencrypt-staging",
  "provider_type": "acme",
  "gateway_addr": "localhost:9092",
  "server_name": "localhost",
  "config": {
    "directory_url": "letsencrypt-staging",
    "email": "you@example.com",
    "challenge": "dns-01",
    "dns_provider": "cloudflare",
    "dns_config": {"api_token": "YOUR_CLOUDFLARE_TOKEN"}
  }
}'
```

The gateway validates this configuration before it is stored, so a wrong token
surfaces immediately rather than during a renewal at 3am.

## Security model

Read this before deploying anything.

**Private keys.** The best outcome is that CertPilot never sees one. Supply a
CSR with a certificate request and the key stays wherever it was generated. When
no CSR is supplied the gateway generates a key, and that key is sealed with
AES-256-GCM before it reaches the database. Keys are never included in list or
detail responses; exporting one is a separate admin-only endpoint that writes an
audit record.

**Key encryption.** Set `CERTPILOT_KEK` to a base64 32-byte key
(`make generate-kek`). Values are sealed under a per-record data key which is
itself wrapped by the KEK, so rotation is incremental: put the new key in
`CERTPILOT_KEK`, list the old one in `CERTPILOT_KEK_RETIRED`, and re-seal at
leisure. Ciphertexts are bound to the field they belong to, so a blob cannot be
moved from one column to another. The core refuses to start against a database
without a KEK.

**Transport.** Core-to-gateway is mutual TLS 1.3 with both ends verified against
a shared CA. gRPC reflection is off by default.

**Authentication.** Prefer `auth.jwks_url` — the core then verifies
asymmetrically signed tokens and holds nothing capable of minting one. Roles are
read only from `app_metadata`, never `user_metadata`, which the user can write.
Accepted signing algorithms are pinned. An invalid token is always rejected;
there is no development fallback that grants admin.

**Display tokens.** A wall display cannot use the bearer flow — `EventSource`
cannot set headers — and the obvious workaround, leaving an operator session
logged in on a machine in a corridor, hands that machine the authority to issue,
revoke, and export private keys. A display token is a separate credential that
carries none of it. The role it grants is the constant `viewer`; anything but a
`GET` is refused on every route; private-key export, token enumeration, and the
actor-attributed activity feed are refused by path, independently of the role
gates those routes already carry. Tokens expire, are revocable, and record where
and when they were last used. Only a SHA-256 is stored, so the raw value exists
in exactly one response and nowhere else.

**Production mode** refuses anonymous access, an insecure gateway channel, and a
wildcard CORS origin. These are the settings that look harmless locally and
travel to production unnoticed.

### Known gaps

- The audit log is an ordinary table. It is not yet hash-chained, so a database
  writer can rewrite history.
- Renewal has no retry, backoff, or distributed lock. Two core replicas will
  renew the same certificate concurrently.
- The OCSP responder check is an HTTP GET, not an RFC 6960 request, and reports
  a responder as healthy when it should not.
- `migrations/001_initial_schema.sql` defines `get_user_role()` in terms of
  `auth.jwt()` and grants its RLS policies to the `authenticated` role, neither
  of which exists outside Supabase, so it will not apply to vanilla PostgreSQL.
  Migrations 002–005 are portable, and the Go store layer is plain `pgx` with no
  Supabase dependency. The `auth.users` foreign keys 001 declared were a harder
  problem than a portability wart — they made Supabase Auth the only identity
  provider the core could write against, and broke issuance under any other —
  and [005](migrations/005_identity_decoupling.sql) removes them.
- Trusted proxies are not configured, so client IPs are taken from
  `X-Forwarded-For` whoever sends it. Every recorded IP — audit entries and
  display-token `last_seen_ip` alike — is therefore a hint, not evidence.
- Display tokens are not rate-limited. The credential is 256 bits, so guessing
  is not the concern; a stolen one being used heavily is, and nothing throttles
  it beyond revocation.
- `PostgresStore` is exercised by review and by the compile checker, not by
  tests. The store test suite runs against the in-memory implementation, which
  the two are written to keep in step — filters evaluate the same predicates and
  the dashboard buckets are defined clause for clause — but nothing yet proves
  they agree. A container-backed suite is the fix and is not written.
- `/dashboard/activity` is still available to any authenticated reader,
  including `viewer`. Kiosk display tokens are refused it outright, since audit
  entries carry actor identity and a corridor screen should not name who deleted
  what — but a signed-in viewer is a person, and is not restricted.

## Post-quantum

The plan here is deliberately not "issue ML-DSA certificates", because for
public TLS that is not currently possible: the CA/Browser Forum has not updated
the Baseline Requirements to permit ML-DSA, and in February 2026 Google stated
Chrome has no near-term plan to accept post-quantum algorithms in traditional
X.509 certificates in its root store — it is pursuing
[Merkle Tree Certificates](https://datatracker.ietf.org/wg/plants/about/)
instead. Meanwhile the urgent quantum risk, harvest-now-decrypt-later, is
already addressed by hybrid key exchange that browsers deploy today.

So the work is **crypto-agility posture**: knowing where your cryptography
lives, how exposed it is, and what breaks when the algorithms change.

[Migration 002](migrations/002_crypto_agility.sql) lays the groundwork. It
removes the `key_type IN ('RSA','ECDSA','Ed25519')` constraints that would
otherwise block PQC entirely, replaces them with an extensible algorithm table
covering ML-DSA, SLH-DSA, Falcon and composite schemes, and adds tables for
observed TLS posture. The reporting built on top — CBOM export, readiness
scoring, hybrid key exchange visibility — is not implemented yet.

ML-DSA issuance will land first in the private-CA gateways (Vault, step-ca, AWS
Private CA), where it is usable today.

## Writing a gateway

A gateway implements one gRPC service,
[`CertificateProviderService`](proto/provider/v1/provider.proto): issue, renew,
revoke, status, CA info, capabilities, health, and config validation. See
[docs/writing-a-gateway.md](docs/writing-a-gateway.md), and
[`gateways/selfsigned`](gateways/selfsigned) for the smallest complete example.

## Development

```bash
make test        # all modules
make test-race   # under the race detector
make lint        # go vet and gofmt
make proto       # regenerate protobuf code
make help        # everything else
```

The repository is a Go workspace of four modules: `pkg` (shared), `core`, and
one per gateway. Tooling iterates over them, since a single `./...` from the
root does not cover a workspace.

## Tech stack

| Layer | Technology |
|:---|:---|
| Backend | Go |
| Frontend | Vue 3, TypeScript, Vite, Pinia |
| Database | PostgreSQL 17 (Supabase supported, not required) |
| Auth | OIDC via JWKS |
| Plugin transport | gRPC over mutual TLS |
| Packaging | Docker |

## Roadmap

See [ROADMAP.md](ROADMAP.md). The next milestone is a monitoring surface a team
can leave on a screen: live updates, a CA health wall view, chain visualisation,
and alerting that actually reaches people.

## License

[Apache 2.0](LICENSE)
