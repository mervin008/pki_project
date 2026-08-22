# CertPilot

**Open-source PKI and certificate lifecycle management.**

Built for the **central PKI team** — the group that owns the CA hierarchy and
answers for every certificate the organisation serves. One place to watch every
CA and certificate across any authority, public or private, with automated
renewal, CA health monitoring, deployment to the servers that serve them,
policy enforcement, and cryptographic posture reporting.

The dashboard is the point. A central PKI team runs a wall display: CA health
and expiry countdowns have to be visible without anyone asking. An expiring
issuing CA is the failure that takes down everything it ever signed, so the
health sweep runs on a timer, changes are pushed to the browser as they happen,
and there is a fullscreen mode built for a screen nobody is sitting at.

One rule drives that whole surface: **a dashboard that stops updating must look
broken, not healthy.** A frozen screen showing green manufactures exactly the
false confidence this tool exists to prevent.

> **Status: early development.** Everything in the table below works end to end
> and has been run against real certificate authorities, a real database and
> real servers. The table is accurate; anything not in it does not exist. The
> frontend is deliberately minimal pending a redesign, and there is **no
> revocation endpoint** — see [known gaps](docs/security.md#known-gaps). Do not
> run this in production yet.

## Why

Certificate validity is collapsing. The CA/Browser Forum schedule
([ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/))
takes maximum TLS certificate lifetime to **200 days in March 2026, 100 days in
March 2027, and 47 days in March 2029**, with domain validation reuse falling to
10 days on the same schedule. At 47 days, ten thousand certificates means
roughly 670 renewals a day, continuously. Spreadsheet-and-calendar tracking is
already broken.

The open-source ecosystem is good at *getting* a certificate — certbot, lego,
cert-manager and step-ca all do it well. What is missing is everything around
it: knowing what you already have, where it is installed, whether it complies
with your policy, and getting the renewed certificate onto the machine that
serves it. That gap is where the commercial tools live, and it is what
CertPilot is aimed at.

## Architecture

Every CA provider runs as its own process — a *gateway* — speaking gRPC to the
core. You run only the gateways you need, and adding support for a new CA means
writing one, in any language, without touching the core.

```
                    ┌────────────▼─────────────┐
                    │     CertPilot Core       │
                    │  REST API · PKI engine   │
                    │  Renewal · Policy        │
                    │  Plugin manager          │
                    └────────────┬─────────────┘
                                 │ mutual TLS
        ┌────────────────────────┼────────────────────────┐
┌───────▼────────┐      ┌────────▼───────┐      ┌─────────▼──────┐
│ ACME gateway   │      │ Vault gateway  │      │ Self-signed    │
│ RFC 8555       │      │ PKI engine     │      │ gateway (dev)  │
└────────────────┘      └────────────────┘      └────────────────┘
```

Separately, a **host agent** runs on the machines where certificates are
served. It generates its own private keys and never sends them anywhere —
CertPilot cannot produce them and does not claim to.

[docs/architecture.md](docs/architecture.md) explains the three decisions the
whole design follows from.

## What works today

| Capability | State | Notes |
|:---|:---|:---|
| ACME issuance (RFC 8555) | ✅ | Full order flow: authorize, solve, finalize, download chain |
| ACME challenges | ✅ | `dns-01` via Cloudflare or a generic webhook; `http-01` via a built-in listener |
| Wildcard certificates | ✅ | Over `dns-01` |
| External Account Binding | ✅ | Required by ZeroSSL, Google Trust Services, SSL.com |
| ACME revocation | ✅ | Real revocation; already-revoked is treated as success |
| Renewal information (RFC 9773) | ✅ | Renews inside the CA's suggested window, at a random instant within it. A window pulled forward — what a CA does during a mass revocation — is a CRITICAL alert carrying the CA's own explanation |
| Vault PKI issuance | ✅ | Issue, renew, revoke and status against a Vault PKI mount, with token, AppRole or Kubernetes auth. Signs CSRs by preference, so a key generated on the host stays there. Verified against a real Vault, not only a stub |
| Vault issuer visibility | ✅ | The only gateway that answers `GetCAInfo`: the mount's issuers, their expiry and their CRL. Vault **refuses** to sign a certificate that would outlive its issuer, so the day an issuing CA comes within one certificate lifetime of expiry, every renewal through it fails at once — this is said at configuration time instead |
| Self-signed gateway | ✅ | Development and testing |
| Secrets encrypted at rest | ✅ | AES-256-GCM envelope encryption, context-bound, rotatable |
| Mutual TLS, core ↔ gateway | ✅ | Required by default; `make dev-certs` to get started |
| OIDC authentication | ✅ | Any provider, via JWKS; legacy shared-secret path also supported |
| RBAC | ✅ | admin / operator / auditor / viewer, enforced per route |
| Audit log | ⚠️ | Recorded, but the table is not yet tamper-evident |
| Ownership and acknowledgement | ✅ | Who owns a CA, who acknowledged an alert and why. Silencing suppresses delivery only — an acknowledged CA never leaves the dashboard |
| Automated renewal | ✅ | Durable queue, leases, deadline-aware backoff, ARI, and post-renewal verification. Safe on N replicas with no leader |
| CA health monitoring | ⚠️ | Scheduled sweep, expiry thresholds, and CRL freshness are real; the OCSP check is not a real OCSP request |
| CA expiry alerting | ✅ | Threshold crossings are delivered to Slack, a signed webhook, or email over SMTP, with per-channel severity and topic filters |
| Live dashboard updates | ✅ | Server-Sent Events end to end. The client tracks data age independently, so a dead feed degrades the surface instead of freezing it on green |
| CA health view | ✅ | Every CA by urgency: expiry countdown, chain position, CRL freshness, issuance volume, owner, and acknowledgement state |
| Wall display mode | ✅ | `/display` — fullscreen, no chrome, readable across a room, authenticated by a kiosk token in the launch URL |
| Kiosk display tokens | ✅ | Read-only, viewer-scoped, expiring, revocable credentials for a wall display |
| CA hierarchy tree | ⚠️ | Position and lineage are shown per CA and a malformed hierarchy is flagged; the tree is not drawn as a tree |
| Policy engine | ⚠️ | `key_size`, `max_lifetime`, `ca_restriction`; other rule types are not implemented |
| Discovery | ✅ | Scans hosts, CIDR networks, and address ranges on a schedule; records the full handshake, says which certificates nobody manages, and reports what changed since last time |
| Certificate Transparency | ✅ | Watches CT for certificates issued in your name — including ones never deployed anywhere you could scan. A check that could not run is never reported as a check that found nothing |
| Cloud inventory | ✅ | Reads ACM, Azure Key Vault, Google Cloud, and Kubernetes TLS secrets. Reports which certificates the provider itself will not renew — the ones everybody assumes are automatic |
| Renewal queue | ✅ | Durable jobs with leases, an attempt log, and backoff that tightens as expiry approaches. Safe on N replicas with no leader. Per-CA rate limits defer rather than fail |
| Post-renewal verification | ✅ | Re-probes the endpoints discovery has seen serving a certificate and reports when a renewal never reached them — the green-dashboard-over-an-expiring-estate failure, caught |
| Notifications | ✅ | Slack (Block Kit), signed generic webhook, SMTP email. Deliberately not Teams or PagerDuty |
| Store conformance testing | ✅ | One suite run against both the in-memory store and a real PostgreSQL, covering the four classes of defect that had only ever been found by running the thing. Plain PostgreSQL is a supported target and proven by the suite |
| Cryptographic posture | ✅ | Which endpoints negotiate a post-quantum key exchange and which do not, from real handshakes; CNSA 2.0 conformance per certificate; CycloneDX 1.6 CBOM export validated against the published schema. Post-quantum *issuance* waits for `crypto/x509` |
| Deployment to servers | ✅ | Durable, retried, audited deployment to a signed webhook, a host running the agent, AWS ACM, Azure Key Vault and F5 BIG-IP. **A renewal deploys itself**, and a failing target halts the rest of the rollout rather than letting a bad certificate march through the estate. Key Vault and F5 are written to their published APIs and unit-tested; neither has been run against a real vault or appliance |
| Host agent | ✅ | One binary that enrols, inventories, **requests certificates with keys it generates locally and never sends** — CertPilot cannot produce them and does not claim to — then installs them where the server actually reads them and reloads it. Bounded by grants an operator writes in advance |
| Vault issuers in the CA inventory | ✅ | Connecting a CA account records the CAs behind it, and from that moment they are monitored, thresholded and alerted on like everything else. The importer refreshes what the certificate says and never touches what an operator decided — the name, the thresholds, the owning team |
| Certificate revocation | ❌ | The ACME and Vault gateways implement it; the core exposes no route that calls it. `DELETE /certificates/:id` deletes the record and leaves the certificate live at the CA |
| GCP CAS, AWS PCA, DigiCert, Sectigo gateways | ❌ | Not started |
## Quick start

Requires Go 1.26+ and Node 20+. No database or cloud account needed — the core
runs with an in-memory store seeded with sample data.

```bash
git clone https://github.com/your-org/certpilot.git
cd certpilot
make dev-certs
```

Then, in separate terminals:

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

The API is on `:8080`, the frontend on `:3000`. Three pages are worth opening
first: `/` for the dashboard, `/ca-health` for every CA sorted by urgency, and
`/display` for the fullscreen wall view.

[docs/getting-started.md](docs/getting-started.md) goes further — issuing a
certificate, pointing at a real CA, and putting it on a wall.

## Documentation

| | |
|:---|:---|
| [Getting started](docs/getting-started.md) | The first fifteen minutes |
| [Architecture](docs/architecture.md) | How the pieces fit and why |
| [Configuration](docs/configuration.md) | Every setting for every process |
| [Operations](docs/operations.md) | Deploying, migrating, KEK rotation, backups, what to watch |
| [Security](docs/security.md) | Threat model, key custody, and the known gaps |
| [Monitoring](docs/monitoring.md) | CA health, alerting, acknowledgement, wall displays |
| [Deployment](docs/deployment.md) | Getting a renewed certificate to what serves it |
| [The agent](docs/agent.md) | Host agent, and the keys CertPilot never sees |
| [Discovery](docs/discovery.md) | Network scans, CT logs, cloud inventory |
| [Posture](docs/posture.md) | CNSA 2.0 scoring and CBOM export |
| [Vault gateway](docs/gateways/vault.md) | HashiCorp Vault PKI in depth |
| [Writing a gateway](docs/writing-a-gateway.md) | Adding a CA, in any language |
| [API reference](docs/api-reference.md) | Every endpoint |
| [Database](docs/database.md) | Schema, migrations, PostgreSQL and Supabase |
| [Troubleshooting](docs/troubleshooting.md) | Symptom, cause, fix |

[docs/README.md](docs/README.md) is the index.

## Security

Certificate private keys and CA credentials are encrypted before they reach the
database, using AES-256-GCM envelope encryption with a context string bound in
as additional authenticated data — so a ciphertext lifted from one column and
pasted into another fails to decrypt rather than quietly succeeding.

The core-to-gateway channel is mutually authenticated TLS 1.3. Agents sign
every request with Ed25519. Roles are read from `app_metadata` and never from
`user_metadata`. Production mode refuses anonymous access, an insecure gateway
channel, a wildcard CORS origin, a missing auth method, and a missing database
— by refusing to start, not by warning.

[docs/security.md](docs/security.md) has the threat model and an honest list of
what is not covered. Report vulnerabilities per [SECURITY.md](SECURITY.md).

## Development

```bash
make build        # every binary
make test         # every module
make test-race    # under the race detector
make test-store   # the store conformance suite, against a real PostgreSQL
make lint         # go vet, gofmt, staticcheck
```

This is a Go workspace with six modules, so `go build ./...` from the root does
not work — build from inside a module or use the `make` targets.

## Tech stack

Go 1.26 · Gin · pgx · gRPC · PostgreSQL · Vue 3 · TypeScript · Tailwind ·
daisyUI · Chart.js

## Roadmap

Every phase on the [ROADMAP](ROADMAP.md) is built. It is worth reading as a
record of what was found on the way — the defects that only a real database
surfaced, and the ones only a real CA did.

## License

[Apache 2.0](LICENSE).
