# Security model

What CertPilot protects, how, and what it does not protect.

- [Threat model](#threat-model)
- [Secrets at rest](#secrets-at-rest)
- [Private key custody](#private-key-custody)
- [Authentication](#authentication)
- [Authorization](#authorization)
- [Transport](#transport)
- [Audit](#audit)
- [Known gaps](#known-gaps)

Report vulnerabilities per [SECURITY.md](../SECURITY.md).

---

## Threat model

CertPilot holds the credentials that issue certificates for an organisation's
estate, and in many deployments the private keys of those certificates. It is a
high-value target by construction.

**Defended against:**

| | |
|:---|:---|
| Database compromise | Private keys and CA credentials are encrypted before they reach the database. A dump without the KEK yields ciphertext |
| Stolen API token | Roles are enforced per route; private-key export is admin-only and audited with actor and IP |
| A compromised gateway host | A gateway holds one CA account's credentials for one call. It cannot read the database or enumerate certificates |
| A compromised agent host | An agent can request certificates only for names an operator granted it in advance, and only its own |
| Network interception | Core↔gateway is mutual TLS 1.3; agent↔core is Ed25519-signed over HTTPS |
| A leaked wall-display token | `GET` only, viewer role, never private keys, revocable, and its last use is recorded |

**Not defended against:**

| | |
|:---|:---|
| A compromised core host with the KEK in memory | It can decrypt everything. This is inherent to a system that must use these secrets |
| A malicious operator | An operator can issue and deploy certificates. That is the job. The audit log records it |
| A compromised CA | If Vault or an ACME account is under someone else's control, CertPilot faithfully manages certificates they issue |
| Tampering with the audit log | The table is not yet hash-chained. See [known gaps](#known-gaps) |

---

## Secrets at rest

Envelope encryption, in [`pkg/secrets`](../pkg/secrets).

```
CERTPILOT_KEK  (32 bytes, base64, AES-256)
      │
      │  wraps a fresh DEK per record
      ▼
   DEK  →  AES-256-GCM  →  ciphertext
      │
      └── context string bound in as additional authenticated data
```

An envelope is `CPS1` ‖ key ID ‖ nonce ‖ wrapped DEK ‖ nonce ‖ ciphertext,
base64-encoded.

Three properties follow, and the third is the one that is easy to miss:

**A fresh DEK per record.** Two records with identical plaintext produce
unrelated ciphertext, and compromising one record's DEK reveals nothing about
another's.

**A key ID in the envelope.** Ciphertext says which KEK sealed it, so rotation
does not require a flag day.

**A context string as additional authenticated data.** Every sealed field
declares what it is:

| Context | Field |
|:---|:---|
| `ca_account:config` | CA account credentials — Vault AppRole, ACME EAB, API tokens |
| `certificate:private_key` | Certificate private keys |
| `deployment_target:config` | Deployment credentials — webhook secrets, F5 passwords |
| `notification_channel:config` | Slack URLs, SMTP passwords |
| `cloud_connection:config` | Cloud provider credentials |
| `ca_account:acme_account_key` | ACME account keys |

Because the context is authenticated, a ciphertext lifted from one column and
pasted into another **fails to decrypt** rather than quietly succeeding. A
notification channel's config cannot be made to open as a private key.

### The KEK

Generate with `make generate-kek`. Supply as `CERTPILOT_KEK`.

> **It is not recoverable.** Lose it and every stored private key and CA
> credential is gone. Put it in a secret manager — AWS Secrets Manager, Vault,
> GCP Secret Manager, a Kubernetes secret backed by one — before the first
> certificate is issued.

The core refuses to start against a database without one. With the in-memory
store it generates an ephemeral key and warns, because nothing there survives a
restart anyway.

Rotation is supported through `CERTPILOT_KEK_RETIRED`. See
[operations.md](operations.md#rotating-the-kek).

---

## Private key custody

The most important distinction in the product, and it is recorded per
certificate in `key_custody`:

| Custody | Where the key is | How it got there |
|:---|:---|:---|
| `CERTPILOT` | Sealed in the database | A gateway generated it, or a CA did |
| `AGENT` | On the host, and nowhere else | The agent generated it locally |
| `EXTERNAL` | Not here at all | Imported or discovered — an observed certificate has no key |

The agent path is the one worth deploying. The agent generates a key, builds a
CSR, and sends the CSR. **There is no field the key could travel in**, the core
has no way to obtain it, and the agent's own code discards it if the request
fails rather than leaving an untracked secret on disk.

Two consequences that are enforced, not documented hopes:

- **A gateway that returns a private key for a CSR-based request is refused.**
  The caller made the CSR, so the key is theirs; a key coming back means the CA
  generated one for a request that already had one.
- **`auto_renew` is forced false on import.** A certificate with no key and no
  CA account cannot renew, and a record claiming it will is the exact failure
  this product exists to prevent.

### Exporting a key

```http
GET /api/v1/certificates/:id/private-key
```

Admin only. Writes `cert.private_key_exported` to the audit log with the
actor and client IP. Returns 404 when no key is stored — the normal case for
imported, discovered, and agent-held certificates.

---

## Authentication

Four methods, each with its own middleware.

### Bearer JWT

The primary path. Two verification modes:

**JWKS (preferred).** The core fetches the identity provider's published public
keys and verifies asymmetric signatures. It holds nothing capable of minting a
token. Works with any OIDC provider — Keycloak, Okta, Entra ID, Auth0,
Authentik, Supabase.

**Shared secret (legacy).** HS256 against `auth.jwt_secret`. This requires the
core to hold a key that can *forge* an admin token. Kept only for Supabase
projects that have not migrated to asymmetric signing keys.

`issuer` and `audience` are validated when configured.

### Display tokens

For a screen in a corridor that nobody logs into. See
[monitoring.md](monitoring.md#wall-displays).

Constraints, none of them configurable:

- Role is hardcoded to `viewer`
- Accepted only on `GET` routes and the SSE endpoint, enforced by dedicated
  middleware rather than by convention
- **Never** valid for `/certificates/:id/private-key` or any write route
- Presented as `?display_token=` or `X-Display-Token` — the query string is
  necessary because `EventSource` cannot set headers, which is also why the
  request logger never writes the query string
- The raw token is shown once at creation; only a SHA-256 hash is stored, and
  comparison is constant-time
- `last_seen_at` and `last_seen_ip` are recorded, so a leaked token is visible
- Creation and revocation are admin-only and audited

### Agent signatures

Ed25519 over a canonical string, in [`pkg/agentauth`](../pkg/agentauth):

```
certpilot-agent-v1
<METHOD>
<PATH>
<unix-seconds>
<hex sha256 of body>
```

Headers: `X-CertPilot-Agent`, `X-CertPilot-Timestamp`, `X-CertPilot-Signature`.
Tolerance is five minutes.

There is deliberately **no nonce store**. Replay within the tolerance window is
possible and the requests are idempotent reports; a nonce table would add a
write per heartbeat across a fleet to prevent a replay that changes nothing.

### Anonymous

Every request treated as admin. Refused unless `mode` is `development` **and**
the bind address is loopback. It applies only when no `Authorization` header is
present at all — an invalid token is always a rejection, never a fallback to
admin.

---

## Authorization

Four roles, enforced per route by `RequireRole`:

| Role | Can |
|:---|:---|
| `admin` | Everything, including private-key export and token management |
| `operator` | Issue, renew, revoke, deploy, acknowledge, configure |
| `auditor` | Read everything, including the audit log |
| `viewer` | Read the inventory and the dashboard |

The role is read from `app_metadata.<role_claim>`, default
`app_metadata.certpilot_role`.

> **Never `user_metadata`.** In Supabase, `raw_user_meta_data` is user-editable
> and appears in `auth.jwt()`. A role read from it is privilege escalation with
> extra steps.

---

## Transport

**Browser → core.** HTTPS, terminated by your reverse proxy. CORS names origins
explicitly; a wildcard is refused in production mode and matches nothing in any
mode.

**Core → gateway.** Mutual TLS 1.3, both ends verified against a shared CA,
`RequireAndVerifyClientCert` on the server. This channel carries CSRs, private
keys and CA credentials, so it is authenticated in both directions by default.
`--insecure` exists for local work and is refused in production mode.

`make dev-certs` writes development material into `.certpilot/pki/`. In
production, issue the gateway a certificate from your own internal CA and point
`--tls-ca` at that CA.

**Agent → core.** HTTPS plus the Ed25519 signature above. The signature is what
authenticates; TLS is what keeps the reports private.

**Core → outbound.** Webhook deployments and notifications are signed with
HMAC-SHA256 ([`pkg/webhooksig`](../pkg/webhooksig)) so a receiver can verify the
request came from CertPilot.

---

## Audit

Every state change writes to `audit_logs` with actor ID, actor email, entity
type, entity ID, and a JSON detail blob.

Specifically audited: certificate issuance, renewal, revocation and deletion;
private-key export with client IP; CA account creation and deletion; deployment
attempts and their outcomes; agent enrolment and refused agent requests;
display-token creation and revocation; acknowledgements; notification delivery
failures.

The log is queryable through `GET /api/v1/dashboard/activity` with an `actions`
filter and an index on `(action, created_at desc)`.

---

## Known gaps

Listed because a security document that only lists strengths is marketing.

**The audit log is not tamper-evident.** Rows are written and can be deleted or
altered by anything with write access to the database. Hash-chaining each row to
its predecessor would make tampering detectable. Not built.

**No nonce store for agent requests.** Replay inside the five-minute window is
possible. The requests are idempotent reports, so the impact is a duplicate
heartbeat.

**The OCSP check is a bare GET.** It records whether a responder answered, not
a parsed and verified OCSP response with a validated signature.

**Key Vault and F5 deployers are unit-tested only.** Written to their published
APIs; never run against a real vault or appliance.

**The KEK lives in an environment variable.** Loading it from a KMS or from
Vault's transit engine — so that the core never holds the key material itself,
only the ability to ask for unwrapping — would be materially better. Not built.

**A compromised certificate cannot be revoked through CertPilot.** The
gateways implement revocation; the core exposes no route that calls it, and
`DELETE /certificates/:id` deletes the record while leaving the certificate
live at the CA. This is the largest gap in this list: the response to a key
compromise currently has to go around the tool.

**No rate limiting on the API.** A stolen operator token can drive issuance as
fast as the CA allows. CA accounts have their own renewal rate limits, which is
a different control.

**Deployment ordering is not expressible.** "Staging, then production" cannot
be declared; the canary is one-per-worker rather than exactly one.
