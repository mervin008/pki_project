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
| Tampering with the audit log | Every entry is chained with a keyed tag. The key is derived from `CERTPILOT_KEK` and never stored in the database, so a database-only attacker can alter a row but cannot forge a tag that agrees with it |

**Not defended against:**

| | |
|:---|:---|
| A compromised core host with the KEK in memory | It can decrypt everything. This is inherent to a system that must use these secrets |
| A malicious operator | An operator can issue and deploy certificates. That is the job. The audit log records it |
| A compromised CA | If Vault or an ACME account is under someone else's control, CertPilot faithfully manages certificates they issue |
| Rewriting the audit log with the KEK in hand | Somebody holding both the database and the key can recompute the whole chain from any point. Detecting that needs an anchor outside the system; see [known gaps](#known-gaps) |
| Truncating the audit log | Deleting the newest entries leaves a shorter chain that is internally consistent. Same anchor problem |

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

Four credentials, each with its own middleware: a session cookie, a bearer JWT,
a display token, an agent signature. Federated sign-in is listed here too, but
it is not a fifth credential — it is one of the two ways to obtain the first.

There is no anonymous mode, locally or otherwise: `auth.allow_anonymous` is
refused by configuration validation rather than ignored, so an operator who has
it set finds out at start-up instead of on the day somebody is refused.

### Session cookies

How a person is authenticated, whether they signed in with a local password or
through an identity provider.

An opaque random value in an `HttpOnly`, `SameSite=Strict` cookie, stored as a
SHA-256 hash — so the core holds nothing that can forge one, and a database dump
does not yield a usable session. Twelve hours. Account status is re-checked on
**every** request, not only at sign-in, so suspending somebody takes effect
while they are looking at the screen.

Local sign-in is throttled in the database rather than in memory (8 failures, 15
minutes), because the core runs as several replicas and an in-process counter
resets with every request that lands on a different one.

### Federated sign-in

OpenID Connect, authorization code with PKCE. There is no client secret; a
single-page application cannot keep one.

**The core redeems the code, not the browser.** `POST /api/v1/auth/callback`
takes the code, the PKCE verifier and the nonce the browser generated. The core
exchanges the code at the provider's token endpoint, verifies the returned ID
token — signature against the JWKS, issuer, audience against the *client id*,
and the nonce against the one supplied — resolves the identity against
CertPilot's users table, and returns the same session cookie a password sign-in
gets.

This is a backend-for-frontend, and it exists to answer one question: where does
the credential that survives a page reload live? A page that redeems the code
itself receives a refresh token and has nowhere safe to put it — every storage a
browser page can reach is readable by script on that origin. CertPilot used to
keep it in `localStorage` and document the trade-off. Now the browser handles no
token at all.

The provider's refresh token is **discarded**, not stored. CertPilot's own
session is the durable credential, and keeping a second one would mean holding a
provider secret at rest to duplicate what the sessions table already does.

What that costs, stated plainly: a federated session outlives revocation at the
identity provider until it expires. CertPilot's answer to "this person should no
longer have access" is suspending the account, which is checked on every request
and ends every session immediately. The provider says who you are; CertPilot
says what you may do.

### Bearer JWT

For automation — agents' own API calls, CI, scripts. The browser stopped using
this path when the core took over redeeming the authorization code. Two
verification modes:

**JWKS (preferred).** The core fetches the identity provider's published public
keys and verifies asymmetric signatures. It holds nothing capable of minting a
token. Works with any OIDC provider — Keycloak, Okta, Entra ID, Auth0,
Authentik, Supabase.

**Shared secret (legacy).** HS256 against `auth.jwt_secret`. This requires the
core to hold a key that can *forge* an admin token. Kept only for Supabase
projects that have not migrated to asymmetric signing keys.

`issuer` and `audience` are validated when configured.

An **ID token** is verified by different rules and by a separate function. Its
audience is the client id rather than the API audience, and its nonce is
required — conflating the two documents is how an audience check gets skipped.
Accepted algorithms are pinned in both. That pinning is load-bearing on any
instance that has both a JWKS and a legacy `jwt_secret`: without it, an ID token
signed HS256 with that shared secret verifies, and a symmetric key becomes a way
to assert any federated identity at all.

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

### Tamper-evidence

Every entry written since migration 031 carries a gapless sequence number, the
tag of the entry before it, and its own **HMAC-SHA256 tag** over both. The MAC
key is a purpose-derived subkey of `CERTPILOT_KEK` — never the KEK itself, so
one key is not doing two cryptographic jobs — and it lives in the core's
environment, not in the database.

That boundary is the point. Someone holding a database dump, a compromised
replica, or a DBA account can alter or delete a row, but cannot produce a tag
that agrees with it. Editing one entry breaks that entry; re-tagging it breaks
the next one; deleting one leaves a hole in the sequence.

```
entry N-1                     entry N
┌──────────────┐              ┌──────────────┐
│ seq          │              │ seq        N │
│ contents     │         ┌───▶│ prev_hash    │
│ entry_hash ──┼─────────┘    │ contents     │
└──────────────┘              │ entry_hash = │
                              │   HMAC(k,    │
                              │    prev ‖    │
                              │    contents) │
                              └──────────────┘
      k = subkey(CERTPILOT_KEK, "audit-chain")
```

Each entry also records **which** KEK signed it, in the same short hex form the
encryption envelopes use, so rotating `CERTPILOT_KEK` does not invalidate
history. Without that, the safe thing to do would be never to rotate.

`GET /api/v1/audit/verify` (admin) walks the chain and reports the first break,
its sequence number, and a reason. It is surfaced in **Settings → Audit record**.
Three outcomes, deliberately distinct: intact, altered, and *could not be
checked* — the last usually meaning a chain written under a key this core was
never given. A missing key must never read as tampering, or the reverse.

The report also counts entries that **predate** the mechanism. They are left
unchained rather than back-filled: a chain computed over old rows today proves
only that they looked like that at migration time, and presenting it as
tamper-evidence would be a lie the verifier then repeats.

Two things bound the guarantee. `audit_logs` also carries a trigger refusing
`UPDATE` and `DELETE` — that is protection against a mistyped statement, not a
security control, since anyone who can drop a trigger can drop it. And a
determined attacker holding **both** the database and the KEK can rewrite the
chain wholesale; see [known gaps](#known-gaps).

Retention is the one legitimate deletion, and it has a documented door rather
than teaching operators to drop the trigger:

```sql
begin;
set local certpilot.audit_maintenance = 'on';
delete from public.audit_logs where created_at < now() - interval '7 years';
commit;
```

Verification will then report a gap across what was pruned, which is correct: a
pruned chain is not an intact one.

---

## Known gaps

Listed because a security document that only lists strengths is marketing.

**The audit chain has no external anchor.** Each entry is chained with a tag
keyed from `CERTPILOT_KEK`, which defeats an attacker who holds the database but
not the key. It does not defeat one who holds both: they can recompute the chain
from any point forward, or truncate the newest entries and leave something
internally consistent. Detecting either needs the head tag published somewhere
append-only — a second system, an object-lock bucket, a printed page — on a
schedule. Not built.

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

**Deployment ordering is not expressible.** "Staging, then production" cannot
be declared; the canary is one-per-worker rather than exactly one.
