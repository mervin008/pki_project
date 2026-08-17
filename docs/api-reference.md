# REST API reference

All endpoints are under `/api/v1` and speak JSON. `GET /healthz` is the only
unauthenticated route.

## Authentication

```
Authorization: Bearer <token>
```

Tokens are verified against `auth.jwks_url` (preferred) or `auth.jwt_secret`
(legacy shared secret). An invalid or expired token is always rejected — there
is no development mode in which a bad token is accepted.

When `auth.allow_anonymous` is set, requests with **no** `Authorization` header
at all are treated as admin. It is refused unless the server is in development
mode on a loopback address. Presenting a broken token is still a 401.

### Authenticating an unattended screen

A screen in a corridor has nobody to sign in at it, and leaving an operator
session logged in there would hand it the authority to issue, revoke, and export
private keys. A display token is a separate credential for exactly that case.

```
X-Display-Token: cpd_<43 characters>
```

or, for clients that cannot set headers — `EventSource` is the one that matters
— in the query string:

```
GET /api/v1/events?display_token=cpd_...
```

Prefer the header. A query string reaches access logs, `Referer` headers, and
browser history; `RequestLogger` redacts this parameter for that reason, and
CertPilot's own frontend streams over `fetch` so that it can use the header.

A request carrying an `Authorization` header is never resolved as a display
token, whatever else it presents. That precedence is what stops a token left in
a bookmark from quietly masking an operator's identity in the audit log — and it
means an invalid bearer token fails as an invalid bearer token rather than being
rescued by a display token in the URL.

It is **not** a second way to authenticate as a user. The middleware that
resolves it enforces three things centrally, so no individual route has to
remember them:

| | |
|:---|:---|
| Role | Always `viewer`. Not configurable and not derived from any input |
| Methods | `GET` only. Any other method is 403, on every route |
| Refused paths | `/certificates/:id/private-key`, `/display-tokens`, `/dashboard/activity` — refused by path, independently of their own role gate |

An `Authorization` header takes precedence: a display token left in a bookmarked
URL cannot silently downgrade a real session or misattribute its actions.
A display token that is unknown, revoked, or expired is a 401 and does *not*
fall through to anonymous access.

Tokens expire (90 days by default, 365 maximum), are revocable, and record
`last_seen_at` / `last_seen_ip` so a credential in use somewhere unexpected is
visible. The query-string form reaches access logs by nature, which is why the
core's request logger redacts it — but it is also why this credential grants
nothing but read access.

## Authorization

Roles come from `app_metadata.certpilot_role`. `admin` passes every check.

| Role | Read | Issue / renew / revoke | Delete | Export private keys |
|:---|:---:|:---:|:---:|:---:|
| `admin` | ✅ | ✅ | ✅ | ✅ |
| `operator` | ✅ | ✅ | — | — |
| `auditor` | ✅ | — | — | — |
| `viewer` | ✅ | — | — | — |

## Secrets in responses

Two fields are never serialized on any endpoint:

- `certificates.private_key_encrypted`
- `ca_accounts.config_encrypted`

Private keys are retrievable only through the dedicated export endpoint, which
is admin-only and writes an audit record. CA credentials are not retrievable at
all — supply a replacement configuration instead.

## Errors

```json
{ "error": "human-readable description" }
```

| Code | Meaning |
|:---|:---|
| 400 | Malformed request, or a gateway rejected the configuration |
| 401 | Missing, malformed, invalid, or expired token |
| 403 | Role not permitted, or the request was blocked by a policy |
| 404 | Not found |
| 500 | Internal failure — including "the policy engine could not be consulted", which fails closed |
| 502 | The gateway is unreachable, failed, or returned something invalid |
| 503 | Gateway health check failed |

---

## Live event stream

```
GET /api/v1/events   Server-Sent Events
```

Opens with a `retry:` directive and a `snapshot` event carrying current
dashboard statistics and a CA summary per authority, so a client never renders
from an empty store. Live events follow, and a `: heartbeat` comment every 15
seconds keeps intermediaries from reaping the connection — and lets a client
tell "nothing is happening" from "I have stopped receiving", which on a wall
display is the difference that matters.

```
event: ca.expiry_alert
id: 42
data: {"id":42,"topic":"ca.expiry_alert","severity":"CRITICAL","entity_id":"...","payload":{...}}
```

Topics: `ca.health`, `ca.expiry_alert`, `cert.issued`, `cert.renewed`,
`cert.renewal_failed`, `cert.expiring`, `gateway.status`.

Reconnecting clients send `Last-Event-ID` (or `?last_event_id=`) and are
replayed from that point. When the gap is larger than the broker's history, or a
client falls behind mid-stream, the server sends `event: resync` followed by a
fresh snapshot rather than deltas onto a stale base — a dashboard that looks
live and is wrong is worse than one that admits it lost its place.

The snapshot deliberately omits `certificate_pem`: it is kilobytes per CA, it is
re-sent on every resync, and no dashboard uses it.

> Behind a reverse proxy, buffering must be off for this route or the stream
> arrives in chunks and the display looks frozen. See
> [`deploy/docker/nginx.conf`](../deploy/docker/nginx.conf).

## Dashboard

```
GET /api/v1/dashboard/stats      Summary counts for certificates and CAs
GET /api/v1/dashboard/expiring   Certificates inside the renewal lead window
GET /api/v1/dashboard/activity   Recent audit events
```

### Statistics

The five CA counts partition the estate — every authority lands in exactly one,
and they sum to `total_cas`:

| Field | |
|:---|:---|
| `healthy_cas` | |
| `warning_cas` | |
| `critical_cas` | Close to expiry. Still replaceable in an orderly way |
| `expired_cas` | Already an outage. Separate from critical because the response differs |
| `unknown_cas` | Never checked, or the certificate could not be parsed |

`unknown_cas` is reported rather than folded away: a CA nobody can assess is not
a healthy one, and hiding it is how a green dashboard covers an unmonitored CA.

### Activity

```
GET /api/v1/dashboard/activity?action=ca.expiry_alert&limit=50
```

| Parameter | |
|:---|:---|
| `action` | Repeatable, or comma-separated. Matches any of the listed actions |
| `entity_type`, `entity_id` | Narrow to one object's history |
| `since` | RFC 3339 timestamp, inclusive lower bound |
| `limit` | 1–500, default 20 |
| `offset` | |

`total` counts the filtered set, not the table, so a client paging through CA
alerts is told how many alerts exist rather than how large the audit log is.

Filtering is what makes CA alerts reachable. They share a table with every
issuance, so without it the newest twenty rows on a busy day contain no alerts
at all — they were recorded, and never seen. An unparseable `since`, `limit`, or
`offset` is a 400 rather than a silently ignored parameter: a filter that
quietly does nothing is worse than one that fails, because the caller believes
they are looking at a narrowed view.

> Refused to kiosk display tokens. Audit entries carry actor identity, and
> "alice@example.com deleted a certificate" does not belong on a corridor
> screen. Signed-in `viewer` accounts are not restricted.

## Certificates

```
GET    /api/v1/certificates                  List
POST   /api/v1/certificates                  Request and issue          (operator)
GET    /api/v1/certificates/:id              Detail
POST   /api/v1/certificates/:id/renew        Renew now                  (operator)
GET    /api/v1/certificates/:id/private-key  Export the key             (admin, audited)
DELETE /api/v1/certificates/:id              Delete the record          (admin, audited)
```

`GET /certificates` filters on `status`, `environment`, `common_name`,
`ca_account_id`.

### Issuing

```http
POST /api/v1/certificates
```

```json
{
  "common_name": "app.example.com",
  "sans": ["www.app.example.com"],
  "ca_account_id": "uuid",
  "key_type": "ECDSA",
  "key_size": 256,
  "validity_days": 90,
  "environment": "production",
  "team": "platform",
  "auto_renew": true,
  "renewal_lead_days": 30
}
```

What happens, in order: the CA account is loaded, policy is evaluated, the
gateway is located, its stored configuration is decrypted for exactly this one
call, issuance is requested, and the returned certificate is **parsed before it
is stored**. A gateway that returns anything other than a valid X.509
certificate produces a 502 rather than a record marked `ISSUED`.

Metadata on the stored record — serial, issuer, validity dates, fingerprint,
key type and size — is read from the certificate itself, not from what the
gateway claimed.

If the gateway returns a private key, it is sealed before it touches the
database. Supplying your own CSR avoids this entirely and is the better pattern:
the key then stays wherever it was generated.

Returns `201`. When non-blocking policy violations were recorded, the body is
`{"certificate": {...}, "policy_violations": [...]}` instead of the bare record —
a policy that finds something must say so even when it does not block.

### Renewing

`POST /certificates/:id/renew` runs the same path. The key is rotated and the
new one persisted; a renewal that produced a certificate without storing its
matching key would leave a record that looks healthy and cannot terminate TLS.

On failure the record is marked `RENEWAL_FAILED` with `renewal_error` set, and
the previous certificate is left intact.

### Exporting a private key

```http
GET /api/v1/certificates/:id/private-key
```

```json
{ "common_name": "app.example.com", "private_key_pem": "-----BEGIN..." }
```

Admin only. Writes `cert.private_key_exported` to the audit log with the actor
and client IP. Returns 404 when no key is stored — which is the normal case for
imported, discovered, or CSR-based certificates.

## PKI and CA authorities

```
GET    /api/v1/pki/authorities            List monitored CAs
POST   /api/v1/pki/authorities            Register a CA               (operator)
GET    /api/v1/pki/authorities/:id        Detail
GET    /api/v1/pki/authorities/:id/chain  Trust chain to the root
POST   /api/v1/pki/authorities/:id/check  Health, CRL, and OCSP check (operator)
DELETE /api/v1/pki/authorities/:id        Remove                      (admin)
GET    /api/v1/pki/tree                   Hierarchy for visualization
```

`GET /pki/authorities` filters and sorts:

| Parameter | |
|:---|:---|
| `status` | `HEALTHY`, `WARNING`, `CRITICAL`, `EXPIRED`, `UNKNOWN` |
| `expiring_within_days` | Keeps CAs expiring inside the window |
| `sort` | `urgency` (soonest expiry first) or `name` (default) |

`urgency` is the order the CA health view is built on: the question a team
watching a wall display is asking is which authority fails first, and an
alphabetical list answers a different one.

The expiry window is evaluated against `not_after`, not the stored
`days_remaining`. That column is a snapshot written by the health sweep and is
stale by however long it has been since the last one — a CA whose sweep has not
run since registration would otherwise report itself comfortable while expiring
next week.

The list omits `certificate_pem`; the detail endpoint still returns it. It is
kilobytes per CA, no client renders it, and the list is re-read on every
dashboard refresh.

> The CRL freshness check is real. The OCSP check currently issues a plain GET
> rather than an RFC 6960 request and reports a responder as healthy when it
> should not — see the README's known gaps.

### The hierarchy

`GET /pki/tree` returns roots with their children attached recursively. Each
node carries the authority, its `children`, and its `depth` — issuing steps from
the root of its own chain, so a root is `0`.

```json
{
  "authority": { "id": "...", "name": "Corporate Root", "...": "..." },
  "depth": 0,
  "children": [
    { "authority": { "name": "Corporate Intermediate" }, "depth": 1, "children": [] }
  ]
}
```

Three guarantees, because the interesting cases here are malformed hierarchies
rather than well-formed ones:

- **Every registered CA appears exactly once**, including ones whose parentage is
  wrong. A CA missing from a monitoring view is the one nobody notices expiring.
- **The response is always acyclic and always serialisable.** A CA naming itself,
  or a ring of CAs naming each other, is broken out to the top level rather than
  reproduced as a loop.
- **The order is stable.** Siblings sort by name, then id, so the tree does not
  reshuffle itself between identical requests.

A CA that could not be placed under a real root is returned at the top level with
`"detached": true` and a `detached_reason` naming the problem:

| Reason | Meaning |
|:---|:---|
| `its issuing CA is not registered in CertPilot` | Ordinary — a root held offline, or an intermediate imported on its own |
| `this CA is recorded as its own issuer` | Bad data. `parent_ca_id` points at the CA itself |
| `its issuer chain forms a loop, so it has no root` | Bad data. Two or more CAs name each other |

The last two are also logged at `WARN` by the core, since they mean the recorded
hierarchy is wrong rather than merely incomplete.

## CA accounts and gateways

```
GET    /api/v1/ca-accounts             List
POST   /api/v1/ca-accounts             Register                (operator)
POST   /api/v1/ca-accounts/:id/health  Probe the gateway       (operator)
DELETE /api/v1/ca-accounts/:id         Remove                  (admin)
GET    /api/v1/gateways                Connected gateways and capabilities
```

### Registering

```json
{
  "name": "letsencrypt-prod",
  "provider_type": "acme",
  "gateway_addr": "acme-gateway:9092",
  "server_name": "acme-gateway",
  "config": {
    "directory_url": "letsencrypt",
    "email": "ops@example.com",
    "challenge": "dns-01",
    "dns_provider": "cloudflare",
    "dns_config": {"api_token": "..."}
  },
  "is_default": false
}
```

The core connects over mTLS, calls the gateway's `ValidateConfig`, and stores
nothing if the gateway rejects it — a 400 comes back listing what is wrong.
Warnings do not block and are returned alongside the created account.

`config` is sealed with AES-256-GCM before storage and decrypted only to
populate a single outbound gRPC call. It is not readable back through the API.

`server_name` overrides the name expected in the gateway's TLS certificate;
omit it to derive from the host part of `gateway_addr`.

## Discovery

```
POST /api/v1/discovery/scan        Scan endpoints and judge what they serve  (operator)
POST /api/v1/discovery/import      Adopt a finding into inventory            (operator)
GET  /api/v1/discovery/scans       Scan history
GET  /api/v1/discovery/scans/:id   One run and its results
GET  /api/v1/discovery/results     Findings across every scan
```

Scanning is operator-gated because it opens connections to third-party
infrastructure from CertPilot's address. Every run is recorded in the audit log
with the targets it was given, so "who asked us to connect to that" is
answerable afterwards. One request is capped at 256 targets.

```json
POST /api/v1/discovery/scan
{ "targets": ["example.com", "10.0.0.5:8443"], "port": 443 }
```

Every target is parsed before any is scanned: a malformed one fails the whole
request rather than leaving you unsure which part of your list was reached.
`host: "…"` is accepted as the single-target form.

The response carries the run, the results, and a sentence:

```json
{
  "scan": { "results_count": 7, "unmanaged_count": 6, "managed_count": 0, "unreachable_count": 1 },
  "data": [ … ],
  "summary": "6 certificate(s) are being served that CertPilot does not manage. Nothing renews them."
}
```

The `summary` exists because the counts alone are ambiguous in the one direction
that matters: an estate where nothing answered and an estate where everything is
managed both produce zero unmanaged results.

### The verdicts

Each result carries two, and they answer different questions.

`management_state` — **`MANAGED`** when the served certificate's SHA-256
fingerprint matches a row in `certificates`, **`UNMANAGED`** when it does not,
**`UNREACHABLE`** when no handshake completed. Matched on fingerprint, not on
name: two certificates for the same hostname are two different certificates, and
the one being served is the one that expires. An inventory lookup that fails
reports `UNMANAGED`, with a finding saying so — calling something managed that
could not be checked is how a lookup error becomes an outage.

`trust_state` — **`PUBLIC`**, **`INTERNAL`** (chains to a CA registered in
CertPilot), **`SELF_SIGNED`**, **`UNTRUSTED`** (neither), or **`UNKNOWN`**.
Internal trust is decided on signatures rather than by path building, so an
expired certificate still reports the CA that issued it instead of reading as a
rogue issuer.

### Findings

`findings` is an array of `{code, severity, detail}`. Codes are stable:
`expired`, `not_yet_valid`, `expiring_soon`, `hostname_mismatch`, `self_signed`,
`untrusted_issuer`, `incomplete_chain`, `weak_key`, `weak_signature`,
`legacy_tls`, `weak_cipher`, `no_forward_secrecy`, `long_validity`,
`internal_issuer`, `inventory_lookup_failed`.

`weak_signature` covers the whole served chain, not just the leaf: a SHA-1
intermediate breaks a connection as completely as a SHA-1 leaf, and is the more
common of the two. Self-signed certificates are skipped, since a root's own
signature is never verified by anything.

A classical key exchange is deliberately **not** a finding. It is true of nearly
every endpoint alive, and a finding on every row is not a finding. The
negotiated group is recorded verbatim in `key_exchange` instead — that column is
what a posture report reads.

### Import

```json
POST /api/v1/discovery/import
{ "result_id": "…", "team": "Platform", "environment": "production" }
```

`certificate_pem` is accepted instead, for a certificate someone has in hand.

**`auto_renew` is always false on import, whatever was requested.** CertPilot
holds no private key for something it merely observed, so a record claiming it
will renew itself is a promise the system cannot keep — and the moment you find
out is expiry. The response says so in words. Importing the same certificate
twice converges on one record and returns 200 rather than a conflict.

Publishes `discovery.unmanaged` (WARNING) when a run finds anything unmanaged,
so the finding reaches the channels a team already configured instead of waiting
to be noticed on a page nobody has open.

> CIDR ranges, scheduled scans, CT log monitoring, and cloud inventory are not
> implemented yet.

## Ownership and acknowledgement

```
PUT    /api/v1/pki/authorities/:id/owner             Set the owning team    (operator)
POST   /api/v1/pki/authorities/:id/acknowledge       Acknowledge            (operator)
DELETE /api/v1/pki/authorities/:id/acknowledge       Withdraw               (operator)
GET    /api/v1/pki/authorities/:id/acknowledgements  History
```

**Silencing suppresses delivery, never display.** An acknowledged CA still
appears on `/pki/authorities`, on the CA health view, and on the wall display,
with its status unchanged and an `acknowledgement` object attached. Nothing here
removes a row. Hiding a problem because someone clicked a button is how CAs
expire in organisations that believed they were monitoring them.

### Acknowledging

```json
{"note": "replacement issued, cutover Thursday", "silence_days": 7, "threshold": 14}
```

| Field | |
|:---|:---|
| `note` | Why. The most useful field: it turns a red row from an unanswered alarm into a status, and stops the next person re-investigating |
| `silence_days` | Suppress **delivery** for this many days. `0` (the default) acknowledges without silencing — the alert stops being new and still goes out. Capped at 90 |
| `threshold` | The expiry threshold in days this covers. Defaults to the CA's current `last_alert_threshold` |

There is no indefinite silence. A permanent one is indistinguishable from
deleting the alert, and the CA goes on expiring while the team believes it is
monitored.

**An acknowledgement is bound to its threshold.** Silencing a CA at 30 days does
not silence its 7-day alert: the situation has materially worsened, and the
earlier "yes, we know" answered a different question. The same rule governs
display — a CA that has since crossed a tighter threshold stops showing as
acknowledged, because the annotation would otherwise become the false
reassurance the feature exists to prevent.

The response states what was and was not changed, because "acknowledged" is
ambiguous and the ambiguity is the dangerous part:

```json
{
  "data": {"id": "…", "threshold": 7, "silence_until": "2026-08-24T09:48:18Z", "note": "…"},
  "note": "This certificate authority still appears on the dashboard and the wall display, now marked as acknowledged. Delivery is suppressed until 24 August 2026 09:48 CEST, but only for the 7-day threshold: if it crosses a tighter one, it alerts again."
}
```

Withdrawal marks rather than deletes: a CA acknowledged in error and then
un-acknowledged is something an incident review wants to see, not a row that
quietly disappeared. `GET …/acknowledgements` returns the full history, newest
first, revoked entries included.

If the acknowledgement lookup fails, the alert is **delivered anyway**. The cost
of a duplicate notification is an annoyed engineer; the cost of a suppressed one
is an expired CA.

### Ownership

```json
{"owner_team": "Platform Security", "owner_email": "pki@example.com"}
```

Both are free text — team names and distribution lists do not live in CertPilot.
Send an empty string to clear either: ownership moving to nobody is a real state,
and one worth seeing on the dashboard rather than silently keeping the old team's
name. A CA with no owner renders as "Nobody", not as a blank cell.

## Notification channels

```
GET    /api/v1/notification-channels          List channels
POST   /api/v1/notification-channels          Create                      (operator)
PUT    /api/v1/notification-channels/:id      Update                      (operator)
DELETE /api/v1/notification-channels/:id      Delete                      (admin)
POST   /api/v1/notification-channels/:id/test Send a real test alert      (operator)
```

Three channel types have a notifier: `slack`, `webhook`, `email`. Migration 001
also permitted `teams` and `pagerduty`; neither is implemented and 004 narrowed
the constraint, because a channel of a type nothing can deliver looks configured
on the dashboard and silently drops every alert routed to it.

`config` carries the destination's settings and is **write-only**. It is
validated by the notifier, sealed with the keyring, and never returned — not by
the create response and not by the list. Omit it on an update to keep what is
stored; send it to replace it wholesale.

| Field | |
|:---|:---|
| `name` | Required. What names the channel in a delivery failure |
| `channel_type` | `slack`, `webhook`, or `email` |
| `severity_threshold` | `INFO`, `WARNING` (default), or `CRITICAL` — the minimum this channel delivers |
| `topics` | Event topics to accept. **Empty means all**, which is the useful default. An unknown topic is rejected rather than accepted and ignored |
| `is_enabled` | Defaults to true on create |

Configuration per type:

```jsonc
// slack — webhook_url must be https; it is a bearer credential
{"webhook_url": "https://hooks.slack.com/services/...", "username": "", "icon_emoji": ""}

// webhook
{"url": "https://receiver.example.com/hook",
 "signing_secret": "at least 16 characters",
 "headers": {"X-Tenant": "acme"},
 "allow_insecure_http": false}

// email
{"host": "smtp.example.com", "port": 587,
 "username": "", "password": "",
 "from": "pki@example.com", "to": ["oncall@example.com"],
 "encryption": "starttls",   // or "tls" (465) or "none"
 "insecure_skip_verify": false}
```

### Testing a channel

`POST /notification-channels/:id/test` sends a real, clearly labelled test alert.
It does not retry and returns the destination's own complaint verbatim:

```json
{"delivered": false, "error": "Slack returned 403: invalid_token"}
```

The status is **502**, not 500: CertPilot worked and the destination did not, and
that distinction is the entire content of the answer.

### Webhook payload and signature

```json
{
  "severity": "CRITICAL",
  "topic": "ca.expiry_alert",
  "title": "CA expiring: Corporate Issuing CA",
  "summary": "Corporate Issuing CA expires in 9 days. Every certificate it has issued stops validating when it does.",
  "entity_id": "…",
  "fields": [{"label": "Days remaining", "value": "9 days"}],
  "timestamp": "2026-08-17T07:33:24Z",
  "source": "certpilot"
}
```

| Header | |
|:---|:---|
| `X-CertPilot-Event` | The topic, so a receiver can route without parsing |
| `X-CertPilot-Timestamp` | Unix seconds |
| `X-CertPilot-Signature` | Hex HMAC-SHA256, present only when a signing secret is configured |

The signed string is exactly `<X-CertPilot-Timestamp> "." <raw request body>`.
Verify it in constant time and reject anything outside a few minutes' tolerance.
The timestamp is inside the signature rather than merely alongside it: signing
the body alone yields a signature that stays valid forever, so a captured
delivery could be replayed indefinitely and the receiver could not tell.

```python
import hashlib, hmac
want = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(want, signature)
```

### Delivery behaviour

The dispatcher subscribes to the event broker rather than being called inline, so
a wedged destination loses its own place in the queue and can never apply
backpressure to the CA health sweep. Deliveries retry three times with jittered
exponential backoff, then stop — an endpoint that has refused three times inside
a minute is down, and retrying past that turns one outage into a queue that
outlives it.

Both outcomes are audited as `notification.sent` and `notification.failed`, and
are queryable through `/dashboard/activity?action=notification.failed`.

## Policies

```
GET    /api/v1/policies      List
GET    /api/v1/policies/:id  Detail
POST   /api/v1/policies      Create   (operator)
PUT    /api/v1/policies/:id  Update   (operator)
DELETE /api/v1/policies/:id  Delete   (admin)
```

Implemented rule types:

| `rule_type` | `rule_config` |
|:---|:---|
| `key_size` | `{"min_key_size": 2048}` — applies to RSA |
| `max_lifetime` | `{"max_days": 90}` |
| `ca_restriction` | `{"allowed_providers": ["acme", "vault"]}` |

`severity` is `INFO`, `WARNING`, or `BLOCK`. Only `BLOCK` refuses the request;
the rest are returned in the issuance response.

`domain_pattern` scopes a policy — `*` matches everything, `*.example.com`
matches any subdomain. A policy applies when **any** requested domain matches.

> `key_type`, `naming`, and `approval_required` are accepted by the schema but
> not implemented, so policies using them currently do nothing. Policy is
> evaluated on issuance only, not on renewal.

## Display tokens

```
GET    /api/v1/display-tokens      List           (admin)
POST   /api/v1/display-tokens      Create         (admin, audited)
DELETE /api/v1/display-tokens/:id  Revoke         (admin, audited)
```

Create:

```json
{ "name": "fourth-floor-corridor", "expires_in_days": 90 }
```

`name` is required and unique — it is what makes "revoke the screen by the lifts"
an answerable request. `expires_in_days` defaults to 90 and is capped at 365;
there is no unlimited option.

```json
{
  "token": "cpd_...",
  "display": { "id": "...", "name": "...", "status": "ACTIVE", "expires_at": "..." },
  "warning": "This token is shown once and cannot be retrieved again. ..."
}
```

**`token` appears in this response and nowhere else.** Only its SHA-256 is
stored, so a database dump yields no working credentials — and neither does the
list endpoint, which returns everything except the hash.

`status` is `ACTIVE`, `EXPIRED`, or `REVOKED`. Revocation outranks expiry, and
is a soft delete: the row survives with `revoked_at` and `revoked_by` set,
because when a credential had to be pulled is exactly what someone will ask
later.

See [Authenticating an unattended screen](#authenticating-an-unattended-screen)
for what the credential can and cannot do.

## Response headers

Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
`Cache-Control: no-store`.

CORS reflects the request origin only when it appears in
`server.allowed_origins`. A wildcard is never sent — it is invalid alongside
credentials and browsers reject the combination.
