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
POST   /api/v1/discovery/scan                Scan endpoints and judge what they serve  (operator)
POST   /api/v1/discovery/import              Adopt a finding into inventory            (operator)
POST   /api/v1/discovery/scans/:id/cancel    Stop a running scan                       (operator)
GET    /api/v1/discovery/scans               Scan history
GET    /api/v1/discovery/scans/:id           One run and its results
GET    /api/v1/discovery/results             Current findings, one row per endpoint
GET    /api/v1/discovery/schedules           Scheduled scans
POST   /api/v1/discovery/schedules           Create one                                (operator)
PUT    /api/v1/discovery/schedules/:id       Edit one                                  (operator)
DELETE /api/v1/discovery/schedules/:id       Remove one                                (admin)
POST   /api/v1/discovery/schedules/:id/run   Run it now, without moving its schedule   (operator)
```

Scanning is operator-gated because it opens connections to third-party
infrastructure from CertPilot's address. Every run is recorded in the audit log
with the targets it was given, so "who asked us to connect to that" is
answerable afterwards. One request is capped at 256 targets.

```json
POST /api/v1/discovery/scan
{ "targets": ["example.com", "10.0.0.0/24", "10.0.0.4-40:8443"], "ports": [443, 8443] }
```

Each entry may be a host, `host:port`, a CIDR network, or an inclusive address
range — `10.0.0.4-10.0.0.40` or the abbreviated `10.0.0.4-40`. A network or
range may name its own port. `ports` applies to everything that does not, and
multiplies the endpoint count. `host: "…"` is accepted as the single-target form.

Everything is expanded and checked before anything is connected to: a malformed
entry fails the whole request rather than leaving you unsure which part of your
list was reached. Network and broadcast addresses are skipped for IPv4 prefixes
wider than /31, so `10.0.0.0/24` is 254 endpoints and not 256.

Two limits apply. A request carries at most **256 entries**, and those may
expand to at most **4096 endpoints**. The second is the one that matters: a
misplaced digit turns `10.0.0.0/24` into `10.0.0.0/8`, and the refusal names the
size so the typo is visible rather than merely denied.

```
10.0.0.0/8 covers 16777216 addresses, past the 4096-endpoint limit for one
scan; narrow it
```

### Small scans wait, wide scans do not

At **32 endpoints or fewer** the scan runs while you wait and returns `200` with
its results. Above that it goes to the background and returns `202` with a poll
URL. The response says which happened without you having to read the status
code — `scan.status` is `COMPLETED` or `RUNNING`:

```json
{
  "scan": { "id": "…", "status": "RUNNING", "target_count": 254, "results_count": 0 },
  "poll": "/api/v1/discovery/scans/<id>",
  "summary": "Scanning 254 endpoints in the background. Results appear as they are found."
}
```

Results are written as they are found, not at the end, so polling shows real
progress and a run that is interrupted keeps what it reached. Progress is also
published to the event stream as `discovery.progress` — **stream only**: it is
never delivered to a notification channel, because a range scan would otherwise
put a message in Slack every few seconds for minutes, and a team that mutes that
channel has also muted CA expiry.

```
POST /api/v1/discovery/scans/:id/cancel
```

Cancelling keeps everything already found and records the run as `CANCELLED`,
not `FAILED` — the history has to distinguish "somebody stopped it" from
"something went wrong". Endpoints abandoned mid-probe are **not** recorded as
unreachable: they were never really asked, and a row saying otherwise would be a
finding about the estate invented by stopping the scan. Cancelling a run that
has already finished is not an error; the response names its actual status.

The scan record keeps the targets **as they were typed** — `10.0.0.0/24`, not
254 addresses — with `target_count` carrying how far that expanded. A scan is
repeated by re-running what was asked for and found again by the range someone
remembers typing.

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

### Scheduled scans

```json
POST /api/v1/discovery/schedules
{ "name": "nightly perimeter", "targets": ["10.0.0.0/24"], "interval_minutes": 1440 }
```

An interval, not a cron expression. A cron field is a small language whose
mistakes are silent, and a schedule meant to run nightly that instead runs
yearly looks identical on screen to one that works. The floor is 15 minutes;
below that a scan of the same range is indistinguishable from a denial of
service aimed at your own estate.

Targets are expanded and validated **when the schedule is saved**, not when it
first fires — including a check that the run can finish before the next one
starts. A schedule that looks configured and silently never scans is worse than
no schedule, and 3am on the night it mattered is the wrong time to find out its
targets do not parse.

A new schedule runs within the minute, so you can see it work rather than find
out tomorrow. `last_run_at`, `next_run_at`, `last_scan_id`, and `last_error` are
on every schedule: one that fails every night and is never read is the
appearance of coverage. `POST …/run` starts it immediately **without** moving
its schedule — testing what you just wrote should not silently push tonight's
run to tomorrow.

> Two replicas both run every schedule. Leader election over Postgres advisory
> locks arrives with the renewal engine in phase 4, which has the same gap.

### What a repeated scan adds

The second run of a scan is not worth much as a list. It is worth what it says
has **changed**, and three findings exist only on a re-scan:

| Code | |
|:---|:---|
| `certificate_changed` | The endpoint is serving a different certificate. **WARNING** when CertPilot manages neither the old nor the new one — something out there is renewing certificates without going through this system, so somebody knows how to replace it. **INFO** when the new one is managed, because that is a renewal it performed |
| `endpoint_disappeared` | It answered last time and does not now: either it moved and the scan no longer covers it, or it is down |
| `endpoint_appeared` | It did not answer last time and does now |

A first scan reports none of these. Every endpoint is new the first time, and a
run whose findings are all "this is new" is one nobody reads twice.

Changes publish `discovery.changed` (WARNING), separate from
`discovery.unmanaged`: "there is an endpoint you do not manage" may have been
true for years, while "the certificate on it changed last night" is a fact about
somebody actively operating it.

### One row per endpoint

`GET /discovery/results` returns the **latest observation of each endpoint** by
default. A nightly schedule records the same unmanaged certificate every night,
and counting each of those as a separate finding turns one problem into thirty
until the number stops meaning anything.

The collapse happens *before* the filters, which is the part that is easy to get
backwards: filtering first would answer "the most recent time this endpoint was
unmanaged" and keep asking for work that has already been done. Pass
`latest=false` for the full history, which is what an investigation wants.

## Certificate Transparency

```
GET    /api/v1/ct/monitors             Watched domains
POST   /api/v1/ct/monitors             Watch one                    (operator)
PUT    /api/v1/ct/monitors/:id         Edit one                     (operator)
DELETE /api/v1/ct/monitors/:id         Stop watching                (admin)
POST   /api/v1/ct/monitors/:id/check   Check now                    (operator)
GET    /api/v1/ct/certificates         What the logs have reported
```

This is the half of discovery a network scan cannot reach. A scan answers "what
is being served on the addresses I told you about". CT answers **what has been
issued in your name at all** — by any CA, to anyone, whether or not it was ever
deployed and whether or not the machine is reachable from CertPilot. A developer
who obtained a certificate for `api.corp.example.com` with a personal ACME
account appears in no scan of any range, and appears in CT within minutes,
because every publicly-trusted CA is required to log there.

```json
POST /api/v1/ct/monitors
{ "domain": "example.com", "include_subdomains": true, "check_interval_minutes": 360 }
```

Give the domain itself — `*.example.com` is refused, because subdomains are what
`include_subdomains` is for. The floor on the interval is **60 minutes**, higher
than a scan's, for a different reason: the logs are read through a free
community service, and polling it harder is how an organisation loses access to
it and then finds out nothing at all.

### Checked, versus answered

Every monitor carries **both** `last_checked_at` and `last_success_at`, and the
list surfaces `stale_domains` derived from them.

Collapsing those into one field is the failure this whole product exists to
prevent, in miniature: a monitor that has been unable to reach the log for a
week would look exactly like a monitor that has found nothing for a week, and
one of those means nobody is being told about certificates issued in their name.
For the same reason `POST …/check` answers **502** when the index is
unreachable, with its own words and the sentence *"The check did not complete,
so nothing was learned about this domain. It is not the same as finding no
certificates."*

### One certificate, two log entries

A precertificate and its final certificate are logged separately and share a
serial number. The index publishes no field saying which is which, so the
earlier entry for a serial is labelled `is_precertificate` — precertificates are
always logged first. Both rows are kept, because "this was pre-logged then
issued" is real information, but `GET /ct/certificates` hides the pre-issuance
row by default and the counts are per certificate.

This is not cosmetic. Before it existed, a live check of `badssl.com` reported
**18** certificates where there are **9**, and a headline number wrong by a
factor of two is one people act on. Pass `include_precertificates=true` for the
raw log entries.

### Matching your own certificates

Findings are matched to inventory on **serial number**, since the log index does
not publish a SHA-256 fingerprint. The two sides format serials differently —
CertPilot stores unpadded lowercase hex, indexes pad and upper-case them — so
both are normalised before comparison. Getting that wrong would report this
system's own certificates as ones nobody manages, and a findings list full of
your own certificates is one nobody reads.

An unmanaged finding publishes `ct.unmanaged` (WARNING), and only for
certificates that are **new to that monitor**. Check windows overlap by design,
and an alert repeating the same certificate every six hours is how a channel
gets muted — taking the CA expiry alerts sharing it along with it.

> Cloud inventory (ACM, Azure Key Vault, GCP, Kubernetes secrets) is not
> implemented yet.

## Cloud inventory

```
GET    /api/v1/cloud/connections             Configured accounts
POST   /api/v1/cloud/connections             Add one                      (operator)
PUT    /api/v1/cloud/connections/:id         Edit one                     (operator)
DELETE /api/v1/cloud/connections/:id         Remove one                   (admin)
POST   /api/v1/cloud/connections/:id/sync    Sync now                     (operator)
GET    /api/v1/cloud/certificates            What the accounts hold
POST   /api/v1/cloud/import                  Adopt one into inventory     (operator)
```

The third place certificates hide. A scan finds what is **served**; Certificate
Transparency finds what a public CA **issued**; neither finds what is merely
**stored** — in ACM, in a Key Vault, in a Google load balancer, in a Kubernetes
secret, attached to an address nobody scanned or attached to nothing at all.

### What each provider needs

```json
POST /api/v1/cloud/connections
{ "name": "prod-eu", "provider": "aws_acm", "sync_interval_minutes": 360,
  "config": { "region": "eu-west-1",
              "role_arn": "arn:aws:iam::1234:role/certpilot-read",
              "web_identity_token_file": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" } }
```

| `provider` | `config` | Credentials |
|:---|:---|:---|
| `aws_acm` | `region` | `access_key_id` + `secret_access_key` (+ `session_token`), or `role_arn` + `web_identity_token_file` |
| `azure_key_vault` | `vault_url` | `tenant_id` + `client_id` + `client_secret`, or `managed_identity: true` |
| `gcp` | `project_id` | `service_account_json`, or `use_metadata_server: true` |
| `kubernetes` | `api_url`, optional `namespaces`, `ca_cert` | `token`, or `in_cluster: true` |

Read-only permissions are enough everywhere, and the narrower the better —
`acm:ListCertificates` and `acm:GetCertificate`; `certificates/get` and
`certificates/list` on the vault; `compute.sslCertificates.list`; `get` and
`list` on secrets and ingresses.

`config` is validated **before** it is sealed, so a missing region or a
malformed service account key is a 400 while somebody is typing it, rather than
a sync failure six hours later that reads on a dashboard like the account
refusing the connection. It is then encrypted with the keyring under its own
context string. No endpoint returns it, the listing does not carry the sealed
blob either, and the audit entry records the act rather than the credential.

The floor on `sync_interval_minutes` is **30**. Lower than Certificate
Transparency's, because these are your own accounts rather than somebody's free
service — but not trivial, because every sync is a burst of API calls against a
quota your deployments share.

### The finding this exists for

Not "here is another certificate". This:

| Provider | Renews | Does not renew, and looks identical |
|:---|:---|:---|
| AWS ACM | Amazon-issued and still validating | anything **imported** — `RenewalEligibility: INELIGIBLE` |
| Azure Key Vault | a policy with an `AutoRenew` action | policy issuer `Unknown` — uploaded as a PFX, no issuer to go back to |
| Google Cloud | `MANAGED` | `SELF_MANAGED` |
| Kubernetes | secrets cert-manager annotates | every other `kubernetes.io/tls` secret |

Findings carry the provider's own word for it, because that word is what
somebody has to go and find in their console:

```json
{ "code": "will_not_renew", "severity": "CRITICAL",
  "detail": "Nothing renews this certificate: AWS Certificate Manager reports it as \"IMPORTED\". It expires in 2 weeks, and it will simply stop working then unless somebody replaces it by hand." }
```

Severity tracks **time, not category** — `INFO` beyond 90 days, `WARNING` inside
it, `CRITICAL` inside 30 — because a finding that appears on every row is the
noise that stops people reading the list. `will_not_renew` is raised alongside
`expired` rather than instead of it: an expired certificate cert-manager is
about to replace and an expired certificate nobody will ever replace need
opposite responses.

The inverse is the sharpest finding here. `renewal_overdue` fires when a
provider says it renews a certificate and has not, within a week of expiry —
automatic renewal has failed, and nothing else in the system would have said so.

Filter on any of them:

```
GET /api/v1/cloud/certificates?finding=will_not_renew
GET /api/v1/cloud/certificates?management_state=UNMANAGED&unimported=true
```

### Scopes, or what was not looked at

Every successful sync records what it enumerated, in the provider's own words,
and the sync response returns it:

```json
"scopes": [
  "AWS Certificate Manager in eu-west-1 only — certificates in other regions are not visible to this connection",
  "each certificate's PEM body, to match it against inventory by fingerprint"
]
```

ACM is regional. GCP Certificate Manager is **not** covered — the GCP connection
reads `compute.sslCertificates`, and says so. A tool that covers one corner of a
provider while presenting itself as covering the provider produces a short list
that reads as a small estate when it is really a narrow search.

### Synced, versus answered

As with Certificate Transparency, `last_synced_at` and `last_success_at` are
separate columns and the listing surfaces `stale_connections`. A connection
whose credentials lapsed three days ago still attempts every hour, so its "last
synced" is a minute old and means nothing.

`POST …/sync` answers **502** when the provider does not, carrying the
provider's own words and the sentence *"The sync did not complete, so nothing
was learned about this account. It is not the same as finding no
certificates."* It is bounded at 25 seconds, under the server's write timeout,
so the response is never truncated into an empty body that reads as success.

A failed sync also never concludes that the estate was dismantled: certificates
are only marked as gone after a sync that answered, and an answer containing
nothing at all is treated as suspect rather than as an empty account.

### Attachment is three-valued

`attached` is `true`, `false`, or **absent**. Absent means the provider could
not be asked — a Key Vault has no notion of what is serving its certificates,
and a Kubernetes connection without read access to ingresses cannot tell either.
Reporting "nothing is using this" in those cases would be inventing a finding.
`false` is a real one: nobody will notice it expire, and it is still there to be
attached to something during an incident.

### Certificates that disappear

A certificate a successful sync no longer finds is marked `removed_at` and drops
out of the default listing. The row is kept — that a certificate vanished from a
production account is information, and deleting it takes its own history along
with it. `?include_removed=true` brings them back.

### Import

```json
POST /api/v1/cloud/import
{ "cloud_certificate_id": "…", "team": "Payments", "environment": "production" }
```

The certificate becomes a watched inventory record with
`discovered_via: "CLOUD"` and `auto_renew: false` — always false, whatever was
asked for. CertPilot holds no private key for something it read out of somebody
else's store. The response says so, and adds the reason it was found in the
first place: *"Note that the provider does not renew it either."*

## Renewal queue

```
GET    /api/v1/renewals                     What is queued, most urgent first
GET    /api/v1/renewals/:id                 One job, with every attempt
DELETE /api/v1/renewals/:id                 Cancel it                       (admin)
POST   /api/v1/certificates/:id/renew       Queue a renewal                 (operator)
```

Renewal is the only part of this system that changes the world. Everything else
observes. So it is not a call the scheduler makes — it is a durable row that
somebody owns, and a process that dies mid-renewal leaves behind something
another process can pick up.

### Asking for one

```json
POST /api/v1/certificates/{id}/renew
→ 202 Accepted
{ "data": { "id": "…", "status": "PENDING", "reason": "MANUAL", "attempts": 0 },
  "message": "Queued. Watch it at GET /api/v1/renewals/…" }
```

**202, not 200.** This endpoint used to call the gateway inline and return the
renewed certificate, which read well and was wrong in three ways: an ACME order
with a DNS challenge outlives the server's 30-second write timeout, so the
caller got a truncated response for a renewal that was still running; a failure
meant one attempt and no record of it; and a core that restarted mid-request
left nothing behind at all.

Pressing it twice returns **the same job**:

```json
{ "data": { "id": "…same id…" },
  "message": "A renewal for this certificate is already queued; this did not start a second one." }
```

Two certificates issued because somebody clicked twice is a real way to spend a
weekly rate limit. A certificate with no CA account — anything discovered rather
than issued — is refused with **400** at this point rather than becoming a job
that fails forever.

### Where a job stands

```json
GET /api/v1/renewals/{id}
{ "data": { "status": "PENDING", "attempts": 3, "run_after": "…",
            "escalated_at": "…", "not_after": "…",
            "attempt_log": [
              { "number": 1, "started_at": "…", "duration_ms": 412,
                "worker": "core-7c9f/1", "error": "dial tcp 10.0.0.5:9091: connection refused" }
            ] },
  "summary": "Failed 3 time(s), with 41 hours left before this certificate expires. Retrying in 8 minutes. The most recent error was: …" }
```

The **whole attempt log**, not just the last error. "This has failed eleven
times in six days with the same DNS error" is a sentence somebody can act on;
`last_error: timeout` cannot tell a blip from a fortnight of silence. Each entry
names the worker that made it, because one replica failing and every replica
failing are different problems.

The log is capped at the 50 most recent attempts, so a renewal retrying for
weeks does not grow without limit inside a row a dashboard reads constantly. The
attempt count is kept separately and is not capped.

### What the queue does with failure

A failed attempt leaves the job **PENDING** with `run_after` moved forward.
There is no attempt count at which a certificate stops needing to be renewed,
and a queue that gives up on its own goes quiet exactly when it matters.

The delay is the **smaller** of two answers: what exponential backoff says
(2 minutes doubling to a 6-hour ceiling), and what the deadline allows — the
remaining runway divided into a budget of 24 more attempts.

| Runway | Delay |
|:---|:---|
| a month | ~6 hours, the ordinary ceiling |
| a day | ~1 hour |
| an hour | a few minutes |
| already expired | the 60-second floor |

Every backoff library assumes there is no deadline. A certificate has one, and
as it approaches the cost of *not* retrying grows without bound while the cost
of retrying stays flat, so backing off further is exactly wrong. Never faster
than 60 seconds, though: a CA answering the same error once a second will not
answer differently on the two hundredth try.

Jittered ±20% either way. Forty renewals failing against one CA outage and all
coming back at the same instant is how a transient failure becomes a rate-limit
suspension.

`escalated_at` is set when a failure stops being a blip — three attempts, or a
single failure with less than seven days of runway, because close to expiry
there may not be room for many more attempts. The `cert.renewal_failed` alert
fires **once**, on escalation, not per attempt.

```
GET /api/v1/renewals?escalated=true
```

The listing surfaces a `warning` naming them: *"3 renewal(s) have been failing
long enough to need attention … Each of these is a certificate on a countdown."*

The listing defaults to outstanding jobs only — the question is almost always
"what is about to happen", not "what happened last month". `?outstanding=false`
returns the history.

### Rate limits: deferred is not failed

```
PUT /api/v1/ca-accounts/{id}/rate-limit          (operator)
{ "renewal_rate_limit": 50, "renewal_rate_window_hours": 168 }
```

A public CA counts certificates per registered domain per week, and exhausting
that suspends issuance for the whole organisation — at exactly the moment
somebody is reissuing to fix an outage. `0` means unlimited and is the default,
deliberately: inventing a limit for a CA whose real limits nobody entered would
delay renewals for a constraint that does not exist.

A renewal with no slot available is **deferred**, and a deferral is carefully
not a failure:

- `attempts` is not incremented — the claim's increment is undone, because
  nothing was tried
- `last_error` is left holding whatever real failure came before it
- nothing escalates: a job that waited nine times has not failed nine times
- `run_after` is set to the moment the oldest renewal ages out of the window, so
  it returns exactly once rather than polling

```json
{ "attempt_log": [ { "deferred": true,
    "reason": "letsencrypt-prod has renewed 50 certificate(s) in the last 168 hours, which is its limit of 50. A slot opens at 2026-08-25T20:53:33+02:00." } ] }
```

The listing counts them separately as `waiting_on_rate_limit`, because a waiting
renewal is the pacing working and a stuck one is a certificate on a countdown.

Counted in the database rather than in a per-process token bucket: N replicas
each holding their own would allow N times the limit. A limit that cannot be
*read* never blocks a renewal — turning a database hiccup into an expiry is a
much worse trade than being one certificate over a quota.

**When the quota outlasts the certificate** it is not a deferral at all, and the
alert says so in different words, because retrying will not fix it:

> `step7-filter-probe.example.com` cannot be renewed because the CA account's
> renewal rate limit is full until 29 November 2028, and it expires on
> 18 August 2027. Retrying will not fix this: the limit has to be raised, or
> this certificate moved to another CA account.

Published once, when it is first noticed — months before the day, not on the
morning it happens.

### Ordering, leases, and why there is no leader

Jobs are claimed **by the deadline being raced, not by age**. A certificate
expiring tomorrow outranks one enqueued an hour earlier with a month left.

A claim is a **lease** — `locked_by` and `locked_until`. A worker killed
mid-renewal does not need to be cleaned up after: its claim expires and another
worker takes the job. Long renewals heartbeat to extend it, so an ACME order
waiting on DNS propagation is not stolen mid-flight.

There is no leader election and no advisory lock. Enqueues collide on a partial
unique index (`at most one outstanding job per certificate`) and claims use
`FOR UPDATE SKIP LOCKED`, so N replicas can all run the sweep and all run
workers without duplicating anything. A leader would be a single point of
failure with a window after it dies during which nothing renews at all, which is
a strange thing to build into the component whose entire job is that nothing
lapses.

### Cancelling

```
DELETE /api/v1/renewals/{id}
{ "message": "Renewal cancelled. Nothing is now scheduled to replace this certificate before it expires." }
```

Admin, and the response says what it costs. Cancelling is never how a failure is
handled — a renewal nobody cancelled keeps trying.

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
