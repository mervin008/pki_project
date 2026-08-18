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
health sweep runs on a timer, changes are pushed to the browser as they happen,
and there is a fullscreen mode built for a screen nobody is sitting at.

One rule drives that whole surface: **a dashboard that stops updating must look
broken, not healthy.** A frozen screen showing green manufactures exactly the
false confidence this tool exists to prevent, so connection state is a
first-class element of the UI, the client judges freshness by data age rather
than by whether a socket has errored, and a dead feed visibly degrades the
page instead of leaving the last good numbers on it.

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
| Renewal information (RFC 9773) | ✅ | Renews inside the CA's suggested window, at a random instant within it. A window pulled forward — what a CA does during a mass revocation — is a CRITICAL alert carrying the CA's own explanation |
| Self-signed gateway | ✅ | Development and testing |
| Secrets encrypted at rest | ✅ | AES-256-GCM envelope encryption, context-bound, rotatable |
| Mutual TLS, core ↔ gateway | ✅ | Required by default; `make dev-certs` to get started |
| OIDC authentication | ✅ | Any provider, via JWKS; legacy shared-secret path also supported |
| RBAC | ✅ | admin / operator / auditor / viewer, enforced per route |
| Audit log | ⚠️ | Recorded, but the table is not yet tamper-evident |
| Ownership and acknowledgement | ✅ | Who owns a CA, who acknowledged an alert and why. Silencing suppresses delivery only — an acknowledged CA never leaves the dashboard |
| Automated renewal | ⚠️ | Works; no retry, backoff, or distributed locking yet |
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

The API is on `:8080`, the frontend on `:3000`.

Three pages are worth opening first: `/` for the dashboard, `/ca-health` for
every CA sorted by urgency, and `/display` for the fullscreen wall view.

### Putting it on a wall

`/display` is meant to run unattended on a screen nobody is sitting at, so it
authenticates with its own credential rather than a logged-in session:

```bash
curl -X POST localhost:8080/api/v1/display-tokens \
  -H 'Content-Type: application/json' \
  -d '{"name": "ops-corridor", "expires_in_days": 90}'
```

The raw token is returned once and never again. Launch the screen at
`http://<host>:3000/display?display_token=cpd_...`; the browser moves it into
session storage and strips it from the address bar, since a query string reaches
history, `Referer` headers, and any photograph of the window.

Revoke it with `DELETE /api/v1/display-tokens/<id>` when the screen is
decommissioned — the display will show a "not authorised" panel rather than
continuing to render whatever it last saw.

### Getting alerts out

Threshold crossings reach Slack, a signed webhook, or email. Configure a channel
under Settings, or over the API:

```bash
curl -X POST localhost:8080/api/v1/notification-channels \
  -H 'Content-Type: application/json' -d '{
  "name": "pki-oncall",
  "channel_type": "slack",
  "severity_threshold": "WARNING",
  "config": {"webhook_url": "https://hooks.slack.com/services/..."}
}'
```

Then **test it**, because a channel nobody has ever sent through is a promise
rather than a capability:

```bash
curl -X POST localhost:8080/api/v1/notification-channels/<id>/test
```

That sends once, does not retry, and returns the destination's own complaint
verbatim — `invalid_token` tells you what to fix, "delivery failed" does not.

Each channel carries a minimum severity and an optional topic filter, so a
CRITICAL CA expiry can page while routine renewals stay quiet. Both outcomes are
audited: `notification.sent` and `notification.failed` are queryable through
`/api/v1/dashboard/activity?action=notification.failed`, because "we tried and
Slack refused" and "we never tried" look identical from outside and only one of
them means the configuration is wrong.

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

### Finding what nobody told you about

```bash
curl -X POST localhost:8080/api/v1/discovery/scan -H 'Content-Type: application/json' \
  -d '{"targets": ["example.com", "10.0.0.0/24", "internal-api.corp:8443"]}'
```

```
6 certificate(s) are being served that CertPilot does not manage. Nothing renews them.
```

That sentence is the output. A scan of a real estate returns mostly certificates
the team issued itself and already watches; the rows that justify having run it
are the ones nobody knew about, so every result carries a verdict —
`MANAGED`, `UNMANAGED`, or `UNREACHABLE` — matched on the certificate's
fingerprint rather than its hostname.

Alongside it, the second verdict: what the chain terminates in. `PUBLIC`,
`INTERNAL` (a CA registered here, so its own expiry is being watched),
`SELF_SIGNED`, or `UNTRUSTED` — someone is issuing certificates from an
authority nobody has registered, which is a finding in its own right.

Findings name the consequence rather than the observation:

```
incomplete-chain.example.com:443   UNMANAGED  PUBLIC
  [WARNING] incomplete_chain: The server sent only its own certificate and no
  issuing CA certificate. Clients that already hold the intermediate will
  connect and clients that do not will fail, which is why this breaks
  intermittently and only for some users.
```

An unreachable endpoint is a row, not an absence — a scan that reached nothing
and a scan that found nothing produce the same empty list, and only one of them
means the estate is clean.

A `/24` is 254 endpoints and takes minutes, so anything past a handful runs in
the background and returns a scan id to poll. Results are stored as they are
found, progress goes to the live event stream, and the run can be stopped:

```bash
curl -X POST localhost:8080/api/v1/discovery/scans/<id>/cancel
```

Cancelling keeps everything already found and records the run as `CANCELLED`
rather than `FAILED` — a scan somebody stopped on purpose is not a scan that
went wrong, and a history that cannot tell the two apart is one nobody reads.
Expansion is capped at 4096 endpoints, because a misplaced digit turns
`10.0.0.0/24` into sixteen million outbound connections carrying your address.

The full handshake is recorded on every result: TLS version, cipher suite, ALPN,
and the negotiated key exchange group. Not because any of it is a defect today,
but because it is unrecoverable afterwards — the connection is gone, and a
certificate on its own says nothing about how it was negotiated. "142 of your
endpoints do not negotiate X25519MLKEM768" is a question about history, and
history has to have been collected before it is asked.

Importing a finding watches it for expiry. It does **not** make it renewable:
CertPilot holds no private key for something it merely observed, so `auto_renew`
stays false whatever you ask for, and the response says why.

### Looking again

A scan run once is a snapshot, and the endpoint somebody stood up last Tuesday
is not in it. Schedules fix that:

```bash
curl -X POST localhost:8080/api/v1/discovery/schedules -H 'Content-Type: application/json' \
  -d '{"name": "nightly perimeter", "targets": ["10.0.0.0/24"], "interval_minutes": 1440}'
```

The second run is where the value is. It reports what **changed**:

```
127.0.0.1:8443   UNMANAGED  SELF_SIGNED
  [WARNING] certificate_changed: The certificate here changed since 17 August 2026
  and CertPilot manages neither the old one nor the new one. Something is renewing
  certificates on this endpoint outside this system, so somebody knows how to
  replace it — find out who.
```

The same rotation on a managed endpoint is a renewal CertPilot performed, and is
reported at INFO. Alerting on its own renewals is how a system teaches people to
ignore the alert that matters.

### Certificates you never asked for

A scan finds what is being served. Certificate Transparency finds what was
**issued** — including the certificate somebody obtained for your domain with a
personal ACME account and never deployed anywhere you could scan.

```bash
curl -X POST localhost:8080/api/v1/ct/monitors -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "include_subdomains": true}'
```

```
9 certificate(s) have been issued for badssl.com that CertPilot did not issue
and does not manage. Somebody holds their private keys.
```

The rule here is the dashboard's rule again: **a check that could not run must
not look like a check that found nothing.** Every monitor records when a check
was last *attempted* and when one last *answered*, separately, and the list
names the domains that have gone quiet. An on-demand check against an
unreachable index answers 502 with its own words, never an empty list.

### Certificates nobody is renewing

A scan finds what is **served**. Certificate Transparency finds what was
**issued**. Neither finds what is merely **stored** — a certificate sitting in
ACM, in a Key Vault, in a Google load balancer, or in a Kubernetes secret,
attached to an address nobody scanned or attached to nothing at all.

```bash
curl -X POST localhost:8080/api/v1/cloud/connections -H 'Content-Type: application/json' \
  -d '{"name": "prod-eu", "provider": "aws_acm",
       "config": {"region": "eu-west-1",
                  "role_arn": "arn:aws:iam::1234:role/certpilot-read",
                  "web_identity_token_file": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"}}'
```

The finding this exists for is not "here is another certificate". It is that
**cloud certificate stores do not renew everything in them, and everybody
believes they do**:

| Provider | Renewed | Not renewed, and identical on the console |
|:---|:---|:---|
| AWS ACM | Amazon-issued, still validating | anything **imported** — `RenewalEligibility: INELIGIBLE` |
| Azure Key Vault | a policy with an `AutoRenew` action | issuer `Unknown`, meaning it was uploaded as a PFX |
| Google Cloud | `MANAGED` | `SELF_MANAGED` — uploaded once, by someone who may have left |
| Kubernetes | secrets cert-manager owns | everything else in the namespace |

```
2 of the 3 certificate(s) in lab cluster are ones the provider itself does not
renew. They expire on their own schedule and stop working. 1 of them already has.
```

Severity tracks **time, not category**: a self-managed certificate with a year
left is a note and the same certificate with three weeks left is an emergency,
because a finding that appears on every row is what stops people reading the
list. The sharpest one is the inverse — a provider that says it renews a
certificate and has not, days from expiry. Automatic renewal has failed and
nothing else would have said so.

Every connection records what it actually **enumerated**, in the provider's own
words, and shows it beside the results:

```
scopes:
  - AWS Certificate Manager in eu-west-1 only — certificates in other regions
    are not visible to this connection
  - compute sslCertificates in project demo, global and every region
  - NOT Certificate Manager (certificatemanager.googleapis.com)
```

A tool that covers one corner of a provider while presenting itself as covering
the provider commits this project's original sin in a new place: a short list
that reads as a small estate when it is really a narrow search. And as with CT,
a sync that could not run is never a sync that found nothing — `last_synced_at`
and `last_success_at` are separate columns, a failed sync answers 502 carrying
the provider's own words, and it never concludes that an estate it could not
reach has been dismantled.

Credentials are sealed with the keyring before they are stored, never returned
by any endpoint, and never written to the audit log. No cloud SDK is vendored:
the four providers are their REST APIs plus SigV4, OAuth2, and JWT-bearer
signing written out, because two hundred transitive modules is a poor trade
inside a process that holds every private key this system has issued.

### Renewal is the only part that changes the world

Everything else in CertPilot observes. A discovery scan that runs twice wastes a
few seconds; a renewal that runs twice on two replicas issues two certificates
against a rate limit counted per week.

So a renewal is a **row somebody owns**, not a call the scheduler makes:

```bash
curl -X POST localhost:8080/api/v1/certificates/$ID/renew
```
```json
202 Accepted
{ "data": { "id": "1ade1796…", "status": "PENDING", "reason": "MANUAL" },
  "message": "Queued. Watch it at GET /api/v1/renewals/1ade1796…" }
```

Press it twice and you get the same job back, not a second certificate. A core
that restarts mid-renewal leaves a row another replica picks up when the lease
expires, rather than a certificate whose fate nobody recorded.

**There is no leader.** Enqueues collide on a partial unique index — at most one
outstanding job per certificate — and claims use `FOR UPDATE SKIP LOCKED`, so
every replica runs the sweep and runs workers without duplicating anything.
Electing a leader would put a single point of failure, and a window after it
dies during which nothing renews at all, inside the component whose entire job
is that nothing lapses.

Failure is recorded rather than retried blindly:

```
Failed 3 time(s), with 41 hours left before this certificate expires.
Retrying in 8 minutes. The most recent error was: dial tcp 10.0.0.5:9091:
connection refused
```

Every attempt is kept — when, how long, which replica, and what went wrong —
because *"this has failed eleven times in six days with the same DNS error"* is
a sentence somebody can act on and `last_error: timeout` cannot tell a blip from
a fortnight of silence. Backoff is jittered, so forty renewals failing against
one CA outage do not all come back at the same instant and fail together again.

A job is never abandoned. There is no attempt count at which a certificate stops
needing to be renewed. Instead it **escalates** — after three failures, or after
one if there is less than a week of runway — and the alert fires once at that
moment rather than every few minutes for a fortnight.

#### Backoff that tightens instead of loosening

Every backoff library assumes there is no deadline. A certificate has one, and
as it approaches, the cost of *not* retrying grows without bound while the cost
of retrying stays flat — so backing off further is exactly wrong.

The delay is the **smaller** of the exponential curve and the runway divided
into a budget of 24 more attempts:

| Runway | Delay |
|:---|:---|
| a month | ~6 hours (the ordinary ceiling) |
| a day | ~1 hour |
| an hour | a few minutes |
| already expired | the 60-second floor |

#### Letting the CA decide, and letting it change its mind

A CA publishes a window it would like each certificate replaced inside
(RFC 9773). CertPilot picks a **random instant** within it rather than renewing
at the start — renewing at the start would move the thundering herd instead of
dispersing it — and honours the CA's `Retry-After` when polling.

The advice beats the configured lead time in both directions, because the CA
knows things about the certificate that the certificate does not say. But never
off a cliff: inside a seven-day safety floor the advice stops being able to defer
anything, so a bad window — or a stale one left by a poller that stopped
running — cannot talk this system out of renewing something about to expire.

The reason this matters is not load spreading. When a CA has to revoke in bulk,
it pulls the affected windows into the past, and that is **the only automated
warning you get**:

```
CRITICAL — ari-lab.example.com: the CA wants this replaced sooner

ARI Lab Issuing CA has brought this certificate's renewal window forward by
about 3 days. A CA does that when something is wrong with a certificate it
issued — most often a bulk revocation. CertPilot has rescheduled the renewal;
check the explanation before assuming it is routine.

  Renewing at:        19 August 2026, 02:35 CEST
  Brought forward by: 3 days
  Explanation:        https://letsencrypt.status.io/incidents/…
```

Support is three-valued — never asked, asked and unsupported, asked with an
answer — because a CA nobody has reached must not read as one with nothing to
say. A CA that publishes no renewal information is told so plainly: *"it will
not be able to warn you if it revokes this certificate in bulk."*

#### A renewal held back is not a renewal that failed

A public CA counts certificates per week, and exhausting that suspends issuance
for the whole organisation — at exactly the moment somebody is reissuing to fix
an outage. So set the account's limit and the queue paces itself:

```bash
curl -X PUT localhost:8080/api/v1/ca-accounts/$ID/rate-limit \
  -d '{"renewal_rate_limit": 50, "renewal_rate_window_hours": 168}'
```

A renewal with no slot is **deferred**, not failed: the attempt is un-counted,
the last real error is left intact, nothing escalates, and it returns exactly
when a slot opens rather than polling for one.

```
Waiting for the CA's rate limit, not failing. letsencrypt-prod has renewed
50 certificate(s) in the last 168 hours, which is its limit of 50.
A slot opens at 2026-08-25T20:53:33+02:00. Next try in 7 days.
```

Counted in the database, not in a per-process bucket — N replicas each holding
their own would allow N times the limit. Unlimited is the default: inventing a
limit for a CA whose real limits nobody entered would delay renewals for a
constraint that does not exist.

And when the quota does not free up until after the certificate expires, that is
not a deferral at all. It is a loss with a date on it, months in advance:

```
step7-filter-probe.example.com cannot be renewed because the CA account's
renewal rate limit is full until 29 November 2028, and it expires on
18 August 2027. Retrying will not fix this: the limit has to be raised, or
this certificate moved to another CA account.
```

### A renewal is not done when the certificate is stored

It is done when the thing serving it is serving it.

CertPilot deploys nothing yet, so a successful renewal routinely leaves a new
certificate in the database and the old one in front of the users — expiring on
the old schedule, under a green dashboard. That is the failure this whole
product exists to prevent, arriving through its own renewal engine.

So every renewal schedules a check, and the check re-probes **the endpoints
discovery has actually observed serving that certificate**:

```bash
curl -X POST localhost:8080/api/v1/certificates/$ID/verify
```
```json
409 Conflict
{ "state": "STALE",
  "summary": "127.0.0.1:9500 is still serving the certificate this renewal replaced. The new certificate exists in CertPilot and has not reached the server, so what users get expires on the old schedule." }
```

```
CRITICAL — Renewed, but not deployed: verify-lab.local

verify-lab.local was renewed successfully, and the server is still presenting
the certificate it replaced. CertPilot's record looks healthy; what users get
expires on the old schedule. The new certificate has to be installed.
```

Install it and the same call answers `200 VERIFIED`, and stops asking.

Not the SANs — probing hostnames read out of certificate data would open
connections nobody asked for. A certificate discovery has never seen is reported
as `NO_ENDPOINTS` with the sentence that fixes it, because *"we cannot verify
this"* is useful and a fabricated verification is not. An endpoint that does not
answer is `UNREACHABLE`, never verified: silence is the one answer that must
never be read as success.

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

**Display tokens.** The obvious way to get a dashboard onto a corridor screen —
leave an operator session logged in on the machine — hands that machine the
authority to issue, revoke, and export private keys. A display token is a
separate credential that carries none of it. The role it grants is the constant
`viewer`; anything but a `GET` is refused on every route; private-key export,
token enumeration, and the actor-attributed activity feed are refused by path,
independently of the role gates those routes already carry. Tokens expire, are
revocable, and record where and when they were last used. Only a SHA-256 is
stored, so the raw value exists in exactly one response and nowhere else.

The server accepts the token in an `X-Display-Token` header or a
`display_token` query parameter. The query parameter exists for `EventSource`
clients, which cannot set headers; CertPilot's own frontend streams over `fetch`
and so uses the header, which stays out of access logs and `Referer`. A real
session always takes precedence — a display token left in a bookmark cannot mask
an operator's identity in the audit log.

**Notification channels.** A Slack webhook URL and an SMTP password are bearer
credentials, so a channel's configuration is sealed with the keyring before it is
stored and is never returned by any endpoint — not in the create response, not in
the list. It is write-only from a client's point of view, which is why editing a
channel without re-sending `config` keeps what is stored rather than requiring an
operator to re-type a secret they cannot read back.

Generic webhooks are signed with HMAC-SHA256 when a signing secret is set. The
signature covers `<unix-seconds>.<raw body>` and travels in
`X-CertPilot-Signature` alongside `X-CertPilot-Timestamp`. The timestamp is
*inside* the signed string rather than merely beside it: signing the body alone
produces a signature that never expires, so one captured delivery could be
replayed forever and the receiver would have no way to tell.

**Acknowledgement.** Acknowledging a CA records who looked and why; it never
removes the CA from the dashboard or the wall display, and never changes its
status. Silencing suppresses *delivery* only, is capped at 90 days — there is no
indefinite option, because a permanent silence is indistinguishable from deleting
the alert — and is bound to the expiry threshold it was granted at, so a CA that
crosses a tighter one pages regardless of who acknowledged the last.

**Production mode** refuses anonymous access, an insecure gateway channel, and a
wildcard CORS origin. These are the settings that look harmless locally and
travel to production unnoticed.

### Known gaps

- The audit log is an ordinary table. It is not yet hash-chained, so a database
  writer can rewrite history.
- Rate limits are per CA account, not per registered domain. That is the right
  granularity for an internal CA and coarser than Let's Encrypt actually counts,
  so an account holding certificates for several registered domains will be
  paced more conservatively than it needs to be.
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
- `PostgresStore` has now been exercised end to end against a real PostgreSQL 17
  database — migrations, issuance, renewal with key rotation, CA health sweeps,
  expiry alerting, filtering, and private key export all verified — but it is
  still not covered by automated tests. The suite runs against the in-memory
  implementation. That gap is not theoretical: the manual run turned up four
  defects the in-memory store could not express, including one that made
  certificate issuance fail outright. A container-backed suite is the fix and is
  not written.
- `/dashboard/activity` is still available to any authenticated reader,
  including `viewer`. Kiosk display tokens are refused it outright, since audit
  entries carry actor identity and a corridor screen should not name who deleted
  what — but a signed-in viewer is a person, and is not restricted.
- After the core has been down for a while, a wall display can take up to 30
  seconds to notice it is back — the reconnect backoff is capped there so a floor
  of displays does not stampede a core the instant it restarts.

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
make test           # all modules
make test-race      # under the race detector
make test-frontend  # typecheck the UI and run its checks
make lint           # go vet and gofmt
make proto          # regenerate protobuf code
make help           # everything else
```

The repository is a Go workspace of four modules: `pkg` (shared), `core`, and
one per gateway. Tooling iterates over them, since a single `./...` from the
root does not cover a workspace.

The frontend has no test runner and deliberately needs none: Node strips
TypeScript types natively from v22.18, so `frontend/scripts/check-*.mjs` import
the modules under test directly, with no build step and nothing to install. They
cover the three pieces that are hand-rolled and fail silently when wrong — SSE
frame parsing, CA chain resolution, and the display-token client.

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

See [ROADMAP.md](ROADMAP.md). The monitoring milestone is complete: a streaming
dashboard, a CA health view, a wall display, alert delivery to Slack / SMTP /
signed webhooks, and ownership with acknowledgement. Next is a renewal engine
that survives 47-day certificates — durable job queue, leader election, backoff,
and post-renewal verification.

## License

[Apache 2.0](LICENSE)
