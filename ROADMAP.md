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

### Phase 3 — A monitoring surface a team can leave on a screen ✅

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
| 7 | Alert delivery: Slack, webhook, SMTP | ✅ |
| 8 | Acknowledgement and ownership | ✅ |

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

**Step 7** made alerts leave the building. Slack, a signed generic webhook, and
email over SMTP, with the dispatcher subscribing to the broker rather than being
called inline — so a wedged Slack webhook loses its own place in the queue and
can never apply backpressure to the CA health sweep. Two rules shape it: a
channel is validated when it is saved and can be tested on demand, because a
channel that looks configured and silently drops everything is worse than none;
and both outcomes are audited, because "we tried and Slack refused" and "we never
tried" look identical from outside and only one means the configuration is wrong.

**Step 8** answered the two questions the dashboard could not: who owns this CA,
and has anyone already looked at it. Without the second, an alerting dashboard
becomes wallpaper within a month — the same red row every morning, no way to tell
whether it is being handled, and the team stops reading it.

One rule governs it, and it is the one most likely to be "simplified" later:
**silencing suppresses delivery, never display.** An acknowledged CA stays
exactly where it was in the urgency order, marked with who acknowledged it and
why. Silencing buys quiet in Slack, not a clean screen. Two consequences follow.
An acknowledgement is bound to the threshold it was granted at, so someone who
silenced a CA at 30 days has not silenced the 7-day page — that is a materially
different situation and the earlier "yes, we know" answered a different question.
And the acknowledgement lookup fails *open*: a database blip must not turn into
an alert nobody received, because the cost of a duplicate notification is an
annoyed engineer and the cost of a suppressed one is an expired CA.

With that, phase 3 is complete.

The rest:

- **Chain visualisation.** Each CA now states its position and lineage, and a
  malformed hierarchy is flagged rather than hidden. The tree itself — root →
  intermediate → issuing drawn as a tree, with health carried up it, because a
  healthy issuing CA under an expiring root is not healthy — is not drawn yet.
- **Expiry timeline.** What breaks in the next 7 / 30 / 90 days, grouped by team
  and environment.

### Phase 5 — Discovery that finds what nobody told you about

| Step | | |
|:---|:---|:---|
| 1 | Scans that persist, and the verdict that matters | ✅ |
| 2 | CIDR expansion, worker pool, cancellation, progress on the stream | ✅ |
| 3 | Scheduled scans and re-scan reconciliation | ✅ |
| 4 | CT log monitoring | ✅ |
| 5 | Cloud inventory: ACM, Azure Key Vault, GCP, Kubernetes secrets | ✅ |

One sentence governs the phase:

> **Discovery's output is not a list of certificates. It is the list of
> certificates nobody told you about.**

A scan of a real estate returns mostly certificates the team issued itself and
already watches. Those rows are noise. So every result carries a verdict —
`MANAGED`, `UNMANAGED`, `UNREACHABLE` — decided on the certificate's fingerprint
rather than its hostname, because two certificates for the same host are two
different certificates and the one being served is the one that expires. An
inventory lookup that fails reports `UNMANAGED` and says so: calling something
managed that could not be checked is how a lookup error becomes an outage.

**Step 1** replaced a scanner that could reach one host and store nothing.
`discovery_scans` and `discovery_results` had existed since migration 001 with
no Go surface at all, and the columns 001 chose describe a certificate — which
is what a scanner *finds*, not what it needs to say.

A second verdict runs alongside the first: what the served chain terminates in.
`PUBLIC`, `INTERNAL` — a CA registered in CertPilot, so its own expiry is
already being watched — `SELF_SIGNED`, or `UNTRUSTED`, meaning someone is
issuing certificates from an authority nobody has registered. Internal trust is
decided on **signatures rather than by path building**, and that distinction is
load-bearing: an expired certificate fails every verification for one reason,
and letting that reason decide the trust answer reports every expired internal
certificate as issued by an unknown CA, sending whoever reads it hunting a rogue
issuer that does not exist.

Findings name the consequence rather than the observation. A missing
intermediate is not "chain incomplete" but "clients that already hold the
intermediate will connect and clients that do not will fail, which is why this
breaks intermittently and only for some users". It is also detected without
relying on verification succeeding, because a platform verifier caches
intermediates it has seen — so the endpoint verifies on the machine that has
visited it and fails on a fresh one, which is the defect itself.

Two deliberate omissions. `auto_renew` is always false on import whatever was
asked for, because CertPilot holds no private key for something it merely
observed and a record claiming it will renew itself is a promise the system
cannot keep. And a classical key exchange is **not** a finding: it is true of
nearly every endpoint alive, and a finding that appears on every row is the
noise that stops people reading the list. The negotiated group is recorded
verbatim instead — which is the whole point of capturing the handshake, since it
is unrecoverable once the connection is gone.

Verified against live endpoints, not only in tests: expired, self-signed,
wrong-host, incomplete-chain, TLS 1.0, 3DES, and a SHA-1 intermediate each
produced exactly one correct finding, an unmanaged run reached a signed webhook
through the existing dispatcher, and importing a result flipped the same
endpoint to `MANAGED` on re-scan.

**Step 2** made it a scanner rather than a lookup. Targets expand from CIDR
networks and address ranges, run through a worker pool, and can be stopped.

Expansion is where a typo becomes an incident: one misplaced digit turns
`10.0.0.0/24` into `10.0.0.0/8`, which is sixteen million outbound connections
carrying CertPilot's return address across somebody else's network. So the size
is counted from the prefix before a single address is materialised, and the
refusal names the number rather than merely saying no.

Three things follow from a scan now taking minutes rather than seconds.

Results are **written as they are found**, so a run that is cancelled, crashes,
or is restarted through keeps everything it reached — the alternative is having
nothing to show for the one endpoint it found something on. Progress goes to the
event stream, but **never** to a notification channel: a range scan would put a
message in Slack every few seconds for minutes, and a team that mutes that
channel has also muted the CA expiry alerts sharing it. That distinction now
exists in the broker as a property of the topic rather than of the severity,
because an INFO event can still be news.

And **cancelled is not failed.** A scan somebody stopped on purpose reached what
it reached; recording it as a failure would make the scan history lie about
which runs went wrong, and that history is the only thing that says whether
discovery is running at all. Endpoints abandoned mid-probe are not recorded as
unreachable either — they were never really asked, and a row saying otherwise is
a finding about the estate invented by stopping the scan.

The scan record keeps the targets as they were **typed**, with a separate count
of what they expanded to. A scan is repeated by re-running what was asked for
and found again by the range someone remembers typing; 254 addresses in an audit
entry answer neither question.

**Step 3** made it monitoring rather than a snapshot, which is the difference
between finding what was there the morning somebody ran a scan and finding what
is there now. Schedules run scans on an interval — not a cron expression, since
a cron field is a small language whose mistakes are silent and a schedule meant
to run nightly that instead runs yearly looks identical on screen to one that
works.

The important half is not the timer, it is what a *second* run is for. The
second scan of a range is not worth much as a list; it is worth what it says has
changed. Three findings exist only on a re-scan, and one of them is the reason
to bother:

> A certificate that changed on an endpoint CertPilot does not manage means
> something out there renewed it without going through any of this. **Somebody
> knows how to replace that certificate** — find out who.

The same rotation on a managed endpoint is a renewal CertPilot performed, and is
reported at INFO. Alerting on its own renewals is how a system teaches people to
ignore the alert that matters. An endpoint that used to answer and no longer
does is the third: either it moved and the scan no longer covers it, or it is
down, and both are invisible to a first scan. A first scan reports none of them,
because every endpoint is new the first time and a run whose findings are all
"this is new" is one nobody reads twice.

This also closed the gap step 1 left open. The results list now returns the
latest observation per endpoint, so a nightly schedule stops turning one
unmanaged certificate into thirty findings. The collapse happens *before* the
filters — the other order answers "the most recent time this endpoint was
unmanaged" and keeps asking for work already done — and the full history is
still one query parameter away.

Two smaller rules, both learned by reading what the system actually said. A
schedule advances even when its run fails, because one that only advanced on
success would retry a permanently broken target every tick, turning a single bad
entry into a scan running continuously against somebody else's network; the
error is recorded on the schedule rather than only logged, since a schedule that
fails every night and is never read is the appearance of coverage. And the
change alert is composed from the parts that happened: the first version said
"0 endpoints are serving a different certificate … so something is renewing
certificates outside this system", which asserts a claim about zero things and
then draws a conclusion from it.

**Step 4** added the half of discovery that a network scan cannot reach. A scan
answers "what is being served on the addresses I told you about". Certificate
Transparency answers a larger question — **what has been issued in your name at
all**, by any CA, to anyone, whether or not it was ever deployed and whether or
not the machine is reachable from here. A developer who obtained a certificate
for `api.corp.example.com` with a personal ACME account appears in no scan of
any range, and appears in CT within minutes, because every publicly-trusted CA
is required to log there.

One rule governs it, and it is the same rule as the dashboard's:

> **A check that could not run must not look like a check that found nothing.**

So a monitor carries two timestamps, not one: when a check was last *attempted*,
and when one last *answered*. Collapsed into a single "last checked", a monitor
unable to reach the log for a week reads exactly like one that has found nothing
for a week — and only one of those means nobody is being told about certificates
issued in their name. The list surfaces stale domains, and an on-demand check
answers 502 with the index's own words rather than an empty list.

That rule was exercised immediately: crt.sh returned 502s through most of the
live verification. The failure path is therefore the better-tested one, which is
not the worst outcome for a feature whose dependency is a free community service.

Two defects came out of running it against real data rather than fixtures.

A precertificate and its final certificate are logged separately and share a
serial, and the index publishes no field saying which is which — so a live check
of `badssl.com` reported **18** certificates where there are **9**. A headline
number wrong by a factor of two is one people act on. Entries are now labelled
by the one reliable signal (the precertificate is logged first, so it carries
the lower entry id), both rows are kept because "pre-logged, then issued" is
real information, and every count is per certificate.

And the synchronous check outlived the HTTP server's 30-second write timeout, so
the response was cut off mid-write and the caller got an empty body — which
reads as "nothing happened", the one conclusion that must never be reachable by
accident. The on-demand path is now bounded under it; the background poller
keeps its longer budget, because nobody is waiting on it.

Findings are matched to inventory on serial number, since the log index does not
publish a fingerprint. Both sides normalise first: CertPilot stores unpadded
lowercase hex and indexes pad and upper-case them, and a mismatch there would
report this system's own certificates as ones nobody manages.

**Step 5** covered the third place certificates hide: stored rather than served.
ACM, Azure Key Vault, Google Cloud load balancing, and Kubernetes TLS secrets.

The reason this belongs in a certificate lifecycle tool, rather than "because
cloud is popular", is one sentence: **cloud certificate stores do not renew
everything in them, and everybody believes they do.** AWS never renews an
imported certificate and says so in `RenewalEligibility`, a field beside a green
`ISSUED` on the console. A Key Vault certificate whose policy issuer is
`Unknown` was uploaded as a PFX and has no issuer to go back to — its lifetime
action can only send an email. A GCP `SELF_MANAGED` certificate sits in the same
list as its `MANAGED` neighbour and is renewed by nobody. A Kubernetes secret
without a cert-manager annotation was made by hand by somebody who may have
left. On each provider's own console, all four are indistinguishable from the
ones that renew themselves.

Severity therefore tracks **time rather than category**. The same self-managed
certificate is a note with a year left and an emergency with three weeks left,
and ranking them alike buries the one that matters among two hundred that do
not — the noise rule from step 1, in a new place. The inverse finding is the
sharpest of all: a provider that claims to renew a certificate and has not, days
from expiry, means automatic renewal has failed and nothing else would have said
so.

Two things are recorded that a naive inventory would omit. **Scopes** — what
each sync actually enumerated, in the provider's own words, including what it
cannot see: ACM is regional, and GCP Certificate Manager is not covered at all.
A tool that quietly covers one corner of a provider while presenting itself as
covering the provider produces a short list that reads as a small estate when it
is really a narrow search. And **attachment is three-valued**: attached, not
attached, or not knowable. A Key Vault has no idea what is serving its
certificates, and reporting "nothing is using this" there would be inventing a
finding.

No cloud SDK is vendored. The four providers are their REST APIs plus SigV4,
OAuth2 client credentials, JWT-bearer signing, and the instance metadata
services, written out — roughly two hundred transitive modules avoided inside a
process that holds every private key this system has issued. The signer is
checked against AWS's published test vector, because the failure mode of getting
it subtly wrong is a 403 that reads on a dashboard as the account refusing us.

Two defects came out of running it rather than testing it. An expired
certificate that nothing renews looked exactly like an expired certificate
cert-manager was about to replace on its own, because the two findings were
competing in one switch; they are separate facts now and both are raised. And
the import was rejected outright by a check constraint from migration 001 that
had never heard of `CLOUD` — invisible to every test, because the in-memory
store enforces no constraints. Writing `IMPORT` instead would have passed and
thrown away the answer to the only question that column exists for.

**Still open in this phase:** two replicas both run every schedule, every CT
monitor, and every cloud sync. Leader election over Postgres advisory locks
arrives with the renewal engine in phase 4, which has the same gap.

### Phase 4 — A renewal engine that survives 47-day certificates

Deferred deliberately: it is the last phase before deployment, and every earlier
phase widened what it has to renew.

| Step | | |
|:---|:---|:---|
| 1 | Renewal as a durable job, not a function call | ✅ |
| 2 | Backoff that tightens towards the deadline, and per-CA rate limiting | ✅ |
| 3 | ARI: let the CA say when, and when it changes its mind | ✅ |
| 4 | Post-renewal verification — confirm the new certificate is actually served | ✅ |

One sentence governs the phase:

> **Renewal is the only part of this system that changes the world.
> Everything else observes.**

Every other engine can be wrong, retried, or restarted with no consequence
beyond a stale screen. This one issues certificates, rotates private keys, and
replaces working material with new material. A discovery scan that runs twice
wastes a few seconds; a renewal that runs twice on two replicas issues two
certificates against a rate limit that is counted per week.

Which is why renewal stops being a call the scheduler makes and becomes a row
somebody owns. A process that dies mid-renewal must leave behind something that
can be picked up, not a certificate whose fate nobody recorded.

**Step 1** made that literal. A renewal is a row in `renewal_jobs` with a lease,
an attempt log, and a deadline it is racing.

The thing worth arguing about is what is *not* there: **there is no leader
election.** The roadmap said Postgres advisory locks, and building it that way
would have been a mistake. A leader is a single point of failure with a window
after it dies during which nothing renews at all, which is a strange thing to
put inside the one component whose entire job is that nothing lapses. Instead
the correctness comes from the schema: a partial unique index allows at most one
outstanding job per certificate, so two replicas sweeping in the same second
produce one job, and `FOR UPDATE SKIP LOCKED` means two workers never claim the
same row. Every replica is an equal worker and none of them is special.

The lease is the other half. A worker that is OOM-killed mid-renewal does not
need reaping — its claim expires and somebody else takes the job. Long renewals
heartbeat to extend it, because an ACME order waiting on DNS propagation can
outlive a five-minute lease and a job stolen mid-flight is one renewal becoming
two certificates.

Three decisions that look small and are not:

**A failed job stays outstanding.** There is no attempt count at which a
certificate stops needing to be renewed, so nothing is ever abandoned. It
escalates instead — after three failures, or after one when there is less than a
week of runway — and the alert fires once at that moment. A renewal retrying
every few minutes for a fortnight would otherwise put thousands of CRITICAL
messages into the channel that also carries CA expiry alerts, and a muted
channel takes those with it.

**Every attempt is kept, not just the last error.** "This has failed eleven
times in six days with the same DNS error" is a sentence somebody can act on;
`last_error: timeout` cannot distinguish a blip from a fortnight of silence.
Each entry names the replica that made it, because one replica failing and every
replica failing are different problems.

**The crash guard checks the outcome rather than trusting a key.** A worker that
finalised an order and died before writing the result would otherwise issue a
second certificate on retry. So the next attempt compares the certificate's
fingerprint against what it was at enqueue: if it moved on its own, the renewal
already happened. Verifying what actually changed beats an idempotency token,
because it is true however the world changed.

`POST /certificates/:id/renew` now answers 202 with a job. It used to call the
gateway inline and return the renewed certificate, which read well and was wrong
three ways: an ACME order with a DNS challenge outlives the 30-second write
timeout, so the caller got a truncated response for a renewal still running; a
failure meant one attempt and no record of it; and a restart mid-request left
nothing behind. Pressing it twice now returns the same job rather than spending
a weekly rate limit twice.

Two defects came out of reading the live output rather than the tests. A warning
that read *"8759 hours left"* — technically correct, and a number nobody parses
at a glance, which in a list of things needing attention means it does not get
read at all. And the same warning named certificates by UUID, so it could tell
somebody a renewal was broken without telling them which certificate it was.

Verified against the live database across a deliberate outage: four failed
attempts, a core restart in the middle, then success when the gateway came back
— all one job, `['fail','fail','fail','fail','ok']`, with the escalation raised
once on the third.

**Step 2** fixed the pacing, which step 1 had left deliberately wrong.

Ordinary exponential backoff rests on three assumptions: failures are transient,
retrying costs something, and there is no deadline. A certificate violates the
third outright. As expiry approaches, the cost of *not* retrying grows without
bound while the cost of retrying stays flat — so backing off further, which is
exactly what every backoff library does, is exactly wrong.

The delay is now the **smaller** of what the exponential curve says and what the
runway allows, where the runway is divided into a budget of twenty-four more
attempts. With a month left it behaves like ordinary backoff and sits at the
six-hour ceiling. With a day left it retries roughly hourly. With an hour left,
every few minutes. A certificate that has already expired retries at the floor,
because it is an outage now and getting it back matters more than politeness —
but never below a minute, since a CA answering the same error once a second will
not answer differently on the two hundredth try.

The other half is rate limiting, and the thing worth getting right is not the
counting. It is that **a renewal held back is not a renewal that failed.** A
public CA counts certificates per registered domain per week, and exhausting
that suspends issuance for the whole organisation — at exactly the moment
somebody is trying to fix an outage by reissuing. So the queue declines to
spend a slot it does not have, and records that as a deferral: `attempts` is
un-counted, `last_error` is left holding whatever real failure came before, and
nothing escalates. A job that waited nine times has not failed nine times, and a
system that reported it that way would teach people that escalation means
nothing.

Counted in the database rather than in a per-process token bucket, for the same
reason step 1 has no leader: N replicas each holding their own bucket would
allow N times the limit. And a limit that cannot be *read* never blocks a
renewal — turning a database hiccup into an expiry is a much worse trade than
being one certificate over a quota.

Unlimited is the default, deliberately. Inventing a conservative limit for a CA
whose real limits nobody has entered would delay renewals for a constraint that
does not exist, and a certificate that expired because this tool was being
careful is the worst outcome available.

Out of that falls the sharpest thing this engine can say — that the quota does
not free up until *after* the certificate has expired:

> step7-filter-probe.example.com cannot be renewed because the CA account's
> renewal rate limit is full until 29 November 2028, and it expires on 18 August
> 2027. Retrying will not fix this: the limit has to be raised, or this
> certificate moved to another CA account.

That is a loss with a date on it, months before the day, and it is deliberately
worded away from "renewal failed, retrying" — nothing is broken and retrying
will not help, so an alert that sent somebody hunting for a fault would waste
the warning.

One defect, found live rather than in the tests: the blocked-by-quota alert
published correctly and never persisted its escalation mark, so a certificate
deferred every hour would have sent the same CRITICAL message every hour until
it expired — the precise noise failure the rest of the engine is built to avoid,
reintroduced in the one path that had not been through it.

**Step 3** let the CA decide, and — the part that matters — let it change its
mind.

The ACME gateway has read RFC 9773 renewal information since phase 2. Nothing in
the core ever asked, so the advice was fetched during a status call, logged, and
thrown away. That is a strange thing to find in a tool whose entire subject is
knowing when certificates need replacing.

Routinely, honouring the window lets the CA spread load in a way a lead time
cannot: thirty days means every certificate issued in one week renews in one
week, forever. The client is meant to pick a **random instant inside** the
window rather than renewing at its start, and that randomness is the point of
the window rather than an implementation detail — renewing at the start would
move the thundering herd instead of dispersing it.

In an incident it is something else entirely. A CA facing mass revocation — a
CAA rechecking bug, a mis-issued intermediate, a broken validation path — pulls
the affected windows into the past. Clients that read ARI replace their
certificates within hours. Clients that do not find out by email, if the address
on the account still belongs to somebody, and otherwise find out when the
certificate stops working. **It is the only automated warning there is**, which
is why a window brought materially forward is a CRITICAL alert carrying the CA's
own explanation link, worded as what it means rather than what changed.

Three decisions worth naming.

**The CA's advice beats the lead time in both directions — but never off a
cliff.** It can bring a renewal forward and it can hold one back, because the CA
knows things about the certificate that the certificate does not say. Inside a
seven-day safety floor it stops being able to defer anything at all: a CA
publishing a bad window, or a poller that stopped running and left a stale one
behind, must not be able to talk this system out of renewing something that is
about to stop working.

**Support is three-valued.** Never asked, asked and unsupported, and asked with
an answer are three different states. Collapsing the first two would make a CA
nobody has reached look identical to one that has nothing to say — the same
mistake as a monitor with a single timestamp, in a new place. A gateway that is
down is likewise not recorded as "this CA publishes nothing", and it never
clears advice already given: a window does not stop being true because the next
call failed.

**The alert has a threshold.** The selected instant is a fresh random draw each
check, so two consecutive polls of an unchanged window differ by hours for no
reason at all. Alerting on that would mute the one message that matters during
an incident before the incident.

Verified live against the real database, driving the real gateway over the real
proto with a stand-in ACME directory: the RFC 9773 certificate identifier was
built correctly from the AKI and serial, the window was recorded with a random
instant inside it, Retry-After was honoured, a window pulled forward produced one
CRITICAL naming the CA and linking its explanation, moving it *further* into an
already-open window produced no second alert, and a certificate with sixty days
left — which the thirty-day lead time would never have queued — was renewed
because the CA asked.

One defect found by reading the delivered alert: it rendered the renewal moment
as a date, so something happening in fifty-five minutes read as "18 August
2026". During a revocation that is the difference between acting now and acting
tomorrow.

**Step 4** closed the phase with the question everything before it had assumed
the answer to: **is the thing in front of the users actually serving the new
certificate?**

Until now a successful renewal wrote a new certificate, incremented the count,
set the status to ISSUED, and published "certificate renewed". Every one of
those can be true while the server is still presenting the certificate it
replaced — and still expiring on that certificate's schedule. It is the sharpest
possible version of the failure this product exists to prevent, produced by this
product: a green dashboard over an expiring estate, where the inventory says
ninety days and the endpoint says twenty.

CertPilot deploys nothing yet, so "renewed but not deployed" is not an edge case
here. It is the normal state, and reporting it is the difference between a
renewal engine and a renewal engine somebody can trust.

The endpoints checked are the ones **discovery has actually observed serving
this certificate** — the two halves of the product finally holding each other
up. Not the SANs: probing hostnames read out of certificate data would have
CertPilot opening connections nobody asked for, to names that may not resolve to
anything it should be touching. A certificate discovery has never seen is
reported as `NO_ENDPOINTS`, with the sentence that makes it actionable — *"run a
discovery scan that covers wherever it is deployed and this will start being
verified"* — rather than guessed at. "We cannot verify this" is useful; a
fabricated verification is not.

Silence is never success. An endpoint that does not answer is `UNREACHABLE`, and
a certificate where some endpoints serve the new one and others do not answer is
*not* verified — the ones that did not answer are exactly the ones that might
still be on the old certificate.

Two defects, both from running it rather than testing it.

The renewal set the verification fields on the certificate and saved it with
`UpdateCertificate`, whose explicit column list did not include them, so they
were **dropped in silence** against PostgreSQL. Every test passed: the in-memory
store keeps whole structs and cannot express a dropped column. Found by renewing
a real certificate and watching `previous_fingerprint` come back empty. It is
now written through the narrow verification writer, which is where it belonged
anyway.

And after renewing twice without deploying, the endpoint — still on the
original certificate, two renewals back — was reported as *"something else is
terminating TLS there"*. Technically true and badly wrong: it sends somebody
hunting a rogue service when the answer is that renewals have been landing
nowhere. An older certificate for the same name now has its own words.

Verified live end to end: issue, deploy, scan so discovery links the endpoint,
renew, and the check answered **409 STALE** naming the endpoint; deploy the
renewed certificate and it answered **200 VERIFIED** and stopped asking; renew
once more and one CRITICAL arrived — *"Renewed, but not deployed:
verify-lab.local … CertPilot's record looks healthy; what users get expires on
the old schedule."*

The 47-day horizon is what forces the rest. When the CA/Browser Forum's maximum
lifetime lands, a certificate is renewed roughly every fortnight rather than
twice a year — renewal stops being an event and becomes a heartbeat, failures
become routine rather than exceptional, and anything that quietly stops working
has weeks rather than months before it is noticed.

### Phase 6 — Deployment, then the agent

Renewal that does not reach the server is only half the job, and this is where
the commercial tools earn their price. Phase 4 ended by being able to say,
honestly, that a renewal had not reached the server. This is the phase that can
do something about it.

| Step | | |
|:---|:---|:---|
| 1 | Deployment as a durable job, and the first target | ✅ |
| 2 | The deployers that need no agent: Kubernetes, ACM, Azure Key Vault, F5 | |
| 3 | Deploy on renewal, and the loop that proves it landed | |
| 4 | The agent: enrolment, local key generation, install and reload | |

One sentence governs the phase, and it is not the same sentence that governed
phase 4:

> **Renewal creates new material. Deployment replaces material that is
> currently carrying traffic.**

A renewal that goes wrong leaves a certificate nobody installed — bad, and
recoverable by trying again. A deployment that goes wrong replaces a working
certificate on a live listener. Everything in step 1 is shaped by that
difference: nothing is deployed that has not been parsed, nothing is deployed
without the key that matches it when a target needs one, every attempt is
recorded against the *place* it was made, and success is reported as what it
actually is.

**Step 1** makes a deployment a row somebody owns, exactly as renewal is. The
same durable queue, the same lease, the same attempt log, the same
deadline-aware backoff — a certificate that has been renewed and not installed
runs down precisely the same clock as one that was never renewed at all, so the
retry curve tightens towards expiry for the same reason.

The one place the renewal queue's shape would have been actively wrong is the
partial unique index. Renewal allows one outstanding job per certificate,
because a second renewal issues a second certificate. Deployment is the opposite
case: **the index is on the binding, not the certificate.** A wildcard on six
load balancers needs six jobs outstanding at once, and copying renewal's
constraint would have deployed to the first target and dropped five without a
word.

That is also why `certificates.deployment_target_id` — one certificate, one
place, since migration 001 — is superseded by a binding table. One certificate
in six places has six outcomes, six fingerprints, and six ways to be
half-finished. A single `deployed_at` on the certificate averages them into a
number that is true of nowhere.

**What is deployed is the certificate as it stands now, not the fingerprint the
job recorded at enqueue.** If a second renewal happened while the job waited,
installing what the job was created for would push an older certificate onto a
live listener — and that renewal's own enqueue may well have been a no-op,
because the binding already had a job outstanding. The captured fingerprint stays
as provenance; it never selects the bytes.

The first deployer is the generic signed webhook, which is the escape hatch: any
receiver anybody can write fifteen lines of HTTP handler for becomes a
deployment target. Two of its rules are stricter than the notification
webhook's, and both follow from what the endpoint can *do* rather than what it
carries:

- **A signing secret is mandatory.** An unsigned alert webhook means a receiver
  might act on a fabricated alert. An unsigned *deployment* webhook means anyone
  who can reach the receiver can install a certificate on whatever it feeds —
  their certificate, their key, your hostname.
- **Private keys do not cross plaintext HTTP off the machine.** The exception is
  a loopback address, where there is no wire; that is the local-agent case, and
  refusing it would rule out the one topology where plaintext is harmless. A
  hostname that merely resolves to loopback today does not count.

`deployment_targets.deploys_private_key` is a plain column rather than something
derived from the sealed config at read time, because **"which places does this
organisation ship private keys to" has to be answerable with a SELECT** — by
somebody who does not hold the KEK and cannot decrypt a single deployment
credential.

Verified live end to end against a receiver written independently in Python,
which verified the documented HMAC itself: issue, bind, deploy, and the receiver
installed it and brought up a TLS listener; scan so discovery links the
endpoint; renew without deploying, and **both halves agreed from different
evidence** — the binding said *"1 holding an older certificate"* from its
recorded fingerprint with no network at all, and the verifier said **409 STALE**
from an actual handshake. Deploy, and it went to `200 VERIFIED`. Then the
receiver was made to refuse: three failures, the job stayed `PENDING`, one
CRITICAL arrived, and the binding kept the fingerprint it was really holding
rather than the one that failed to arrive. Signing the delivery with the wrong
secret produced `401: bad signature` from the receiver and that exact sentence
in the attempt log.

Running it caught a defect the tests did not. The binding summary reported only
what each place was holding, so a target that held the current certificate *and*
had failed its last three deployments read as **"All 1 target hold the current
certificate"** — true, reassuring, and precisely the half-told story this
product exists to stop other tools telling. What a place holds and whether the
last attempt to change it worked are two facts, and both belong in the sentence.

**Still to come in this phase:** the deployers that reach real infrastructure
without an agent, then the agent itself — one binary that enrols over mTLS,
inventories certificate stores (filesystem, Java keystore, Windows store,
nginx/Apache/HAProxy, IIS), **generates keys locally so private keys never
traverse the network**, submits CSRs, installs renewals, and runs a reload hook.

Local key generation is what makes this architecturally safer than the
incumbents rather than merely cheaper — and it is the answer to the rule above
about plaintext and loopback, rather than an exception to it.

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
- Post-renewal verification only covers endpoints discovery has already
  observed. A certificate deployed somewhere nothing has scanned is reported as
  unverifiable rather than checked
- A successful renewal does not yet enqueue its own deployments; deployment is
  triggered by hand. That is phase 6 step 3, deliberately after the deployers
  that reach real infrastructure exist — pushing automatically to production
  through one newly written deployer is not a thing to switch on early
- `certificates.deployment_target_id` survives from migration 001 and is no
  longer the answer to where a certificate is deployed. It is unread by anything
  in the deployment path and should be dropped once nothing else references it
- Deployment is not staged. A certificate bound to forty targets goes to all
  forty as fast as the workers drain the queue; there is no canary, no ordering,
  and no pause between the first target and the rest
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
