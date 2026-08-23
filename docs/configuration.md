# Configuration reference

Every setting for every process, and what happens when it is wrong.

- [Core](#core) — YAML file, flags, environment
- [Gateways](#gateways) — flags
- [Agent](#agent) — subcommands and flags
- [Production mode](#production-mode) — what it refuses

---

## Core

The core reads one YAML file, some flags, and three environment variables.
Start from [`config.example.yaml`](../config.example.yaml).

Values of the form `${VAR}` are expanded from the environment when the file is
loaded, so a committed configuration never has to contain a secret.

### Flags

| Flag | Default | |
|:---|:---|:---|
| `--config` | `config.dev.yaml` | Path to the YAML file. Missing file → development defaults with a warning |
| `--db` | — | PostgreSQL connection string. Overrides `CERTPILOT_DB_URL` |
| `--migrate` | `false` | Apply migrations and exit |
| `--migrations` | `migrations` | Directory to read migrations from |
| `--generate-kek` | `false` | Print a new base64 KEK and exit |
| `--generate-dev-certs` | — | Write development mTLS material to the given directory and exit |

Migrations are a separate invocation rather than something the server does at
startup, so a schema change is something an operator runs rather than a side
effect of a deploy restarting a replica.

### Environment

| Variable | Required | |
|:---|:---|:---|
| `CERTPILOT_KEK` | **yes, with a database** | Base64 32-byte key encrypting private keys and CA credentials at rest |
| `CERTPILOT_KEK_RETIRED` | no | Comma-separated previous KEKs, still able to decrypt. See [KEK rotation](operations.md#rotating-the-kek) |
| `CERTPILOT_DB_URL` | no | Connection string. `DATABASE_URL` is a fallback |

With no connection string the core uses the in-memory store, seeded with sample
data, discarded on restart.

> **`CERTPILOT_KEK` is not recoverable.** Every stored private key and every CA
> credential is encrypted with it. Lose it and they are gone — not
> inconvenient, gone. Put it in a secret manager before the first certificate is
> issued.

### `server`

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  mode: "development"        # development | production
  allowed_origins:
    - "http://localhost:5173"
```

| Key | Default | |
|:---|:---|:---|
| `host` | `0.0.0.0` | Bind address. The shipped example sets `127.0.0.1`; the code default if the key is absent is `0.0.0.0` |
| `port` | `8080` | HTTP port |
| `mode` | `development` | See [production mode](#production-mode) |
| `allowed_origins` | — | Browser origins permitted to call the API. Must name the frontend explicitly — a wildcard is not accepted alongside credentials |

### `auth`

```yaml
auth:
  jwks_url: "${CERTPILOT_JWKS_URL}"
  issuer: "${CERTPILOT_JWT_ISSUER}"
  audience: "authenticated"
  role_claim: "certpilot_role"
  allow_anonymous: false
```

| Key | Default | |
|:---|:---|:---|
| `jwks_url` | — | The identity provider's JSON Web Key Set endpoint. **Preferred** |
| `issuer` | — | Validated when set |
| `audience` | — | Validated when set |
| `jwt_secret` | — | Legacy HS256 shared secret. See below |
| `role_claim` | `certpilot_role` | Claim inside `app_metadata` carrying the role |
| `allow_anonymous` | `false` | Treat every request as admin |

Two verification paths exist and they are not equivalent. With `jwks_url` the
core verifies asymmetric signatures against published public keys and holds
nothing capable of minting a token. With `jwt_secret` it holds a key that can
forge an admin token. Use `jwks_url` wherever the provider supports it; the
shared-secret path is kept for Supabase projects that have not migrated to
asymmetric signing keys.

`allow_anonymous` is refused unless `mode` is `development` **and** the bind
address is loopback. It exists so a first evaluation does not require standing
up an identity provider.

Roles are read only from `app_metadata`. `user_metadata` is user-writable in
Supabase, and a role read from it is a privilege escalation with extra steps.

### `plugins`

```yaml
plugins:
  discovery_mode: "static"
  tls:
    cert_file: ".certpilot/pki/core.pem"
    key_file: ".certpilot/pki/core-key.pem"
    ca_file: ".certpilot/pki/ca.pem"
    insecure: false
  gateways:
    - name: "letsencrypt-staging"
      addr: "localhost:9092"
      type: "acme"
      server_name: "localhost"
```

| Key | Default | |
|:---|:---|:---|
| `discovery_mode` | `static` | Only `static` is implemented — gateways are the list below |
| `tls.cert_file` | — | The core's client certificate for the gateway channel |
| `tls.key_file` | — | Its key |
| `tls.ca_file` | — | CA bundle the gateway's certificate is verified against |
| `tls.insecure` | `false` | Disable TLS on the gateway channel. Refused in production mode |
| `gateways[].name` | — | Registration name. A CA account is matched to a gateway by this first, then by `type` |
| `gateways[].addr` | — | `host:port` |
| `gateways[].type` | — | `acme`, `vault`, `selfsigned` |
| `gateways[].server_name` | host part of `addr` | Name expected in the gateway's certificate. Set it when dialing by IP or through a service alias |

`make dev-certs` writes usable development material into `.certpilot/pki/`.

### `pki`

```yaml
pki:
  ca_health_check_interval: 360   # minutes
  crl_ocsp_check_interval: 60     # minutes
```

| Key | Default | |
|:---|:---|:---|
| `ca_health_check_interval` | 360 (6 h) | How often every CA is re-parsed, CRL and OCSP checked, expiry thresholds evaluated |
| `crl_ocsp_check_interval` | 60 | CRL freshness and OCSP responsiveness cadence |

The issuer importer runs on a fixed 12-hour interval and is not configurable: a
mount's issuers change when somebody rotates a CA, which happens a few times a
decade.

### `renewal`

```yaml
renewal:
  scan_interval: 60               # minutes
  default_lead_days: 30
  retry_backoff: [60, 240, 720, 1440]   # minutes
```

| Key | Default | |
|:---|:---|:---|
| `scan_interval` | 60 | How often to look for certificates inside their lead window |
| `default_lead_days` | 30 | Days before expiry to renew, when a certificate does not set its own |
| `retry_backoff` | `[60, 240, 720, 1440]` | Minutes between renewal attempts, per attempt |

On lead days: the CA/Browser Forum schedule takes maximum validity to 200 days
(March 2026), 100 days (March 2027) and 47 days (March 2029). A fixed 30-day
lead stops making sense well before the end of that. Where a CA publishes RFC
9773 renewal information, the ACME gateway reports the window the CA suggests,
which is both better timed and what lets a CA drain a mass-revocation event
gradually instead of every client renewing at once.

### `logging`

```yaml
logging:
  level: "info"     # debug | info | warn | error
  format: "text"    # text | json
```

### `supabase`

```yaml
supabase:
  url: "${SUPABASE_URL}"
  anon_key: "${SUPABASE_ANON_KEY}"
```

Supabase is one supported deployment target, not a requirement. The core talks
to any PostgreSQL over `CERTPILOT_DB_URL`. These keys are used by the frontend
for authentication, not by the core for storage.

Prefer Supabase's **session pooler** (port 5432 on the pooler host) over the
transaction pooler (6543): pgx caches prepared statements per connection, and
transaction-mode pooling hands the next query to a backend that has never seen
them. See [database.md](database.md).

---

## Gateways

All three gateways share the transport flags:

| Flag | Default | |
|:---|:---|:---|
| `--port` | per gateway | gRPC port |
| `--tls-cert` | — | This gateway's certificate |
| `--tls-key` | — | Its key |
| `--tls-ca` | — | CA bundle the core's certificate is verified against |
| `--insecure` | `false` | Serve without TLS. Development only, and refused by the core in production mode |
| `--grpc-reflection` | `false` | Enable reflection, for `grpcurl` |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |

### ACME — port 9092

| Flag | Default | |
|:---|:---|:---|
| `--directory` | `letsencrypt-staging` | Default ACME directory, or an alias: `letsencrypt`, `letsencrypt-staging`, `zerossl`, `buypass`, `google` |
| `--state-dir` | — | Where ACME account keys are persisted. **Strongly recommended** — without it, every restart registers a new ACME account |
| `--http01-addr` | `:80` | Bind address for the http-01 challenge listener |

Per-account settings — directory URL, contact email, EAB credentials, challenge
type, DNS provider — live in the CA account's `config`, not here. See
[api-reference.md](api-reference.md).

### Vault — port 9093

| Flag | Default | |
|:---|:---|:---|
| `--address` | `$VAULT_ADDR` | Default Vault address for accounts that do not name one, and the only address `HealthCheck` can probe |
| `--namespace` | `$VAULT_NAMESPACE` | Default Vault Enterprise namespace |

**No Vault token is read from the environment.** A gateway that picked up
`VAULT_TOKEN` would issue under an ambient credential no CA account names, and
nothing in CertPilot would record which identity signed. Every account carries
its own. See [gateways/vault.md](gateways/vault.md).

### Self-signed — port 9091

No gateway-specific flags. Development and testing only.

---

## Agent

```
certpilot-agent enrol   --server URL --token TOKEN [--name] [--interval] [--path]
certpilot-agent run     [--state-dir] [--installs] [--once]
certpilot-agent status  [--state-dir]
certpilot-agent scan    [--path]... [--json]
certpilot-agent request --name HOST [--key-type] [--key-size]
certpilot-agent install [--installs] [--force] [--offline]
```

| Flag | Default | |
|:---|:---|:---|
| `--server` | — | Core base URL, e.g. `https://certpilot.internal:8080` |
| `--token` | — | An enrolment token, issued by an operator and single-use |
| `--name` | hostname | What to call this host in CertPilot |
| `--state-dir` | platform default | Where the agent's identity and certificates live |
| `--interval` | `5m` | How often this agent reports |
| `--path` | platform defaults | A directory to scan for certificates. Repeatable |
| `--installs` | `/etc/certpilot/installs.json` | Where install destinations are declared |
| `--once` | `false` | One cycle — heartbeat, renew, install, inventory — then exit |
| `--json` | `false` | Print a scan report exactly as it would be sent |
| `--force` | `false` | Rewrite and reload even when the files already match |
| `--offline` | `false` | Do the local work and report nothing to the core |
| `--key-type` | `ECDSA` | `ECDSA`, `RSA`, `Ed25519` |
| `--key-size` | 256 / 2048 | Defaults by key type |

`CERTPILOT_AGENT_STATE` overrides the state directory.

`install --offline` is deliberate: putting a certificate this machine already
holds where its own server reads it needs permission from nobody, so it works
with a revoked credential or an unreachable core. See [agent.md](agent.md).

---

## Production mode

Setting `server.mode: production` refuses three things that are convenient
locally and dangerous deployed:

| Refused | Why |
|:---|:---|
| `auth.allow_anonymous: true` | Every request would be admin |
| Neither `auth.jwks_url` nor `auth.jwt_secret` | Nothing would verify anything |
| `plugins.tls.insecure: true` | The gateway channel carries CSRs, private keys and CA credentials |
| `"*"` in `server.allowed_origins` | A wildcard with credentials is not a CORS configuration, it is an open door |
| No database connection string | An in-memory store would come up healthy and lose every certificate it issued |

The core **refuses to start**, rather than warning. A warning in a log nobody
reads is the same as no check at all. The first four are checked at config
load ([`pkg/config/config.go`](../pkg/config/config.go) `Validate`); the last
when the store is built.

One check applies in every mode: `auth.allow_anonymous` requires
`server.host` to be a loopback address. Anonymous access on an interface
anything can reach is not a development convenience.

Production mode also requires `CERTPILOT_KEK` whenever a database is
configured. See [operations.md](operations.md) and [security.md](security.md).

### What is *not* refused

`"*"` in `allowed_origins` outside production mode does not error — but it does
not work either. The CORS middleware matches origins exactly, so a wildcard
matches nothing and every browser request is simply refused by the browser.
That combination — wildcard origin plus credentials — is rejected by the Fetch
specification in any case; the previous implementation set it and looked
permissive while working nowhere.
