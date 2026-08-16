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

## Dashboard

```
GET /api/v1/dashboard/stats      Summary counts for certificates and CAs
GET /api/v1/dashboard/expiring   Certificates inside the renewal lead window
GET /api/v1/dashboard/activity   Recent audit events
```

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

> The CRL freshness check is real. The OCSP check currently issues a plain GET
> rather than an RFC 6960 request and reports a responder as healthy when it
> should not — see the README's known gaps.

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
POST /api/v1/discovery/scan    TLS handshake against {host, port}  (operator)
POST /api/v1/discovery/import  Import a discovered certificate     (operator)
```

> Single endpoint only. CIDR ranges, CT log monitoring, and cloud inventory are
> not implemented, and results are not yet persisted to `discovery_scans`.

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

## Response headers

Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and
`Cache-Control: no-store`.

CORS reflects the request origin only when it appears in
`server.allowed_origins`. A wildcard is never sent — it is invalid alongside
credentials and browsers reject the combination.
