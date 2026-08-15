# CertPilot REST API Reference

All API endpoints are mounted under `/api/v1` and accept/return JSON.

## Authentication
Pass a Supabase JWT bearer token in the `Authorization` header:
```
Authorization: Bearer <SUPABASE_JWT_TOKEN>
```
In development mode (`mode: development`), anonymous requests are granted the `admin` role by default.

---

## Endpoints

### Dashboard
- `GET /api/v1/dashboard/stats` — Summary counts (total, expiring, healthy certs & CAs)
- `GET /api/v1/dashboard/expiring` — Certificates expiring within the renewal lead window
- `GET /api/v1/dashboard/activity` — Recent audit log events

### Certificates
- `GET /api/v1/certificates` — List managed certificates (supports `?status=`, `?environment=`, `?common_name=`)
- `POST /api/v1/certificates` — Request and issue a new certificate via gateway plugin
- `GET /api/v1/certificates/:id` — Retrieve certificate details and PEM
- `POST /api/v1/certificates/:id/renew` — Trigger manual renewal
- `DELETE /api/v1/certificates/:id` — Delete certificate record

### PKI & CA Management
- `GET /api/v1/pki/authorities` — List all monitored CA authorities
- `POST /api/v1/pki/authorities` — Register a Root or Intermediate CA
- `GET /api/v1/pki/authorities/:id` — Get CA authority details
- `GET /api/v1/pki/authorities/:id/chain` — Get full trust chain up to root
- `GET /api/v1/pki/tree` — Get hierarchy tree for UI visualization
- `POST /api/v1/pki/authorities/:id/check` — Trigger on-demand CA health & CRL/OCSP check
- `DELETE /api/v1/pki/authorities/:id` — Remove CA authority

### CA Accounts & Gateways
- `GET /api/v1/ca-accounts` — List configured CA accounts
- `POST /api/v1/ca-accounts` — Add/configure CA account connection
- `POST /api/v1/ca-accounts/:id/health` — Probe gateway gRPC health
- `GET /api/v1/gateways` — List active connected gRPC gateway plugins

### Discovery
- `POST /api/v1/discovery/scan` — Perform TLS handshake scan on `{host, port}`

### Policies
- `GET /api/v1/policies` — List compliance policy rules
- `POST /api/v1/policies` — Create policy rule
- `PUT /api/v1/policies/:id` — Update policy rule
- `DELETE /api/v1/policies/:id` — Remove policy rule
