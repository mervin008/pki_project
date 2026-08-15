# CertPilot

**Open-source PKI & Certificate Lifecycle Management Platform**

CertPilot gives your team a single pane of glass across all your Certificate Authorities — public and private — with automated certificate renewal, CA health monitoring, discovery, policy enforcement, and team collaboration.

## Why CertPilot?

Certificate lifetimes are shrinking fast (47 days by 2029). Manual management is dead. Existing open-source tools are great at individual tasks, but there's no unified platform that:

- Manages **both certificates AND the CAs themselves** (health, expiry, chain monitoring)
- Works with **any CA** via a modular gateway plugin system
- Runs only what you need — each gateway is a **separate container**
- Provides a **real-time dashboard** with alerting

## Architecture

```
┌─────────────────────────────┐
│        Vue 3 Frontend        │
└──────────────┬───────────────┘
               │ HTTP
┌──────────────▼───────────────┐
│      CertPilot Core (Go)      │
│  REST API · PKI Engine         │
│  Renewal · Discovery · Policy  │
│  Plugin Manager (gRPC hub)     │
└──┬───────┬───────┬───────┬────┘
   │ gRPC  │ gRPC  │ gRPC  │ gRPC
┌──▼───┐ ┌─▼────┐ ┌▼─────┐ ┌▼────────┐
│ ACME │ │Vault │ │ GCP  │ │SelfSign │
│  GW  │ │ GW   │ │  GW  │ │  GW     │
└──────┘ └──────┘ └──────┘ └─────────┘
```

**Each gateway is its own binary/container.** You only run the ones you need.

## Features

### PKI & CA Management
- 📊 **CA Dashboard** — Health status, days until CA cert expires, certificates issued count
- 🌳 **Chain Visualization** — Interactive trust chain: Root → Intermediate → Issuing CA
- 🔍 **CRL/OCSP Monitoring** — Track CRL freshness and OCSP responder availability
- 🚨 **CA Alerts** — Configurable alerts for CA certificate expiry (365, 180, 90, 30, 14, 7 days)

### Certificate Lifecycle
- 🔄 **Auto-Renewal** — Certificates renew automatically before expiry
- 🔌 **Multi-CA** — Issue from any CA via gateway plugins (ACME, Vault, GCP CAS, DigiCert, etc.)
- 🔎 **Discovery** — Scan networks and CT logs to find all certificates
- 📋 **Policy Engine** — Enforce key size, algorithms, CA restrictions, naming rules
- 🚀 **Deployment** — Push renewed certs to servers, load balancers, CDNs

### Platform
- 🔐 **OIDC/SSO + RBAC** — Supabase Auth with any OIDC provider + role-based access control
- 📡 **Real-time Dashboard** — Live updates via Supabase Realtime
- 📝 **Audit Trail** — Immutable audit logs for compliance
- 🔔 **Notifications** — Slack, Teams, Email, PagerDuty, webhooks

## Quick Start

### Prerequisites
- Go 1.22+
- Node.js 20+
- A [Supabase](https://supabase.com) project

### Development

```bash
# Clone
git clone https://github.com/your-org/certpilot.git
cd certpilot

# Configure
cp config.example.yaml config.dev.yaml
# Edit config.dev.yaml with your Supabase URL and keys

# Run Core
go run core/cmd/main.go --config=config.dev.yaml

# Run a gateway (separate terminal)
go run gateways/selfsigned/cmd/main.go --port=9091

# Run Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

### Docker (Production)

```bash
cd deploy
docker compose up -d
```

## Supported Gateways

| Gateway | CA | Status |
|:---|:---|:---|
| `gateway-acme` | Let's Encrypt, ZeroSSL, BuyPass, Google Trust Services | ✅ Phase 1 |
| `gateway-selfsigned` | Self-signed (dev/testing) | ✅ Phase 1 |
| `gateway-vault` | HashiCorp Vault PKI | ✅ Phase 1 |
| `gateway-gcp-cas` | Google Cloud Certificate Authority Service | 🔜 Phase 2 |
| `gateway-aws-pca` | AWS Private CA | 🔜 Phase 2 |
| `gateway-digicert` | DigiCert CertCentral | 🔜 Phase 2 |
| `gateway-sectigo` | Sectigo Certificate Manager | 🔜 Phase 2 |

### Writing Your Own Gateway

See [docs/writing-a-gateway.md](docs/writing-a-gateway.md) for a guide on building a custom gateway plugin.

## Tech Stack

| Layer | Technology |
|:---|:---|
| Backend | Go |
| Frontend | Vue 3, TypeScript, Vite, Pinia |
| Database | Supabase (PostgreSQL 17) |
| Auth | Supabase Auth (OIDC/SSO + email/password) |
| Plugin Communication | gRPC (protobuf) |
| Containerization | Docker |

## License

[Apache License 2.0](LICENSE)
