# Getting Started with CertPilot

CertPilot is an open-source PKI and Certificate Lifecycle Management (CLM) platform built for high reliability, automated renewal, and multi-CA orchestration.

## Architecture Highlights

1. **Gateway Plugin Model**: Every CA provider (ACME, HashiCorp Vault, GCP CAS, Self-Signed) runs as an isolated binary or Docker container communicating via gRPC.
2. **Supabase Database & Auth**: Powered by PostgreSQL 17 with database-level Row Level Security (RLS), OIDC/SSO authentication, and Realtime live WebSocket subscriptions.
3. **Local-First & Containerized**: Run locally with `go run` and `npm run dev`, or deploy everything with Docker Compose.

---

## Local Development Setup

### 1. Prerequisites
- **Go**: 1.22+
- **Node.js**: 20+
- **Buf** (optional, for editing protobuf schemas)

### 2. Configure Environment
Copy `config.example.yaml` to `config.dev.yaml`:
```bash
cp config.example.yaml config.dev.yaml
```

Set your Supabase PostgreSQL connection string:
```bash
export CERTPILOT_DB_URL="postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres"
```

### 3. Run the Components

**Terminal 1: Start Gateway (Self-Signed)**
```bash
make run-gateway-selfsigned
```

**Terminal 2: Start Gateway (ACME - Let's Encrypt)**
```bash
make run-gateway-acme
```

**Terminal 3: Start CertPilot Core Control Plane**
```bash
make run-core
```

**Terminal 4: Start Frontend SPA**
```bash
make run-frontend
```

Open [http://localhost:3000](http://localhost:3000) in your browser!

---

## Running with Docker Compose

```bash
cd deploy
export CERTPILOT_DB_URL="postgresql://..."
docker compose up -d
```
