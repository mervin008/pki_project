# CertPilot — Open-Source PKI & Certificate Lifecycle Management Platform

## The Problem

Certificate validity periods are shrinking aggressively (47 days by 2029). The open-source ecosystem lacks a unified, CA-agnostic platform that gives teams full control across public AND private PKI — with CA health monitoring, certificate automation, discovery, and policy enforcement.

---

## Decisions Locked In

| Decision | Choice |
|:---|:---|
| **Backend** | **Go** |
| **Frontend** | **Vue 3 + TypeScript** |
| **Database** | **Supabase** (PostgreSQL 17, project `wlhrdxswnzwpiffvbkez`, `eu-north-1`) |
| **Auth** | **Supabase Auth (OIDC/SSO)** + built-in user management + RBAC |
| **Dev workflow** | **Local first** (`go run` + `npm run dev`), Docker for production packaging |
| **Plugin model** | **Separate processes/containers** communicating via gRPC |
| **License** | **Apache 2.0** |

---

## Architecture — Plugin Gateway Model

> Every CA provider runs as its **own separate binary/container** ("gateway"). The core platform communicates with gateways via **gRPC**. Users compose only the gateways they need.

```
                         ┌─────────────────────────────┐
                         │        Vue 3 Frontend        │
                         │     (npm run dev / Nginx)     │
                         └──────────────┬───────────────┘
                                        │ HTTP
                         ┌──────────────▼───────────────┐
                         │      CertPilot Core (Go)      │
                         │                               │
                         │  REST API ─ PKI Engine         │
                         │  Renewal Engine ─ Discovery    │
                         │  Policy Engine ─ Notifications │
                         │  Plugin Manager (gRPC hub)     │
                         └──┬───────┬───────┬───────┬────┘
                            │ gRPC  │ gRPC  │ gRPC  │ gRPC
                   ┌────────▼──┐ ┌──▼────┐ ┌▼──────┐ ┌▼──────────┐
                   │ Gateway:  │ │Gateway│ │Gateway│ │ Gateway:  │
                   │   ACME    │ │ Vault │ │  GCP  │ │ Self-Sign │
                   │           │ │  PKI  │ │  CAS  │ │  (dev)    │
                   └───────────┘ └───────┘ └───────┘ └───────────┘
                                        │
                         ┌──────────────▼───────────────┐
                         │     Supabase (Cloud)          │
                         │  PostgreSQL 17 ─ Auth ─ RT    │
                         │  wlhrdxswnzwpiffvbkez         │
                         └───────────────────────────────┘
```

### Local Dev Workflow

```bash
# Terminal 1: Core
go run cmd/certpilot-core/main.go --config=config.dev.yaml

# Terminal 2: Self-signed gateway (for testing)
go run cmd/gateway-selfsigned/main.go --port=9091

# Terminal 3: ACME gateway (when ready)
go run cmd/gateway-acme/main.go --port=9092

# Terminal 4: Frontend
cd frontend && npm run dev
```

No Docker required for development. Supabase is cloud-hosted — just configure the connection string.

---

## Supabase Integration

### Why Supabase Fits

| Supabase Feature | CertPilot Use |
|:---|:---|
| **PostgreSQL 17** | All data models — certs, CAs, policies, audit logs |
| **Supabase Auth** | Built-in OIDC/SSO support (Google, GitHub, Azure AD, Keycloak, any OIDC). Plus email/password for local accounts. Handles JWT, sessions, refresh tokens. |
| **Row Level Security** | RBAC enforcement at the database layer — viewers can't see private keys, operators can't change policies |
| **Realtime** | Live dashboard updates — when a cert renews or a CA health check runs, the dashboard updates instantly via WebSocket |
| **Edge Functions** | Optional: lightweight webhook receivers, notification dispatchers |
| **Storage** | Certificate/key backup storage (encrypted) |

### Auth Strategy

```
┌───────────────────────────────────────────────────────┐
│                    Supabase Auth                       │
│                                                       │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Email/Pass  │  │  OIDC/SSO    │  │   SAML 2.0   │ │
│  │  (local)    │  │ (any provider)│  │  (enterprise)│ │
│  └─────────────┘  └──────────────┘  └──────────────┘ │
│           │                │                │         │
│           └────────────────┴────────────────┘         │
│                        │                              │
│              Supabase JWT Token                       │
│         (contains user_id, role claims)               │
└───────────────────────┬───────────────────────────────┘
                        │
              ┌─────────▼──────────┐
              │  CertPilot Core    │
              │  Validates JWT     │
              │  Maps to RBAC role │
              │  (app_metadata)    │
              └────────────────────┘
```

**OIDC providers supported out-of-the-box via Supabase Auth**: Google, GitHub, GitLab, Azure AD, Keycloak, Okta, Auth0, Bitbucket, Discord, and any generic OIDC provider.

**RBAC roles stored in `app_metadata`** (not `user_metadata` — per Supabase security best practices):
- `admin` — Full control
- `operator` — Issue/renew/revoke certs, manage CAs
- `viewer` — Read-only dashboard access
- `auditor` — Read-only + full audit log access

---

## Database Schema (Supabase/PostgreSQL)

### Tables

#### `ca_authorities` — The CA Entities Themselves

```sql
create table ca_authorities (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  ca_type text not null check (ca_type in ('ROOT', 'INTERMEDIATE', 'ISSUING')),
  subject_dn text not null,
  issuer_dn text not null,
  serial_number text,
  not_before timestamptz not null,
  not_after timestamptz not null,
  days_remaining int generated always as (
    greatest(0, extract(day from not_after - now())::int)
  ) stored,
  key_type text not null check (key_type in ('RSA', 'ECDSA', 'Ed25519')),
  key_size int not null,
  fingerprint_sha256 text not null unique,
  certificate_pem text not null,

  -- Chain
  parent_ca_id uuid references ca_authorities(id) on delete set null,

  -- Health monitoring
  crl_distribution_url text,
  ocsp_responder_url text,
  is_crl_fresh boolean default false,
  crl_last_checked timestamptz,
  is_ocsp_responsive boolean default false,
  ocsp_last_checked timestamptz,
  certificates_issued_count bigint default 0,

  -- Alerting
  alert_thresholds jsonb default '[365, 180, 90, 30, 14, 7]'::jsonb,
  last_alert_sent_at timestamptz,
  last_alert_threshold int,

  -- Status
  status text not null default 'UNKNOWN'
    check (status in ('HEALTHY', 'WARNING', 'CRITICAL', 'EXPIRED', 'UNKNOWN')),

  -- Provider link
  ca_account_id uuid references ca_accounts(id) on delete set null,

  tags jsonb default '[]'::jsonb,
  notes text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Index for chain traversal
create index idx_ca_authorities_parent on ca_authorities(parent_ca_id);
-- Index for status monitoring dashboard
create index idx_ca_authorities_status on ca_authorities(status);
-- Index for expiry monitoring
create index idx_ca_authorities_not_after on ca_authorities(not_after);
```

#### `ca_accounts` — Gateway Connection Configs

```sql
create table ca_accounts (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  provider_type text not null
    check (provider_type in ('acme', 'vault', 'selfsigned', 'gcp_cas',
                              'aws_pca', 'digicert', 'sectigo', 'step_ca')),
  gateway_addr text not null,        -- gRPC address: localhost:9091
  config_encrypted text,             -- Encrypted JSON (API keys, URLs, etc.)
  is_default boolean default false,
  status text not null default 'DISCONNECTED'
    check (status in ('CONNECTED', 'DISCONNECTED', 'ERROR')),
  last_health_at timestamptz,
  created_by uuid references auth.users(id),
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
```

#### `certificates` — Managed Certificates

```sql
create table certificates (
  id uuid primary key default gen_random_uuid(),
  fingerprint_sha256 text not null unique,
  common_name text not null,
  sans jsonb default '[]'::jsonb,
  serial_number text,
  issuer_dn text,
  not_before timestamptz,
  not_after timestamptz,
  days_remaining int generated always as (
    greatest(0, extract(day from not_after - now())::int)
  ) stored,
  key_type text check (key_type in ('RSA', 'ECDSA', 'Ed25519')),
  key_size int,
  status text not null default 'PENDING'
    check (status in ('PENDING', 'ISSUED', 'EXPIRING', 'EXPIRED',
                       'REVOKED', 'RENEWAL_FAILED')),

  -- Automation
  auto_renew boolean default true,
  renewal_lead_days int default 30,
  last_renewal_attempt timestamptz,
  renewal_error text,
  renewal_count int default 0,

  -- Relationships
  ca_account_id uuid references ca_accounts(id) on delete set null,
  ca_authority_id uuid references ca_authorities(id) on delete set null,
  deployment_target_id uuid references deployment_targets(id) on delete set null,

  -- Storage (private key encrypted at app level before storing)
  private_key_encrypted text,
  certificate_pem text,
  chain_pem text,

  -- Provenance
  discovered_via text default 'MANUAL'
    check (discovered_via in ('MANUAL', 'SCAN', 'CT_LOG', 'IMPORT', 'REQUESTED')),

  -- Metadata
  environment text check (environment in ('production', 'staging', 'development')),
  team text,
  tags jsonb default '[]'::jsonb,
  created_by uuid references auth.users(id),
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index idx_certificates_status on certificates(status);
create index idx_certificates_not_after on certificates(not_after);
create index idx_certificates_ca_account on certificates(ca_account_id);
create index idx_certificates_common_name on certificates(common_name);
```

#### `deployment_targets` — Where Certs Get Deployed

```sql
create table deployment_targets (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  target_type text not null
    check (target_type in ('filesystem', 'aws_acm', 'kubernetes',
                           'webhook', 'gcp_lb', 'azure_kv')),
  config_encrypted text,
  last_deployment_at timestamptz,
  last_deployment_status text,
  created_by uuid references auth.users(id),
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
```

#### `policies` — Policy Rules

```sql
create table policies (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  is_enabled boolean default true,
  rule_type text not null
    check (rule_type in ('key_size', 'key_type', 'ca_restriction',
                         'max_lifetime', 'naming', 'approval_required')),
  rule_config jsonb not null,    -- e.g., {"min_key_size": 2048, "allowed_cas": [...]}
  domain_pattern text,           -- e.g., "*.prod.example.com"
  severity text default 'WARNING'
    check (severity in ('INFO', 'WARNING', 'BLOCK')),
  created_by uuid references auth.users(id),
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
```

#### `notification_channels` — Alert Destinations

```sql
create table notification_channels (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  channel_type text not null
    check (channel_type in ('email', 'slack', 'teams', 'webhook', 'pagerduty')),
  config_encrypted text,        -- Webhook URLs, SMTP settings, etc.
  is_enabled boolean default true,
  last_sent_at timestamptz,
  created_by uuid references auth.users(id),
  created_at timestamptz default now()
);
```

#### `audit_logs` — Immutable Audit Trail

```sql
create table audit_logs (
  id uuid primary key default gen_random_uuid(),
  action text not null,            -- cert.issued, cert.renewed, ca.health_check, etc.
  entity_type text not null,       -- certificate, ca_authority, ca_account, policy
  entity_id uuid,
  actor_id uuid references auth.users(id),
  actor_email text,
  details jsonb,
  ip_address inet,
  created_at timestamptz default now()
);

-- Append-only: no UPDATE or DELETE via RLS
create index idx_audit_logs_entity on audit_logs(entity_type, entity_id);
create index idx_audit_logs_actor on audit_logs(actor_id);
create index idx_audit_logs_created on audit_logs(created_at desc);
```

#### `discovery_scans` — Network Scan History

```sql
create table discovery_scans (
  id uuid primary key default gen_random_uuid(),
  scan_type text not null check (scan_type in ('network', 'ct_log', 'cloud')),
  targets jsonb not null,          -- CIDR ranges, domains, cloud accounts
  status text not null default 'PENDING'
    check (status in ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
  results_count int default 0,
  started_at timestamptz,
  completed_at timestamptz,
  error text,
  triggered_by uuid references auth.users(id),
  created_at timestamptz default now()
);

create table discovery_results (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references discovery_scans(id) on delete cascade,
  host text not null,
  port int not null,
  common_name text,
  sans jsonb,
  issuer_dn text,
  not_after timestamptz,
  fingerprint_sha256 text,
  certificate_pem text,
  is_imported boolean default false,
  imported_certificate_id uuid references certificates(id),
  created_at timestamptz default now()
);
```

### Row Level Security

```sql
-- Enable RLS on all tables
alter table ca_authorities enable row level security;
alter table ca_accounts enable row level security;
alter table certificates enable row level security;
alter table deployment_targets enable row level security;
alter table policies enable row level security;
alter table notification_channels enable row level security;
alter table audit_logs enable row level security;
alter table discovery_scans enable row level security;
alter table discovery_results enable row level security;

-- Helper: extract role from app_metadata
create or replace function public.get_user_role()
returns text
language sql
security invoker
stable
as $$
  select coalesce(
    auth.jwt() -> 'app_metadata' ->> 'certpilot_role',
    'viewer'
  );
$$;

-- Example: certificates table policies
-- All authenticated users can read
create policy "certificates_select" on certificates
  for select to authenticated
  using (true);

-- Only admin and operator can insert/update
create policy "certificates_insert" on certificates
  for insert to authenticated
  with check (public.get_user_role() in ('admin', 'operator'));

create policy "certificates_update" on certificates
  for update to authenticated
  using (public.get_user_role() in ('admin', 'operator'))
  with check (public.get_user_role() in ('admin', 'operator'));

-- Only admin can delete
create policy "certificates_delete" on certificates
  for delete to authenticated
  using (public.get_user_role() = 'admin');

-- Audit logs: append-only (insert for all, no update/delete)
create policy "audit_logs_select" on audit_logs
  for select to authenticated
  using (public.get_user_role() in ('admin', 'auditor'));

create policy "audit_logs_insert" on audit_logs
  for insert to authenticated
  with check (true);
```

### Supabase Realtime (Live Dashboard)

Enable realtime on key tables for instant dashboard updates:

```sql
alter publication supabase_realtime add table certificates;
alter publication supabase_realtime add table ca_authorities;
alter publication supabase_realtime add table audit_logs;
alter publication supabase_realtime add table discovery_scans;
```

---

## Repository Structure

```
certpilot/
├── README.md
├── LICENSE                              # Apache 2.0
├── Makefile                             # build, test, lint, run
├── go.work                              # Go workspace (monorepo)
├── go.work.sum
├── config.dev.yaml                      # Dev config (Supabase URL, keys)
├── config.example.yaml                  # Template for production
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
│
├── proto/                               # gRPC service definitions
│   ├── buf.yaml
│   ├── buf.gen.yaml
│   ├── provider/v1/provider.proto       # Gateway contract
│   ├── deployer/v1/deployer.proto
│   └── common/v1/types.proto
│
├── pkg/                                 # Shared Go packages (all binaries)
│   ├── crypto/                          # CSR generation, key mgmt
│   ├── x509util/                        # Cert parsing
│   ├── grpckit/                         # gRPC helpers, mTLS
│   ├── config/                          # Config loading
│   └── pb/                              # Generated protobuf Go code
│
├── core/                                # CertPilot Core (main platform)
│   ├── go.mod
│   ├── cmd/main.go
│   ├── server/                          # HTTP server (Gin/Echo)
│   │   ├── server.go
│   │   └── middleware/
│   │       ├── auth.go                  # Supabase JWT validation
│   │       ├── rbac.go
│   │       └── audit.go
│   ├── api/                             # REST handlers
│   │   ├── router.go
│   │   ├── certificates.go
│   │   ├── ca_management.go
│   │   ├── ca_accounts.go
│   │   ├── discovery.go
│   │   ├── policies.go
│   │   ├── dashboard.go
│   │   ├── users.go
│   │   └── notifications.go
│   ├── store/                           # Supabase/PostgreSQL access
│   │   ├── store.go                     # Interface
│   │   ├── supabase.go                  # Supabase client (REST + direct PG)
│   │   ├── certificates.go
│   │   ├── ca_authorities.go
│   │   └── ...
│   ├── engine/
│   │   ├── renewal/
│   │   │   ├── scheduler.go
│   │   │   └── executor.go
│   │   ├── pki/
│   │   │   ├── ca_monitor.go            # CA health & expiry checks
│   │   │   ├── chain_resolver.go        # Trust chain builder
│   │   │   └── crl_ocsp_checker.go
│   │   ├── discovery/
│   │   │   ├── scanner.go
│   │   │   └── ct_monitor.go
│   │   ├── policy/engine.go
│   │   └── notifications/
│   │       ├── dispatcher.go
│   │       ├── email.go
│   │       ├── slack.go
│   │       ├── teams.go
│   │       └── webhook.go
│   └── pluginmgr/                       # Plugin/gateway manager
│       ├── manager.go
│       ├── registry.go
│       └── health.go
│
├── gateways/                            # Plugin binaries (each = own container)
│   ├── acme/                            # ACME Gateway
│   │   ├── go.mod
│   │   ├── cmd/main.go
│   │   ├── provider.go                  # gRPC server
│   │   ├── client.go                    # ACME RFC 8555 client
│   │   ├── challenges/
│   │   │   ├── http01.go
│   │   │   ├── dns01.go
│   │   │   └── tlsalpn01.go
│   │   ├── dns_solvers/
│   │   │   ├── cloudflare.go
│   │   │   ├── route53.go
│   │   │   ├── gcloud.go
│   │   │   └── azure.go
│   │   ├── Dockerfile
│   │   └── README.md
│   ├── vault/                           # Vault PKI Gateway
│   │   ├── go.mod
│   │   ├── cmd/main.go
│   │   ├── provider.go
│   │   ├── Dockerfile
│   │   └── README.md
│   ├── gcp-cas/                         # Google Cloud CAS Gateway
│   │   ├── go.mod
│   │   ├── cmd/main.go
│   │   ├── provider.go
│   │   ├── Dockerfile
│   │   └── README.md
│   └── selfsigned/                      # Self-Signed Gateway (dev/testing)
│       ├── go.mod
│       ├── cmd/main.go
│       ├── provider.go
│       ├── Dockerfile
│       └── README.md
│
├── frontend/                            # Vue 3 SPA
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── App.vue
│   │   ├── main.ts
│   │   ├── router/index.ts
│   │   ├── lib/
│   │   │   └── supabase.ts             # Supabase JS client init
│   │   ├── stores/                      # Pinia
│   │   │   ├── auth.ts                  # Supabase Auth state
│   │   │   ├── certificates.ts
│   │   │   ├── caAuthorities.ts
│   │   │   └── dashboard.ts
│   │   ├── composables/
│   │   │   ├── useSupabase.ts
│   │   │   └── useRealtime.ts           # Live subscriptions
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   ├── dashboard/
│   │   │   ├── pki/
│   │   │   │   ├── CaChainTree.vue
│   │   │   │   ├── CaDetailCard.vue
│   │   │   │   ├── CaHealthGauge.vue
│   │   │   │   └── CrlOcspStatus.vue
│   │   │   ├── certificates/
│   │   │   └── common/
│   │   └── views/
│   │       ├── DashboardView.vue
│   │       ├── PkiOverviewView.vue
│   │       ├── CaDetailView.vue
│   │       ├── CertificatesView.vue
│   │       ├── DiscoveryView.vue
│   │       ├── PoliciesView.vue
│   │       ├── GatewaysView.vue
│   │       └── SettingsView.vue
│   └── Dockerfile
│
├── deploy/                              # Production Docker
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   └── docker/
│       ├── core.Dockerfile
│       └── nginx.conf
│
└── docs/
    ├── getting-started.md
    ├── architecture.md
    ├── writing-a-gateway.md             # How to build a new gateway plugin
    └── api-reference.md
```

---

## Execution Order

| # | Component | Description |
|:--|:---|:---|
| 1 | **Project scaffolding** | Go workspace, modules, Makefile, config |
| 2 | **Supabase schema** | Apply migrations: all tables, RLS, indexes, realtime |
| 3 | **Proto definitions** | gRPC contracts, buf generate |
| 4 | **Shared packages** | `pkg/crypto`, `pkg/x509util`, `pkg/grpckit` |
| 5 | **Self-signed gateway** | Simplest gateway — validates gRPC architecture end-to-end |
| 6 | **Core: plugin manager** | gRPC hub, gateway registration, health checks |
| 7 | **Core: auth middleware** | Supabase JWT validation, RBAC middleware |
| 8 | **Core: store layer** | Supabase/PostgreSQL data access |
| 9 | **Core: REST API** | Certificate + CA management endpoints |
| 10 | **Core: PKI engine** | CA health monitor, chain resolver, CRL/OCSP checker |
| 11 | **Core: renewal engine** | Scheduled renewal with retry logic |
| 12 | **ACME gateway** | Full ACME provider with DNS-01/HTTP-01 |
| 13 | **Core: discovery** | TLS scanner, CT log monitor |
| 14 | **Core: policy engine** | Rule evaluation |
| 15 | **Core: notifications** | Email, Slack, Teams, webhook |
| 16 | **Frontend** | Vue 3 dashboard with Supabase Auth + Realtime |
| 17 | **Docker packaging** | Dockerfiles, compose, production config |
| 18 | **Docs** | Getting started, gateway dev guide, API docs |

---

## Verification Plan

### Automated Tests
```bash
make test            # All Go unit tests
make lint            # golangci-lint + buf lint
cd frontend && npm test && npm run lint
```

### Integration Tests
1. Core connects to Supabase → CRUD certificates and CA authorities
2. Self-signed gateway → register → issue → renew → revoke lifecycle
3. ACME gateway → Let's Encrypt staging → issue cert
4. CA monitor → detect expiring CA → trigger alert
5. Discovery scan → find certs → import
6. RLS → viewer can't modify, operator can, admin can delete

### Manual Verification
1. `go run` core + self-signed gateway → both start, gateway registers
2. Login via Supabase Auth (email/password + OIDC)
3. Dashboard shows CA health cards, cert stats, expiry timeline
4. PKI view shows chain tree visualization
5. Real-time: renew a cert → dashboard updates instantly via Supabase Realtime
