-- 011_cloud_inventory.sql
--
-- The third place certificates hide.
--
-- A network scan finds what is **served** on addresses somebody thought to give
-- it. Certificate Transparency finds what was **issued** by a publicly-trusted
-- CA. Neither finds what is merely **stored**: a certificate sitting in ACM, in
-- a Key Vault, in a GCP load balancer, or in a Kubernetes secret — attached to
-- an address nobody scanned, or attached to nothing at all.
--
-- The finding that justifies this table is not "here is another certificate".
-- It is this:
--
--   **Cloud certificate stores do not renew everything in them, and everybody
--   believes they do.**
--
-- An ACM certificate that was imported is never renewed by AWS, and AWS says so
-- in a field almost nobody reads (`RenewalEligibility: INELIGIBLE`). A GCP
-- `SELF_MANAGED` SSL certificate is uploaded once and forgotten. A Key Vault
-- certificate whose issuer is `Unknown` was imported as a PFX and has no
-- issuance policy to renew it. A Kubernetes `kubernetes.io/tls` secret with no
-- cert-manager owner was created by hand by somebody who has since left.
--
-- All four look identical, on their own console, to the ones that do renew.
--
-- Two tables.
--
-- **`cloud_connections`** — where to look. Credentials are sealed with the
-- keyring before they arrive here, exactly as notification channel configs are;
-- this table never holds a usable secret. Note `last_synced_at` versus
-- `last_success_at`: the same split `ct_monitors` carries, for the same reason.
-- A connection whose credentials expired three weeks ago must not read as an
-- account that simply has no certificates in it.
--
-- And note `scopes`. A sync records, in the provider's own words, what it
-- actually enumerated. A cloud provider has many places a certificate can sit,
-- and a tool that quietly covers one of them while presenting itself as
-- covering the provider is committing this product's original sin in a new
-- place: an empty result that reads as an all-clear.
--
-- **`cloud_certificates`** — what was found. Same verdict as everywhere else in
-- discovery, decided the same way: on the SHA-256 fingerprint, because two
-- certificates for one hostname are two certificates and only one of them is
-- the one that expires.
--

begin;

create table if not exists public.cloud_connections (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  -- aws_acm | azure_key_vault | gcp | kubernetes
  provider text not null
    check (provider in ('aws_acm', 'azure_key_vault', 'gcp', 'kubernetes')),

  -- Sealed with the keyring under its own context string. Read access to this
  -- row is not read access to the cloud account.
  config_encrypted text,

  is_enabled boolean not null default true,
  sync_interval_minutes int not null default 360 check (sync_interval_minutes > 0),

  -- Attempted, versus answered. See the note above.
  last_synced_at  timestamptz,
  last_success_at timestamptz,
  next_sync_at    timestamptz,
  last_error      text,

  -- What the last successful sync actually looked at, in the provider's own
  -- vocabulary. Displayed next to the results so nobody reads a short list as
  -- a small estate when it is really a narrow search.
  scopes jsonb not null default '[]'::jsonb,

  certificates_seen int not null default 0,
  unmanaged_seen    int not null default 0,

  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint cloud_connections_name_unique unique (name)
);

create index if not exists idx_cloud_connections_due
  on public.cloud_connections (next_sync_at)
  where is_enabled;

create table if not exists public.cloud_certificates (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.cloud_connections(id) on delete cascade,

  -- The provider's own identifier: an ARN, a Key Vault certificate id, a GCP
  -- self-link, a namespace/name. Unique per connection, which is what makes a
  -- repeated sync an update rather than a duplicate.
  resource_id text not null,
  name        text,
  -- Region, vault, cluster — wherever the provider says this lives.
  location    text,

  common_name  text,
  subject_dn   text,
  issuer_dn    text,
  serial_number text,
  sans         jsonb not null default '[]'::jsonb,
  not_before   timestamptz,
  not_after    timestamptz,
  key_type     text,
  key_size     int,
  fingerprint_sha256 text,
  certificate_pem    text,

  management_state text not null default 'UNMANAGED'
    check (management_state in ('MANAGED', 'UNMANAGED')),
  matched_certificate_id uuid references public.certificates(id) on delete set null,

  -- What the provider says about renewal, in its own vocabulary — `IMPORTED`,
  -- `SELF_MANAGED`, `AutoRenew`, `cert-manager`. Kept verbatim rather than
  -- reduced to a boolean, because the word is what somebody has to go and look
  -- up in their own console.
  renewal_mode text,
  -- Whether the provider itself will renew this. Null means the provider did
  -- not say, which is not the same as no.
  will_renew boolean,

  -- What is using it. `attached` null means the provider could not be asked —
  -- a Key Vault has no notion of attachment at all — and that is deliberately
  -- distinct from `false`, which means nothing is using it.
  attached    boolean,
  attached_to jsonb not null default '[]'::jsonb,

  findings jsonb not null default '[]'::jsonb,

  -- Adoption, mirroring discovery_results.
  is_imported boolean not null default false,
  imported_certificate_id uuid references public.certificates(id) on delete set null,

  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  -- Set when a sync that succeeded did not find it any more. Not deleted: a
  -- certificate that disappeared from the store is information, and a row that
  -- vanishes takes its own history with it.
  removed_at timestamptz,

  created_at timestamptz not null default now(),

  constraint cloud_certificates_resource_unique unique (connection_id, resource_id)
);

create index if not exists idx_cloud_certificates_connection_state
  on public.cloud_certificates (connection_id, management_state);

create index if not exists idx_cloud_certificates_fingerprint
  on public.cloud_certificates (fingerprint_sha256)
  where fingerprint_sha256 is not null;

create index if not exists idx_cloud_certificates_expiry
  on public.cloud_certificates (not_after)
  where removed_at is null;

commit;
