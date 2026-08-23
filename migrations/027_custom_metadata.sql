-- 027_custom_metadata.sql
--
-- Certificates carry three pieces of metadata today — environment, team, tags —
-- and none of them are editable after issuance. Both halves of that are wrong.
--
-- The first half is the smaller problem: a certificate outlives the team that
-- requested it, environments get renamed, and a record that cannot be corrected
-- becomes a record nobody trusts. There has never been a route that updates one.
--
-- The second half is the one that makes an inventory useful or useless. What a
-- PKI team needs to slice by is theirs, not ours: cost centre, change ticket,
-- data classification, PCI in scope, which datacentre, which product line, who
-- signs off on the renewal. A fixed schema guesses at that list and is wrong
-- for every organisation, and the usual escape hatch — free-text tags — cannot
-- be filtered reliably because `pci`, `PCI` and `pci-dss` are three tags.
--
-- So: an admin defines the fields, and every certificate answers them.
--
-- Two decisions worth stating, because both look like overhead until the day
-- they matter:
--
-- `key` and the `value` inside an option are immutable machine names, separate
-- from the labels shown. Renaming "Tier 1" to "Business Critical" then has to
-- rewrite nothing: every certificate holding `tier-1` keeps holding it, and the
-- new label appears everywhere at once. Storing the label as the value means a
-- rename either silently reclassifies history or leaves rows pointing at a
-- string nobody uses any more.
--
-- Fields are archived, never deleted. A certificate issued last year may hold a
-- value for a field the organisation has since stopped using, and that value is
-- part of why the certificate exists. Hard-deleting the definition would leave
-- the value in place with nothing to say what it meant — the row would still
-- read `{"cost_centre": "CC-4471"}` and no screen could label it.
begin;

create table if not exists public.metadata_fields (
  id uuid primary key default gen_random_uuid(),

  -- The machine name. Immutable after creation; it is what certificates store.
  key text not null unique
    check (key ~ '^[a-z][a-z0-9_]{0,62}$'),

  label text not null check (length(trim(label)) > 0),

  field_type text not null
    check (field_type in ('TEXT', 'SELECT', 'MULTI_SELECT', 'BOOLEAN')),

  -- [{"value": "tier-1", "label": "Tier 1"}, ...] for SELECT and MULTI_SELECT.
  options jsonb not null default '[]'::jsonb,

  -- How a single choice is drawn. The same data either way: a list of eight
  -- options is a dropdown and a list of two is radio buttons, and which reads
  -- better is a judgement the person defining the field should get to make
  -- rather than one hardcoded in a component.
  display text not null default 'DROPDOWN'
    check (display in ('DROPDOWN', 'RADIO')),

  help_text text not null default '',

  -- Required is enforced when a certificate is requested, not retroactively.
  -- Adding a required field must not make every existing certificate invalid.
  is_required boolean not null default false,

  sort_order integer not null default 0,

  -- Archived fields stop being offered on new certificates and keep labelling
  -- the values already stored against them.
  is_archived boolean not null default false,

  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_metadata_fields_active
  on public.metadata_fields (is_archived, sort_order, label);

-- The values, on the certificate itself rather than in a join table.
--
-- A join table would be the textbook shape, and it would mean a query per
-- certificate or a join returning one row per field per certificate for a list
-- view that already returns the whole estate. These values are read whenever a
-- certificate is read and written whenever it is written; they belong to it.
alter table public.certificates
  add column if not exists metadata jsonb not null default '{}'::jsonb;

-- GIN so `metadata @> '{"pci_in_scope": true}'` can use an index. Filtering is
-- the entire point of letting people define these; a sequential scan across a
-- large inventory would make the feature useless at exactly the size where it
-- starts to matter.
create index if not exists idx_certificates_metadata
  on public.certificates using gin (metadata);

comment on column public.certificates.metadata is
  'Values for admin-defined metadata_fields, keyed by metadata_fields.key.';

commit;
