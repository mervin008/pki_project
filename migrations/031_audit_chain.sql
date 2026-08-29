-- 031: make the audit log tamper-evident.
--
-- The table has been labelled "immutable" since 001 and was nothing of the
-- sort: any row could be edited or deleted, and nothing downstream would ever
-- notice. That mattered less while the audit log recorded background sweeps.
-- It stopped being acceptable once revocation, private-key export, and account
-- changes started writing to it — those are precisely the entries somebody
-- would want gone.
--
-- Two independent mechanisms, because they defend against different people:
--
--   1. A keyed hash chain (the columns below). Each entry carries an
--      HMAC-SHA256 tag over its own contents and the previous entry's tag. The
--      key is derived from CERTPILOT_KEK, which lives in the core's
--      environment and never in the database — so somebody holding a database
--      dump, a compromised replica, or a DBA account can alter a row but
--      cannot produce a tag that agrees with it. That is the difference
--      between this and a plain SHA-256 chain, which anyone with write access
--      could simply recompute.
--
--   2. An append-only trigger. This one is not a security boundary — anybody
--      who can drop a trigger can also drop it — it is protection against
--      accident: a mistyped UPDATE, a stray DELETE, a migration that meant to
--      touch a different table.
--
-- What this still does not defend against, stated plainly so nobody assumes
-- otherwise: an attacker who holds both the database and the KEK can rewrite
-- the whole chain from any point forward, and truncating the newest entries
-- leaves a shorter but internally consistent chain. Detecting either needs an
-- anchor kept outside the system — periodically publishing the head tag
-- somewhere append-only. That is not built here.

begin;

-- `details` becomes text.
--
-- jsonb does not store the bytes it is given: it parses, reorders keys, and
-- discards whitespace, so the string read back is not the string written. That
-- is fatal for a record whose whole purpose is to be verifiable — the tag would
-- be computed over one byte sequence and checked against another, and every
-- entry with more than one key in its details would read as tampered.
--
-- Nothing queries into this column with a JSON operator; it is written as a
-- JSON string by the core and read back as a string. A column that silently
-- rewrites an audit record is a small integrity problem in its own right.
alter table public.audit_logs
  alter column details type text using details::text;

alter table public.audit_logs
  -- Assigned by the core under an advisory lock, not by a sequence: a sequence
  -- hands out numbers before the transaction that will use them commits, so two
  -- concurrent writers could chain from the same predecessor and fork the
  -- chain. Gapless numbering is also what makes a deleted entry visible.
  add column if not exists seq bigint,
  add column if not exists prev_hash bytea,
  add column if not exists entry_hash bytea,
  -- Which KEK produced the tag, in the same short hex form the encryption
  -- envelopes use. Without it, rotating CERTPILOT_KEK would invalidate every
  -- link ever written — which is a strong reason never to rotate, and that is
  -- the wrong incentive to build in.
  add column if not exists chain_key_id text;

-- Rows written before this migration are deliberately left unchained rather
-- than back-filled. A chain computed now over history proves only that the
-- rows looked like this at migration time; presenting that as tamper-evidence
-- for events that predate the mechanism would be a lie the verifier then
-- repeats. `verify_audit_chain` counts them and says so.
create unique index if not exists idx_audit_logs_seq
  on public.audit_logs (seq) where seq is not null;

-- Reading the chain head on every write, and walking it during verification,
-- are the two hot paths.
create index if not exists idx_audit_logs_seq_desc
  on public.audit_logs (seq desc) where seq is not null;

create or replace function public.audit_logs_append_only()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'UPDATE' then
    raise exception
      'audit_logs is append-only: entry % cannot be modified', old.id
      using hint = 'Record a correcting entry instead. There is no legitimate '
                   'update to an audit record.';
  end if;

  -- Retention is the one legitimate reason to delete, so it gets a door rather
  -- than forcing an operator to drop the trigger and forget to put it back.
  -- It is not a security control: this setting is as reachable as the trigger
  -- itself. It is a speed bump that makes deliberate pruning distinguishable
  -- from a mistake.
  if coalesce(current_setting('certpilot.audit_maintenance', true), '') <> 'on' then
    raise exception
      'audit_logs is append-only: entry % cannot be deleted', old.id
      using hint = 'For retention pruning, run: set local certpilot.audit_maintenance = ''on''; '
                   'in the same transaction. Note that deleting entries breaks '
                   'chain verification across the gap.';
  end if;
  return old;
end;
$$;

drop trigger if exists trg_audit_logs_append_only on public.audit_logs;
create trigger trg_audit_logs_append_only
  before update or delete on public.audit_logs
  for each row execute function public.audit_logs_append_only();

commit;
