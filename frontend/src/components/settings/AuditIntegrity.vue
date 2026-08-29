<script setup lang="ts">
import { computed, ref } from 'vue'
import { FileCheck, ShieldAlert, ShieldCheck, RotateCw, AlertTriangle } from 'lucide-vue-next'
import { useApi } from '@/composables/useApi'

/**
 * Whether the audit record has been altered.
 *
 * Deliberately a button rather than something the page fetches on mount. The
 * answer costs a walk over the whole chain, and — more to the point — "is the
 * record intact" is a question somebody asks, not a number to glance at. A
 * green tick that appeared on its own is one nobody reads.
 */

interface ChainReport {
  intact: boolean
  verified: number
  unchained: number
  first_seq?: number
  last_seq?: number
  broken_at?: number
  reason?: string
  checked_at: string
  truncated: boolean
}

const api = useApi()

const report = ref<ChainReport | null>(null)
const running = ref(false)
const error = ref<string | null>(null)

/**
 * Three outcomes, not two.
 *
 * "Broken" and "could not be checked" must not look alike: the first says
 * somebody altered the record, the second says this core cannot tell — usually
 * a chain written under a key it was not given. Collapsing them would let a
 * missing key read as tampering, or worse, the other way round.
 */
const verdict = computed<'intact' | 'broken' | 'unknown' | null>(() => {
  if (!report.value) return null
  if (report.value.intact) return 'intact'
  if (report.value.broken_at !== undefined) return 'broken'
  return 'unknown'
})

/**
 * The span the walk covered, or nothing when it covered one entry.
 *
 * "1 to 1" is noise, and on a chain that is one entry long it reads as though
 * something were missing.
 */
const range = computed(() => {
  const r = report.value
  if (!r || !r.first_seq) return ''
  const last = r.last_seq ?? r.first_seq
  if (last === r.first_seq) return `entry ${r.first_seq.toLocaleString()}`
  return `${r.first_seq.toLocaleString()} to ${last.toLocaleString()}`
})

async function verify() {
  running.value = true
  error.value = null
  try {
    report.value = await api.get<ChainReport>('/api/v1/audit/verify')
  } catch (err) {
    // A failed request is not a failed verification, and must never render as
    // one. The chain might be perfectly intact and the core simply unreachable.
    report.value = null
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    running.value = false
  }
}

function checkedAt(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}
</script>

<template>
  <section class="panel">
    <header class="panel-head">
      <div class="flex items-center gap-2">
        <FileCheck class="w-4 h-4" style="color: var(--signal)" />
        <h2 class="label-rail">Audit record</h2>
      </div>
      <button class="btn-console" :disabled="running" @click="verify">
        <RotateCw class="w-3 h-3" :class="running ? 'spin' : ''" />
        {{ running ? 'Checking' : 'Verify' }}
      </button>
    </header>

    <p class="field-help panel-intro">
      Every entry carries a tag over its own contents and the entry before it, keyed from
      <code>CERTPILOT_KEK</code>. The key is in this core's environment and not in the database, so
      an altered or deleted row is detectable by anyone holding the key — and not forgeable by
      anyone who only holds the database.
    </p>

    <div v-if="error" class="action-error">
      <AlertTriangle class="w-4 h-4 shrink-0" style="color: var(--sev-critical)" />
      <div>
        <p class="label-rail sev-critical">The check could not run</p>
        <p class="field-help">{{ error }} — this says nothing about whether the record is intact.</p>
      </div>
    </div>

    <div v-if="report" class="verdict" :class="`verdict-${verdict}`">
      <component
        :is="verdict === 'intact' ? ShieldCheck : ShieldAlert"
        class="w-5 h-5 shrink-0"
        :style="{ color: verdict === 'intact' ? 'var(--sev-ok)' : 'var(--sev-critical)' }"
      />
      <div class="flex-1 min-w-0">
        <p
          class="label-rail"
          :class="verdict === 'intact' ? 'sev-ok' : 'sev-critical'"
        >
          <template v-if="verdict === 'intact'">No entry has been altered</template>
          <template v-else-if="verdict === 'broken'">The record has been altered</template>
          <template v-else>The record could not be checked</template>
        </p>

        <p v-if="report.reason" class="reason">{{ report.reason }}</p>

        <p class="field-help">
          <span class="tabular">{{ report.verified.toLocaleString() }}</span>
          {{ report.verified === 1 ? 'entry' : 'entries' }} checked<template v-if="range">,
            {{ range }}</template>. Checked at {{ checkedAt(report.checked_at) }}.
        </p>

        <!-- Both of these qualify the headline, so neither may be hidden behind
             a healthy-looking tick. An operator told the record is intact is
             entitled to know how much of it that claim covers. -->
        <p v-if="report.truncated" class="caveat">
          This was a partial walk and stopped at its limit, so it covers only the entries above.
        </p>
        <p v-if="report.unchained > 0" class="caveat">
          <span class="tabular">{{ report.unchained.toLocaleString() }}</span>
          {{ report.unchained === 1 ? 'entry predates' : 'entries predate' }} tamper-evidence and
          {{ report.unchained === 1 ? 'is' : 'are' }} not covered by this result.
        </p>
      </div>
    </div>

    <p v-else-if="!error" class="field-help">
      Not checked in this session.
    </p>
  </section>
</template>

<style scoped>
.panel {
  background: var(--ink-panel);
  border: 1px solid var(--line);
  padding: 0.875rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.panel-intro { margin-top: -0.25rem; }

.panel-intro code {
  font-family: var(--font-mono);
  color: var(--text-primary);
}

.verdict {
  display: flex;
  align-items: flex-start;
  gap: 0.625rem;
  padding: 0.75rem;
  border: 1px solid var(--line);
}

/* Colour means severity. An intact record is deliberately quiet — it is the
   ordinary case, and there is no healthy wash in the palette on purpose: at
   full saturation green is the loudest thing on a screen where almost
   everything is fine. A broken one is not quiet. */
.verdict-intact {
  border-color: var(--sev-ok);
}

.verdict-broken,
.verdict-unknown {
  border-color: var(--sev-critical);
  background: var(--sev-critical-wash);
}

.reason {
  margin: 0.25rem 0;
  font-family: var(--font-mono);
  font-size: var(--fs-small);
  color: var(--text-primary);
}

.caveat {
  margin-top: 0.25rem;
  font-size: var(--fs-micro);
  color: var(--text-muted);
}

.action-error {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.5rem 0.625rem;
  border: 1px solid var(--sev-critical);
  background: var(--sev-critical-wash);
}

.tabular { font-variant-numeric: tabular-nums; }

.spin { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
