<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  AlertTriangle, CircleCheck, CircleHelp, CircleX, Link2Off,
  RotateCw, Search, ShieldCheck, UserRound,
} from 'lucide-vue-next'
import { useApi } from '@/composables/useApi'
import { useCasStore } from '@/stores/cas'
import { useEventStream } from '@/composables/useEventStream'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import SevChip from '@/components/ui/SevChip.vue'
import {
  caSeverity, compareSeverity, sevBg, sevClass, statusLabel, type Severity,
} from '@/lib/severity'
import { describeChainPosition, describeLineage, resolveChains } from '@/lib/chain'
import { formatDate, formatDateTime, formatRelative, formatTime } from '@/lib/format'
import type { CaAuthority } from '@/lib/types'

/**
 * CA health — the page a central PKI team leaves open.
 *
 * Deliberately not the same page as the CA list under /pki. That one is for
 * managing authorities: importing them, reading fingerprints, expanding detail.
 * This one answers a single question from across a room — *is anything about to
 * expire* — so it is one line per CA, worst first, with the remaining-days count
 * as the largest thing on the row.
 *
 * `last_alert_threshold` and acknowledgement are shown side by side and are
 * deliberately not conflated. The first is de-dupe suppression — it records that
 * CertPilot *sent* something. The second records that a human *saw* it. Labelling
 * the former as the latter would misreport the one thing this view is for.
 *
 * The rule that governs acknowledgement here, and the one most likely to be
 * "improved" away later: **acknowledging never removes a row.** An acknowledged
 * CA stays exactly where it was in the urgency order, marked. Filtering it out
 * would hide the problem, which is how CAs expire in organisations that believed
 * they were monitoring them.
 */

const api = useApi()
const cas = useCasStore()
const stream = useEventStream()

onMounted(() => {
  if (!cas.loaded) void cas.refresh()
})

// ── Chain position ────────────────────────────────────────
// Derived from the authorities already in the store, so it follows the live
// feed without a second fetch. See lib/chain.ts for why not GET /pki/tree.
const chains = computed(() => resolveChains(cas.authorities))

// ── Filtering ─────────────────────────────────────────────

type Filter = 'all' | 'attention' | Severity

const filter = ref<Filter>('all')
const query = ref('')

const counts = computed(() => {
  const tally: Record<Severity, number> = { critical: 0, warning: 0, ok: 0, unknown: 0 }
  for (const ca of cas.authorities) tally[caSeverity(ca.status)] += 1
  return tally
})

const attentionCount = computed(
  () => counts.value.critical + counts.value.warning + counts.value.unknown,
)

const visible = computed(() => {
  const needle = query.value.trim().toLowerCase()

  return cas.byUrgency.filter((ca) => {
    const severity = caSeverity(ca.status)
    if (filter.value === 'attention' && severity === 'ok') return false
    if (filter.value !== 'all' && filter.value !== 'attention' && severity !== filter.value) {
      return false
    }
    if (!needle) return true
    return (
      ca.name.toLowerCase().includes(needle) ||
      ca.subject_dn.toLowerCase().includes(needle) ||
      ca.ca_type.toLowerCase().includes(needle)
    )
  })
})

const filtered = computed(() => visible.value.length !== cas.authorities.length)

/** Filter chips, in the order a PKI team reads them: worst first. */
const chips = computed(() => [
  { key: 'all' as Filter, label: 'All', count: cas.authorities.length, tone: '' },
  {
    key: 'attention' as Filter,
    label: 'Needs attention',
    count: attentionCount.value,
    tone: attentionCount.value > 0 ? 'sev-warning' : '',
  },
  { key: 'critical' as Filter, label: 'Critical', count: counts.value.critical, tone: 'sev-critical' },
  { key: 'warning' as Filter, label: 'Warning', count: counts.value.warning, tone: 'sev-warning' },
  { key: 'unknown' as Filter, label: 'Unassessed', count: counts.value.unknown, tone: '' },
  { key: 'ok' as Filter, label: 'Healthy', count: counts.value.ok, tone: 'sev-ok' },
])

// ── Row rendering ─────────────────────────────────────────

/** The large numeral. Never a negative number — "expired" is the fact. */
function remainingNumeral(days: number): string {
  if (days === null || days === undefined || Number.isNaN(days)) return '—'
  if (days < 0) return '!'
  return String(days)
}

function remainingLabel(days: number): string {
  if (days === null || days === undefined || Number.isNaN(days)) return 'unknown'
  if (days < 0) return `expired ${Math.abs(days)}d ago`
  if (days === 0) return 'expires today'
  return days === 1 ? 'day left' : 'days left'
}

function severityIcon(severity: Severity) {
  switch (severity) {
    case 'critical': return CircleX
    case 'warning': return AlertTriangle
    case 'ok': return CircleCheck
    default: return CircleHelp
  }
}

/**
 * The freshest thing this page can honestly claim.
 *
 * While the stream is live that is the moment the last event landed; once it is
 * not, it falls back to the last completed REST load, because the stream clock
 * would otherwise keep advancing on heartbeats that carry no data.
 */
const lastUpdatedAt = computed(() =>
  stream.status.value === 'live' ? (stream.lastEventAt.value ?? cas.lastUpdatedAt) : cas.lastUpdatedAt,
)

// ── Acknowledging ─────────────────────────────────────────

const acting = ref<string | null>(null)
const actionError = ref<string | null>(null)
/** Which row has its acknowledge form open. */
const acknowledging = ref<string | null>(null)
const ackNote = ref('')
const ackSilenceDays = ref(0)

function openAcknowledge(ca: CaAuthority) {
  acknowledging.value = ca.id
  ackNote.value = ''
  ackSilenceDays.value = 0
  actionError.value = null
}

async function acknowledge(ca: CaAuthority) {
  acting.value = ca.id
  actionError.value = null
  try {
    await api.post(`/api/v1/pki/authorities/${ca.id}/acknowledge`, {
      note: ackNote.value,
      silence_days: Number(ackSilenceDays.value) || 0,
    })
    acknowledging.value = null
    await cas.refresh()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    acting.value = null
  }
}

async function withdraw(ca: CaAuthority) {
  acting.value = ca.id
  actionError.value = null
  try {
    await api.delete(`/api/v1/pki/authorities/${ca.id}/acknowledge`)
    await cas.refresh()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    acting.value = null
  }
}

/** True while an explicit silence is in force. */
function isSilenced(ca: CaAuthority): boolean {
  const until = ca.acknowledgement?.silence_until
  return !!until && new Date(until) > new Date()
}

const worst = computed<Severity>(() => {
  let peak: Severity = 'ok'
  for (const ca of cas.authorities) {
    if (compareSeverity(caSeverity(ca.status), peak) < 0) peak = caSeverity(ca.status)
  }
  return peak
})
</script>


<template>
  <div class="flex flex-col gap-3 min-w-0">
    <!-- Intent, then freshness. Both matter: the sentence says why this page
         exists, and the clock says whether to believe it. -->
    <div class="page-head">
      <div class="min-w-0">
        <h1 class="label-rail">Certificate authority health</h1>
        <p class="page-sub prose-ui">
          Every CA under management, most urgent first. An expiring issuing CA invalidates
          everything it has ever signed.
        </p>
      </div>
      <div class="flex items-center gap-2 shrink-0">
        <span class="label-micro">Updated {{ formatTime(lastUpdatedAt) }}</span>
        <button class="btn-console" :disabled="cas.loading" @click="cas.refresh()">
          <RotateCw class="w-3 h-3" :class="cas.loading && 'animate-spin'" />
          Refresh
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="action-error">
      <CircleX class="w-3.5 h-3.5 shrink-0 sev-critical" />
      <span>{{ actionError }}</span>
    </div>

    <DataState :loading="cas.loading" :error="cas.error" :loaded="cas.loaded" @retry="cas.refresh()">
      <!-- Filters that double as the severity tally, so the counts and the
           controls are the same object rather than two things to reconcile. -->
      <div class="filter-bar">
        <button
          v-for="chip in chips"
          :key="chip.key"
          type="button"
          class="filter-chip"
          :data-active="filter === chip.key || undefined"
          @click="filter = chip.key"
        >
          {{ chip.label }}
          <span class="filter-count" :class="filter === chip.key ? '' : chip.tone">
            {{ chip.count }}
          </span>
        </button>

        <label class="filter-search">
          <Search class="w-3 h-3 shrink-0" style="color: var(--text-muted)" />
          <input v-model="query" type="search" placeholder="Filter by name" />
        </label>
      </div>

      <!-- The list -->
      <div v-if="visible.length" class="flex flex-col gap-px" style="background: var(--line)">
        <article v-for="ca in visible" :key="ca.id" class="ca-row">
          <span class="ca-rail" :class="sevBg(caSeverity(ca.status))" aria-hidden="true" />

          <!-- Days remaining: the largest thing on the row, on purpose. Tabular
               numerals so the column does not jitter under a live feed. -->
          <div class="ca-days">
            <span class="ca-days-num" :class="sevClass(caSeverity(ca.status))">
              {{ remainingNumeral(ca.days_remaining) }}
            </span>
            <span class="label-micro">{{ remainingLabel(ca.days_remaining) }}</span>
          </div>

          <div class="ca-identity">
            <div class="flex items-center gap-2 min-w-0">
              <component
                :is="severityIcon(caSeverity(ca.status))"
                class="w-3.5 h-3.5 shrink-0"
                :class="sevClass(caSeverity(ca.status))"
              />
              <span class="ca-name">{{ ca.name }}</span>
              <SevChip :severity="caSeverity(ca.status)" :label="statusLabel(ca.status)" />
            </div>
            <div class="ca-meta">
              <span>{{ statusLabel(ca.ca_type) }}</span>
              <span class="ca-sep">·</span>
              <span :title="describeLineage(chains.get(ca.id), ca.name)">
                {{ describeChainPosition(chains.get(ca.id)) }}
              </span>
              <template v-if="chains.get(ca.id)?.detached">
                <span class="ca-sep">·</span>
                <span
                  class="inline-flex items-center gap-1 sev-warning"
                  :title="chains.get(ca.id)?.detachedReason"
                >
                  <Link2Off class="w-3 h-3" />detached
                </span>
              </template>
              <span class="ca-sep">·</span>
              <span>expires {{ formatDate(ca.not_after) }}</span>
            </div>
          </div>

          <!-- Operational facts as fixed columns, so they line up down the list
               and can be compared without reading each row as a sentence. -->
          <dl class="ca-facts">
            <div>
              <dt class="label-micro">Issued</dt>
              <dd class="ca-fact-value">{{ ca.certificates_issued_count.toLocaleString() }}</dd>
            </div>

            <div>
              <dt class="label-micro">Revocation</dt>
              <dd v-if="ca.crl_distribution_url" class="ca-fact-value">
                <span :class="ca.is_crl_fresh ? '' : 'sev-warning'">
                  CRL {{ ca.is_crl_fresh ? 'fresh' : 'stale' }}
                </span>
              </dd>
              <!-- Distinct from "stale": a CA that publishes no CRL cannot have
                   a stale one, and conflating the two invents a problem. -->
              <dd v-else class="ca-fact-value sev-unknown">No CRL</dd>
            </div>

            <div>
              <dt class="label-micro">Owner</dt>
              <dd v-if="ca.owner_team || ca.owner_email" class="ca-fact-value truncate">
                <span v-if="ca.owner_team">{{ ca.owner_team }}</span>
                <a v-else :href="`mailto:${ca.owner_email}`" class="ca-link">{{ ca.owner_email }}</a>
              </dd>
              <!-- Distinct from a blank cell: an unowned CA is a real and
                   worrying state, not a rendering gap. -->
              <dd v-else class="ca-fact-value sev-warning">Nobody</dd>
            </div>

            <div>
              <dt class="label-micro">Last alert</dt>
              <dd
                v-if="ca.last_alert_sent_at"
                class="ca-fact-value"
                :title="`CertPilot sent an alert at the ${ca.last_alert_threshold}-day threshold on ${formatDateTime(ca.last_alert_sent_at)}. This records what was sent, not whether anyone acknowledged it.`"
              >
                {{ ca.last_alert_threshold }}d sent
              </dd>
              <dd v-else class="ca-fact-value sev-unknown">None</dd>
            </div>
          </dl>

          <!-- Acknowledgement. Beneath the row rather than replacing anything in
               it: the CA is exactly as urgent as it was, and this says who is on
               it. Acknowledging never removes a row — hiding a problem because
               someone clicked a button is how CAs expire in organisations that
               believed they were monitoring them. -->
          <div v-if="ca.acknowledgement" class="ca-drawer">
            <UserRound class="w-3.5 h-3.5 shrink-0 mt-0.5" style="color: var(--text-muted)" />
            <div class="min-w-0 flex-1">
              <span class="ca-ack-who">
                Acknowledged by {{ ca.acknowledgement.acknowledged_by_email || 'an operator' }}
              </span>
              <span class="ca-ack-when">
                &nbsp;{{ formatRelative(ca.acknowledgement.acknowledged_at) }}
              </span>
              <template v-if="ca.acknowledgement.note"> — {{ ca.acknowledgement.note }}</template>
              <div class="ca-ack-state">
                <template v-if="isSilenced(ca)">
                  Alerts are silenced until
                  {{ formatDateTime(ca.acknowledgement.silence_until)
                  }}<template v-if="ca.acknowledgement.threshold">, for the
                    {{ ca.acknowledgement.threshold }}-day threshold only — a tighter one alerts
                    again</template>.
                </template>
                <template v-else>Alerts are still being delivered.</template>
              </div>
            </div>
            <button class="btn-console" :disabled="acting === ca.id" @click="withdraw(ca)">
              Withdraw
            </button>
          </div>

          <div v-else-if="acknowledging === ca.id" class="ca-drawer flex-col items-stretch gap-2">
            <input
              v-model="ackNote"
              placeholder="What is being done? e.g. replacement issued, cutover Thursday"
              class="input-console w-full"
            />
            <div class="flex items-center gap-2 flex-wrap">
              <label class="label-micro">Silence alerts for</label>
              <select v-model.number="ackSilenceDays" class="input-console">
                <option :value="0">not at all — keep alerting</option>
                <option :value="1">1 day</option>
                <option :value="7">7 days</option>
                <option :value="30">30 days</option>
                <option :value="90">90 days (maximum)</option>
              </select>
              <button
                class="btn-console"
                data-variant="signal"
                :disabled="acting === ca.id"
                @click="acknowledge(ca)"
              >
                Acknowledge
              </button>
              <button class="btn-console" @click="acknowledging = null">Cancel</button>
              <span class="label-micro">
                This never hides the CA — it stays here and on the wall display
              </span>
            </div>
          </div>

          <div v-else-if="caSeverity(ca.status) !== 'ok'" class="ca-drawer">
            <button class="btn-console" @click="openAcknowledge(ca)">Acknowledge</button>
          </div>
        </article>
      </div>

      <p v-if="visible.length && filtered" class="label-micro">
        Showing {{ visible.length }} of {{ cas.authorities.length }} authorities.
        <button class="ca-link" @click="filter = 'all'; query = ''">Show all</button>
      </p>

      <!-- Nothing matched the filter — distinct from having no CAs at all -->
      <PanelBox v-if="!visible.length && cas.authorities.length">
        <div class="empty-state">
          <Search class="w-6 h-6" style="color: var(--text-muted)" />
          <p class="label-rail">No CA matches this filter</p>
          <p class="prose-ui">{{ cas.authorities.length }} authorities are under management.</p>
          <button class="btn-console" @click="filter = 'all'; query = ''">Clear the filter</button>
        </div>
      </PanelBox>

      <PanelBox v-else-if="!cas.authorities.length">
        <div class="empty-state">
          <ShieldCheck class="w-7 h-7" style="color: var(--text-muted)" />
          <p class="label-rail">No certificate authorities are being monitored</p>
          <!-- The distinction this paragraph draws is the whole reason it is
               here. An empty monitoring screen looks identical to a healthy one. -->
          <p class="prose-ui max-w-md">
            This page is empty because nothing has been imported — not because everything is
            healthy. Import a CA to begin monitoring its expiry.
          </p>
          <router-link to="/pki" class="btn-console" data-variant="signal">Import a CA</router-link>
        </div>
      </PanelBox>

      <!-- A quiet, factual footer rather than a reassuring one. "All healthy"
           is only ever stated with the time it was true. -->
      <p v-if="cas.authorities.length" class="label-micro">
        <template v-if="worst === 'ok'">
          All {{ cas.authorities.length }} authorities were healthy as of
          {{ formatTime(lastUpdatedAt) }}.
        </template>
        <template v-else>
          {{ attentionCount }} of {{ cas.authorities.length }} authorities need attention.
        </template>
      </p>
    </DataState>
  </div>
</template>

<style scoped>
.page-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--line);
}

.page-sub {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 0.25rem;
  max-width: 46rem;
}

.action-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.625rem;
  font-size: 11px;
  background: var(--sev-critical-wash);
  border: 1px solid var(--sev-critical);
  border-left-width: 3px;
  word-break: break-word;
}

.filter-bar {
  display: flex;
  align-items: center;
  gap: 1px;
  flex-wrap: wrap;
  background: var(--line);
  border: 1px solid var(--line);
}

.filter-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.3rem 0.625rem;
  font-size: 9px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-weight: 600;
  color: var(--text-muted);
  background: var(--ink-panel);
  border: 0;
  cursor: pointer;
}

.filter-chip:hover {
  color: var(--text-primary);
  background: var(--ink-hover);
}

.filter-chip[data-active] {
  color: var(--text-primary);
  background: var(--ink-raised);
  box-shadow: inset 0 -2px 0 0 var(--signal);
}

.filter-count {
  font-weight: 700;
  font-size: 10px;
}

.filter-search {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin-left: auto;
  padding: 0 0.5rem;
  background: var(--ink-panel);
  align-self: stretch;
}

.filter-search input {
  background: none;
  border: 0;
  outline: none;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 11px;
  width: 11rem;
}

.filter-search input::placeholder {
  color: var(--text-muted);
}

/* Rows separated by a single hairline rather than gaps between cards. The list
   is one object — an ordering — and gaps would say it is many. */
.ca-row {
  display: grid;
  grid-template-columns: 3px 4.5rem minmax(0, 1fr) auto;
  align-items: center;
  column-gap: 0.75rem;
  background: var(--ink-panel);
  padding: 0.5rem 0.75rem 0.5rem 0;
}

.ca-rail {
  align-self: stretch;
  margin: -0.5rem 0;
}

.ca-days {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 0.125rem;
}

.ca-days-num {
  font-size: 1.75rem;
  line-height: 1;
  font-weight: 500;
  letter-spacing: -0.03em;
  font-variant-numeric: tabular-nums;
}

.ca-identity {
  min-width: 0;
}

.ca-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ca-meta {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  flex-wrap: wrap;
  margin-top: 0.2rem;
  font-size: 10px;
  color: var(--text-muted);
}

.ca-sep {
  opacity: 0.45;
}

.ca-facts {
  display: none;
  gap: 1.25rem;
  flex: none;
}

@media (min-width: 1024px) {
  .ca-facts {
    display: flex;
  }
}

.ca-facts > div {
  min-width: 5rem;
  max-width: 9rem;
}

.ca-fact-value {
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 0.1rem;
}

.ca-link {
  color: var(--signal);
  text-decoration: underline;
  text-underline-offset: 2px;
  background: none;
  border: 0;
  cursor: pointer;
  font: inherit;
}

.ca-drawer {
  grid-column: 2 / -1;
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-top: 0.5rem;
  padding: 0.4rem 0.5rem;
  background: var(--ink-raised);
  border-left: 2px solid var(--line-strong);
  font-size: 11px;
  color: var(--text-secondary);
}

.ca-ack-who {
  font-weight: 600;
  color: var(--text-primary);
}

.ca-ack-when,
.ca-ack-state {
  color: var(--text-muted);
}

.ca-ack-state {
  margin-top: 0.15rem;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 2.5rem 1rem;
  text-align: center;
  font-size: 11px;
  color: var(--text-muted);
}
</style>
