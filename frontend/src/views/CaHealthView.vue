<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  AlertTriangle, CircleCheck, CircleHelp, CircleX, Link2Off,
  RotateCw, Search, ShieldCheck,
} from 'lucide-vue-next'
import { useCasStore } from '@/stores/cas'
import { useEventStream } from '@/composables/useEventStream'
import DataState from '@/components/common/DataState.vue'
import {
  caSeverity, compareSeverity, severityBadge, severityBorder, severityText,
  statusLabel, type Severity,
} from '@/lib/severity'
import { describeChainPosition, describeLineage, resolveChains } from '@/lib/chain'
import { formatDate, formatDateTime, formatTime } from '@/lib/format'

/**
 * CA health — the page a central PKI team leaves open.
 *
 * Deliberately not the same page as the CA list under /pki. That one is for
 * managing authorities: importing them, reading fingerprints, expanding detail.
 * This one answers a single question from across a room — *is anything about to
 * expire* — so it is one line per CA, worst first, with the remaining-days count
 * as the largest thing on the row.
 *
 * Two columns the plan calls for are absent because the data behind them does
 * not exist yet: **owner** (`owner_team` / `owner_email`) and **acknowledgement**
 * both arrive with the schema change in step 8. Rendering a column of dashes, or
 * worse borrowing `last_alert_threshold` and labelling it "acknowledged", would
 * misreport the one thing this view is for. `last_alert_threshold` is de-dupe
 * suppression — it records that CertPilot *sent* something, not that a human
 * *saw* it — so it is shown, labelled as exactly that.
 */

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
    tone: attentionCount.value > 0 ? 'text-warning' : '',
  },
  { key: 'critical' as Filter, label: 'Critical', count: counts.value.critical, tone: 'text-error' },
  { key: 'warning' as Filter, label: 'Warning', count: counts.value.warning, tone: 'text-warning' },
  { key: 'unknown' as Filter, label: 'Unassessed', count: counts.value.unknown, tone: '' },
  { key: 'ok' as Filter, label: 'Healthy', count: counts.value.ok, tone: 'text-success' },
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

const worst = computed<Severity>(() => {
  let peak: Severity = 'ok'
  for (const ca of cas.authorities) {
    if (compareSeverity(caSeverity(ca.status), peak) < 0) peak = caSeverity(ca.status)
  }
  return peak
})
</script>

<template>
  <div class="space-y-5">
    <!-- Header -->
    <div class="flex items-end justify-between gap-4 flex-wrap">
      <div>
        <h1 class="text-lg font-bold tracking-tight">Certificate authority health</h1>
        <p class="text-xs text-base-content/60 mt-0.5">
          Every CA under management, most urgent first. An expiring issuing CA invalidates
          everything it has ever signed.
        </p>
      </div>
      <div class="flex items-center gap-2">
        <span class="text-[11px] text-base-content/50 tabular-nums">
          Updated {{ formatTime(lastUpdatedAt) }}
        </span>
        <button class="btn btn-ghost btn-sm gap-1.5" :disabled="cas.loading" @click="cas.refresh()">
          <RotateCw class="w-3.5 h-3.5" :class="cas.loading && 'animate-spin'" />
          Refresh
        </button>
      </div>
    </div>

    <DataState :loading="cas.loading" :error="cas.error" :loaded="cas.loaded" @retry="cas.refresh()">
      <!-- Filters, which double as the severity tally -->
      <div class="flex items-center gap-2 flex-wrap">
        <button
          v-for="chip in chips"
          :key="chip.key"
          type="button"
          class="btn btn-sm gap-2 font-medium"
          :class="filter === chip.key ? 'btn-neutral' : 'btn-ghost border border-base-300'"
          @click="filter = chip.key"
        >
          <span>{{ chip.label }}</span>
          <span
            class="tabular-nums text-[11px] opacity-80"
            :class="filter === chip.key ? '' : chip.tone"
          >
            {{ chip.count }}
          </span>
        </button>

        <label class="input input-bordered input-sm flex items-center gap-2 ml-auto max-w-56">
          <Search class="w-3.5 h-3.5 opacity-50" />
          <input v-model="query" type="search" placeholder="Filter by name" class="grow text-xs" />
        </label>
      </div>

      <!-- The list -->
      <div v-if="visible.length" class="space-y-2">
        <article
          v-for="ca in visible"
          :key="ca.id"
          class="bg-base-100 border border-base-300 border-l-4 rounded-xl"
          :class="severityBorder(caSeverity(ca.status))"
        >
          <div class="flex items-center gap-4 p-3 pl-4">
            <!-- Days remaining: the largest thing on the row, on purpose.
                 Tabular numerals so the column does not jitter as values change
                 under a live feed. -->
            <div class="w-20 shrink-0 text-center">
              <div
                class="text-3xl font-bold leading-none tabular-nums"
                :class="severityText(caSeverity(ca.status))"
              >
                {{ remainingNumeral(ca.days_remaining) }}
              </div>
              <div class="text-[10px] uppercase tracking-wide opacity-60 mt-1">
                {{ remainingLabel(ca.days_remaining) }}
              </div>
            </div>

            <!-- Identity and position in the hierarchy -->
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2 min-w-0">
                <component
                  :is="severityIcon(caSeverity(ca.status))"
                  class="w-4 h-4 shrink-0"
                  :class="severityText(caSeverity(ca.status))"
                />
                <span class="font-bold text-sm truncate">{{ ca.name }}</span>
                <span class="badge badge-xs" :class="severityBadge(caSeverity(ca.status))">
                  {{ statusLabel(ca.status) }}
                </span>
              </div>
              <div class="text-[11px] text-base-content/60 mt-1 flex items-center gap-1.5 flex-wrap">
                <span>{{ statusLabel(ca.ca_type) }}</span>
                <span class="opacity-40">·</span>
                <span :title="describeLineage(chains.get(ca.id), ca.name)">
                  {{ describeChainPosition(chains.get(ca.id)) }}
                </span>
                <span
                  v-if="chains.get(ca.id)?.detached"
                  class="inline-flex items-center gap-1 text-warning"
                  :title="chains.get(ca.id)?.detachedReason"
                >
                  <Link2Off class="w-3 h-3" />
                  detached
                </span>
                <span class="opacity-40">·</span>
                <span class="font-mono">expires {{ formatDate(ca.not_after) }}</span>
              </div>
            </div>

            <!-- Operational facts, right-aligned so they form columns -->
            <div class="hidden md:flex items-center gap-6 shrink-0 text-[11px]">
              <div class="w-20 text-right">
                <div class="opacity-60">Certificates</div>
                <div class="font-bold tabular-nums text-sm">
                  {{ ca.certificates_issued_count }}
                </div>
              </div>

              <div class="w-24">
                <div class="opacity-60">Revocation</div>
                <div v-if="ca.crl_distribution_url" class="flex items-center gap-1 font-medium">
                  <CircleCheck v-if="ca.is_crl_fresh" class="w-3.5 h-3.5 text-success" />
                  <CircleX v-else class="w-3.5 h-3.5 text-error" />
                  <span :class="ca.is_crl_fresh ? '' : 'text-error'">
                    CRL {{ ca.is_crl_fresh ? 'fresh' : 'stale' }}
                  </span>
                </div>
                <!-- Distinct from "stale": a CA that publishes no CRL cannot have
                     a stale one, and conflating the two invents a problem. -->
                <div v-else class="opacity-50">No CRL published</div>
              </div>

              <div class="w-32">
                <div class="opacity-60">Last alert</div>
                <div
                  v-if="ca.last_alert_sent_at"
                  class="font-medium"
                  :title="`CertPilot sent an alert at the ${ca.last_alert_threshold}-day threshold on ${formatDateTime(ca.last_alert_sent_at)}. This records what was sent, not whether anyone acknowledged it.`"
                >
                  {{ ca.last_alert_threshold }}-day threshold
                </div>
                <div v-else class="opacity-50">None sent</div>
              </div>
            </div>
          </div>
        </article>

        <p v-if="filtered" class="text-[11px] text-base-content/50 pt-1">
          Showing {{ visible.length }} of {{ cas.authorities.length }} certificate authorities.
          <button class="link" @click="filter = 'all'; query = ''">Show all</button>
        </p>
      </div>

      <!-- Nothing matched the filter — distinct from having no CAs at all -->
      <div
        v-else-if="cas.authorities.length"
        class="card bg-base-100 border border-base-300"
      >
        <div class="card-body items-center text-center py-10">
          <Search class="w-8 h-8 opacity-30" />
          <h3 class="font-bold text-sm">No CA matches this filter</h3>
          <p class="text-xs opacity-60">
            {{ cas.authorities.length }} authorities are under management.
          </p>
          <button class="btn btn-sm btn-ghost mt-1" @click="filter = 'all'; query = ''">
            Clear the filter
          </button>
        </div>
      </div>

      <div v-else class="card bg-base-100 border border-base-300">
        <div class="card-body items-center text-center py-12">
          <ShieldCheck class="w-10 h-10 opacity-30" />
          <h3 class="font-bold text-sm">No certificate authorities are being monitored</h3>
          <p class="text-xs opacity-60 max-w-sm">
            This page is empty because nothing has been imported — not because everything is
            healthy. Import a CA to begin monitoring its expiry.
          </p>
          <router-link to="/pki" class="btn btn-primary btn-sm mt-2">Import a CA</router-link>
        </div>
      </div>

      <!-- A quiet, factual footer rather than a reassuring one -->
      <p v-if="cas.authorities.length" class="text-[11px] text-base-content/50">
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
