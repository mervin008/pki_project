<script setup lang="ts">
import { computed, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import { useThemeStore } from '@/stores/theme'
import DoughnutChart from '@/components/charts/DoughnutChart.vue'
import BarChart from '@/components/charts/BarChart.vue'
import DataState from '@/components/common/DataState.vue'
import {
  KeyRound, AlertTriangle, XCircle, Building2, ShieldCheck, RotateCw,
} from 'lucide-vue-next'
import {
  caSeverity, certSeverity, severityBadge, severityText, statusLabel,
  compareSeverity, severityPalette, categoricalPalette,
} from '@/lib/severity'
import { formatDaysShort, formatRelative, formatTime } from '@/lib/format'
import {
  emptyList, parseDetails,
  type AuditLog, type CaAuthority, type CaExpiryAlertDetails,
  type Certificate, type DashboardStats, type ListResponse,
} from '@/lib/types'

const api = useApi()
const theme = useThemeStore()
const { currentTheme } = storeToRefs(theme)

const stats = useAsyncData<DashboardStats>((s) =>
  api.get<DashboardStats>('/api/v1/dashboard/stats', s),
)
const cas = useAsyncData<ListResponse<CaAuthority>>((s) =>
  api.get<ListResponse<CaAuthority>>('/api/v1/pki/authorities', s),
)
const certs = useAsyncData<ListResponse<Certificate>>((s) =>
  api.get<ListResponse<Certificate>>('/api/v1/certificates', s),
)
const activity = useAsyncData<ListResponse<AuditLog>>((s) =>
  api.get<ListResponse<AuditLog>>('/api/v1/dashboard/activity', s),
)

const sources = [stats, cas, certs, activity]
const loading = computed(() => sources.some((s) => s.loading.value))
const loaded = computed(() => sources.every((s) => s.loaded.value))
// Any failing panel degrades the whole dashboard. Showing three fresh numbers
// beside one stale one, with nothing to tell them apart, is how a monitoring
// screen misleads.
const error = computed(() => sources.map((s) => s.error.value).find(Boolean) ?? null)
const lastLoadedAt = computed(() => stats.lastLoadedAt.value)

function refreshAll() {
  sources.forEach((s) => void s.refresh())
}

const caList = computed(() => cas.data.value?.data ?? [])
const certList = computed(() => certs.data.value?.data ?? [])
const activityList = computed(() => activity.data.value?.data ?? [])
const summary = computed<DashboardStats>(
  () =>
    stats.data.value ?? {
      total_certificates: 0, healthy_certs: 0, expiring_soon_certs: 0, expired_certs: 0,
      total_cas: 0, healthy_cas: 0, warning_cas: 0, critical_cas: 0, total_scans: 0,
    },
)

// ── Charts ────────────────────────────────────────────────
// Palettes are resolved from the theme's CSS variables and recomputed when the
// theme changes, so charts follow the light/dark toggle instead of staying on
// the hardcoded palette they were born with.
const sevColors = computed(() => {
  void currentTheme.value
  return severityPalette()
})
const catColors = computed(() => {
  void currentTheme.value
  return categoricalPalette()
})

const statusChart = computed(() => {
  const counts = new Map<string, number>()
  for (const c of certList.value) {
    counts.set(c.status, (counts.get(c.status) ?? 0) + 1)
  }
  const entries = [...counts.entries()].sort((a, b) => b[1] - a[1])
  return {
    labels: entries.map(([status]) => statusLabel(status)),
    data: entries.map(([, count]) => count),
    colors: entries.map(([status]) => {
      const palette = sevColors.value
      switch (certSeverity(status)) {
        case 'ok': return palette[0]
        case 'warning': return palette[1]
        case 'critical': return palette[2]
        default: return palette[3]
      }
    }),
  }
})

// Derived from the certificates actually held, rather than the constant array
// this panel used to display.
const algoChart = computed(() => {
  const counts = new Map<string, number>()
  for (const c of certList.value) {
    const label = c.key_type ? `${c.key_type}${c.key_size ? `-${c.key_size}` : ''}` : 'Unknown'
    counts.set(label, (counts.get(label) ?? 0) + 1)
  }
  const entries = [...counts.entries()].sort((a, b) => b[1] - a[1])
  return {
    labels: entries.map(([label]) => label),
    data: entries.map(([, count]) => count),
  }
})

// Real forecast: certificates bucketed by the month they expire.
const expirationChart = computed(() => {
  const buckets: { label: string; expiring: number; expired: number }[] = []
  const now = new Date()

  for (let i = 0; i < 6; i++) {
    const d = new Date(now.getFullYear(), now.getMonth() + i, 1)
    buckets.push({
      label: d.toLocaleDateString(undefined, { month: 'short' }),
      expiring: 0,
      expired: 0,
    })
  }

  for (const c of certList.value) {
    if (!c.not_after) continue
    const expiry = new Date(c.not_after)
    if (Number.isNaN(expiry.getTime())) continue

    const monthsOut =
      (expiry.getFullYear() - now.getFullYear()) * 12 + (expiry.getMonth() - now.getMonth())

    if (monthsOut < 0) {
      buckets[0].expired++
    } else if (monthsOut < buckets.length) {
      buckets[monthsOut].expiring++
    }
  }

  return {
    labels: buckets.map((b) => b.label),
    datasets: [
      { label: 'Expiring', data: buckets.map((b) => b.expiring), backgroundColor: sevColors.value[1] },
      { label: 'Already expired', data: buckets.map((b) => b.expired), backgroundColor: sevColors.value[2] },
    ],
  }
})

// Real counts per issuing CA, replacing the Math.random() this panel used to
// generate — which regenerated on every reactivity tick and would strobe the
// moment live updates arrive.
const caDistChart = computed(() => {
  const byCA = new Map<string, number>()
  for (const c of certList.value) {
    const key = c.ca_authority_id ?? c.ca_account_id ?? 'unassigned'
    byCA.set(key, (byCA.get(key) ?? 0) + 1)
  }

  const nameFor = (id: string) =>
    id === 'unassigned' ? 'Unassigned' : caList.value.find((ca) => ca.id === id)?.name ?? id

  const entries = [...byCA.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
  return {
    labels: entries.map(([id]) => nameFor(id)),
    data: entries.map(([, count]) => count),
  }
})

// ── CA health ─────────────────────────────────────────────
const casByUrgency = computed(() =>
  [...caList.value].sort((a, b) => {
    const bySeverity = compareSeverity(caSeverity(a.status), caSeverity(b.status))
    return bySeverity !== 0 ? bySeverity : a.days_remaining - b.days_remaining
  }),
)

const casNeedingAttention = computed(
  () => caList.value.filter((ca) => caSeverity(ca.status) !== 'ok').length,
)

/** Renders an audit entry as a sentence, with CA alerts given their real detail. */
function describeActivity(log: AuditLog): string {
  if (log.action === 'ca.expiry_alert') {
    const d = parseDetails<CaExpiryAlertDetails>(log.details)
    if (d) return `${d.ca_name} expires in ${d.days_remaining} days (${d.threshold}-day threshold)`
  }
  const d = parseDetails<{ cn?: string; ca_name?: string; error?: string }>(log.details)
  const subject = d?.cn ?? d?.ca_name ?? log.entity_type
  switch (log.action) {
    case 'cert.issued': return `Issued ${subject}`
    case 'cert.renewed': return `Renewed ${subject}`
    case 'cert.renewal_failed': return `Renewal failed for ${subject}${d?.error ? `: ${d.error}` : ''}`
    case 'cert.deleted': return `Deleted ${subject}`
    case 'cert.private_key_exported': return `Private key exported for ${subject}`
    case 'ca_account.created': return `CA account ${subject} registered`
    default: return `${log.action} — ${subject}`
  }
}

function activitySeverity(log: AuditLog) {
  if (log.action === 'ca.expiry_alert') {
    const d = parseDetails<CaExpiryAlertDetails>(log.details)
    return d?.severity === 'CRITICAL' ? 'critical' : 'warning'
  }
  if (log.action.endsWith('_failed')) return 'critical'
  if (log.action === 'cert.private_key_exported') return 'warning'
  return 'ok'
}

// Charts hold their own chart.js instances; nudge them when the theme flips.
watch(currentTheme, () => {
  /* palettes are computed and re-read on change */
})
</script>

<template>
  <div class="space-y-6">
    <!-- Freshness and failure state, above everything. A dashboard that has
         stopped updating must look broken, not healthy. -->
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <div class="flex items-center gap-3 text-xs">
        <span v-if="lastLoadedAt" class="opacity-60 font-mono">
          Updated {{ formatTime(lastLoadedAt) }}
        </span>
        <span v-else class="opacity-60">Loading…</span>
      </div>
      <button class="btn btn-ghost btn-xs gap-1.5" :disabled="loading" @click="refreshAll">
        <RotateCw class="w-3.5 h-3.5" :class="loading && 'animate-spin'" />
        Refresh
      </button>
    </div>

    <DataState :loading="loading" :error="error" :loaded="loaded" @retry="refreshAll">
      <!-- ═══ Risk ribbon ═══ -->
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-primary"><KeyRound class="w-5 h-5" /></div>
          <div class="stat-title text-xs">Total certificates</div>
          <div class="stat-value text-2xl tabular-nums">{{ summary.total_certificates }}</div>
          <div class="stat-desc text-[11px]">Across all CAs</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-warning"><AlertTriangle class="w-5 h-5" /></div>
          <div class="stat-title text-xs">Expiring in 30d</div>
          <div class="stat-value text-2xl tabular-nums" :class="summary.expiring_soon_certs > 0 && 'text-warning'">
            {{ summary.expiring_soon_certs }}
          </div>
          <div class="stat-desc text-[11px]">Inside the renewal window</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-error"><XCircle class="w-5 h-5" /></div>
          <div class="stat-title text-xs">Expired</div>
          <div class="stat-value text-2xl tabular-nums" :class="summary.expired_certs > 0 && 'text-error'">
            {{ summary.expired_certs }}
          </div>
          <div class="stat-desc text-[11px]">Serving traffic will fail</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-info"><Building2 class="w-5 h-5" /></div>
          <div class="stat-title text-xs">CA authorities</div>
          <div class="stat-value text-2xl tabular-nums">{{ summary.total_cas }}</div>
          <div class="stat-desc text-[11px]">{{ summary.healthy_cas }} healthy</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4 col-span-2 md:col-span-1">
          <div class="stat-figure" :class="casNeedingAttention > 0 ? 'text-error' : 'text-success'">
            <ShieldCheck class="w-5 h-5" />
          </div>
          <div class="stat-title text-xs">CAs needing attention</div>
          <div
            class="stat-value text-2xl tabular-nums"
            :class="casNeedingAttention > 0 ? 'text-error' : 'text-success'"
          >
            {{ casNeedingAttention }}
          </div>
          <div class="stat-desc text-[11px]">
            {{ summary.warning_cas }} warning · {{ summary.critical_cas }} critical
          </div>
        </div>
      </div>

      <!-- ═══ Distributions ═══ -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Certificate status</h2>
            <DoughnutChart
              v-if="statusChart.data.length"
              :labels="statusChart.labels"
              :data="statusChart.data"
              :colors="statusChart.colors"
              :center-text="String(summary.total_certificates)"
              center-sub="Total"
            />
            <p v-else class="text-xs opacity-60 py-8 text-center">No certificates yet.</p>
          </div>
        </div>
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Key algorithms</h2>
            <DoughnutChart
              v-if="algoChart.data.length"
              :labels="algoChart.labels"
              :data="algoChart.data"
              :colors="catColors"
              :center-text="String(algoChart.data.reduce((a, b) => a + b, 0))"
              center-sub="Keys"
            />
            <p v-else class="text-xs opacity-60 py-8 text-center">No certificates yet.</p>
          </div>
        </div>
      </div>

      <!-- ═══ Forecast ═══ -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Expiration forecast</h2>
            <BarChart :labels="expirationChart.labels" :datasets="expirationChart.datasets" />
          </div>
        </div>
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Certificates by CA</h2>
            <DoughnutChart
              v-if="caDistChart.data.length"
              :labels="caDistChart.labels"
              :data="caDistChart.data"
              :colors="catColors"
            />
            <p v-else class="text-xs opacity-60 py-8 text-center">No certificates yet.</p>
          </div>
        </div>
      </div>

      <!-- ═══ CA health and activity ═══ -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold mb-2">CA health — most urgent first</h2>
            <div v-if="casByUrgency.length" class="overflow-x-auto">
              <table class="table table-sm">
                <thead>
                  <tr>
                    <th class="text-xs">CA</th>
                    <th class="text-xs">Type</th>
                    <th class="text-xs text-right">Expires</th>
                    <th class="text-xs">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="ca in casByUrgency.slice(0, 6)" :key="ca.id">
                    <td class="text-xs font-medium">{{ ca.name }}</td>
                    <td class="text-xs">{{ statusLabel(ca.ca_type) }}</td>
                    <td
                      class="text-xs font-mono tabular-nums text-right"
                      :class="severityText(caSeverity(ca.status))"
                    >
                      {{ formatDaysShort(ca.days_remaining) }}
                    </td>
                    <td>
                      <span class="badge badge-sm" :class="severityBadge(caSeverity(ca.status))">
                        {{ statusLabel(ca.status) }}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p v-else class="text-xs opacity-60 py-8 text-center">
              No CA authorities registered yet.
            </p>
          </div>
        </div>

        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold mb-2">Recent activity</h2>
            <ul v-if="activityList.length" class="space-y-2">
              <li
                v-for="log in activityList.slice(0, 7)"
                :key="log.id"
                class="flex items-start gap-2.5 text-xs"
              >
                <span
                  class="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0"
                  :class="{
                    'bg-error': activitySeverity(log) === 'critical',
                    'bg-warning': activitySeverity(log) === 'warning',
                    'bg-success': activitySeverity(log) === 'ok',
                  }"
                ></span>
                <span class="flex-1">{{ describeActivity(log) }}</span>
                <span class="opacity-50 font-mono text-[10px] shrink-0 whitespace-nowrap">
                  {{ formatRelative(log.created_at) }}
                </span>
              </li>
            </ul>
            <p v-else class="text-xs opacity-60 py-8 text-center">No activity recorded yet.</p>
          </div>
        </div>
      </div>
    </DataState>
  </div>
</template>
