<script setup lang="ts">
/**
 * Discovery — deliberately plain, pending the frontend redesign.
 *
 * The one thing this view must get right is which row is the finding. A scan of
 * a real estate returns mostly certificates the team issued itself; the rows
 * that justify having run it are the ones nobody knew about. So results are
 * sorted with UNMANAGED first and the verdict is the first column, not a badge
 * tucked at the end.
 *
 * It previously sent `target` where the API expects `host`/`targets`, and read
 * `results.subject`, `results.protocol` and `results.cipher`, none of which the
 * backend has ever returned — so every field rendered as an em dash and the
 * scan itself 400'd.
 */
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import type {
  DiscoveryResult,
  DiscoveryScanResponse,
  DiscoverySchedule,
  DiscoveryScheduleList,
} from '@/lib/types'
import { AlertTriangle, CalendarClock, CheckCircle, Radar, Search, Trash2 } from 'lucide-vue-next'

const api = useApi()
const targetInput = ref('')
const port = ref('443')
const scanning = ref(false)
const scanError = ref('')
const response = ref<DiscoveryScanResponse | null>(null)
const importing = ref<string | null>(null)
const importMessage = ref('')
const cancelling = ref(false)

/** A wide scan runs in the background; the response says so via scan.status. */
const running = computed(() => response.value?.scan.status === 'RUNNING')
let pollTimer: ReturnType<typeof setTimeout> | null = null

onUnmounted(stopPolling)

function stopPolling() {
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
}

/**
 * Poll a background run until it stops.
 *
 * Deliberately not driven off the event stream. Progress is published there,
 * but this view is opened to watch one specific scan, and a poll that keeps
 * working when the stream is down is the version that does not leave someone
 * staring at a run they cannot see the end of.
 */
function pollScan(id: string) {
  stopPolling()
  pollTimer = setTimeout(async () => {
    try {
      const res = await api.get<DiscoveryScanResponse>(`/api/v1/discovery/scans/${id}`)
      response.value = res
      if (res.scan.status === 'RUNNING') {
        pollScan(id)
      } else {
        scanning.value = false
      }
    } catch (err: any) {
      scanError.value = err.message || 'Lost track of the scan'
      scanning.value = false
    }
  }, 2000)
}

async function cancelScan() {
  const id = response.value?.scan.id
  if (!id) return
  cancelling.value = true
  try {
    await api.post(`/api/v1/discovery/scans/${id}/cancel`)
  } catch (err: any) {
    scanError.value = err.message || 'Cancel failed'
  } finally {
    cancelling.value = false
  }
}

/** Split on commas, spaces, and newlines so a pasted list works. */
const targets = computed(() =>
  targetInput.value
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter(Boolean),
)

/** Unmanaged first, then unreachable, then the rest. */
const results = computed<DiscoveryResult[]>(() => {
  const order = { UNMANAGED: 0, UNREACHABLE: 1, MANAGED: 2 } as const
  return [...(response.value?.data ?? [])].sort(
    (a, b) => order[a.management_state] - order[b.management_state],
  )
})

async function runScan() {
  if (targets.value.length === 0) return
  scanning.value = true
  scanError.value = ''
  importMessage.value = ''
  response.value = null
  stopPolling()
  try {
    const res = await api.post<DiscoveryScanResponse>('/api/v1/discovery/scan', {
      targets: targets.value,
      port: parseInt(port.value) || 443,
    })
    response.value = res
    if (res.scan.status === 'RUNNING') {
      pollScan(res.scan.id)
      return // stays "scanning" until the run stops
    }
  } catch (err: any) {
    scanError.value = err.message || 'Scan failed'
  }
  scanning.value = false
}

async function importResult(result: DiscoveryResult) {
  importing.value = result.id
  importMessage.value = ''
  try {
    const res = await api.post<{ message: string }>('/api/v1/discovery/import', {
      result_id: result.id,
    })
    importMessage.value = res.message
    result.is_imported = true
    result.management_state = 'MANAGED'
  } catch (err: any) {
    scanError.value = err.message || 'Import failed'
  } finally {
    importing.value = null
  }
}

function verdictClass(state: DiscoveryResult['management_state']) {
  switch (state) {
    case 'UNMANAGED':
      return 'sev-warning'
    case 'UNREACHABLE':
      return 'sev-unknown'
    default:
      return 'sev-ok'
  }
}

function severityClass(severity: string) {
  switch (severity) {
    case 'CRITICAL':
      return 'text-error'
    case 'WARNING':
      return 'text-warning'
    default:
      return 'sev-unknown'
  }
}

function formatDate(d?: string) {
  if (!d) return '—'
  return new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

function formatWhen(d?: string | null) {
  if (!d) return 'never'
  return new Date(d).toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  })
}

// ── Schedules ─────────────────────────────────────────────
//
// Discovery run once is a snapshot. Run on a schedule it is monitoring, which
// is the only version that catches an endpoint someone stood up last Tuesday.

const schedules = ref<DiscoverySchedule[]>([])
const scheduleError = ref('')
const newSchedule = ref({ name: '', targets: '', interval_minutes: 1440 })
const savingSchedule = ref(false)

onMounted(loadSchedules)

async function loadSchedules() {
  try {
    const res = await api.get<DiscoveryScheduleList>('/api/v1/discovery/schedules')
    schedules.value = res.data
  } catch (err: any) {
    scheduleError.value = err.message || 'Could not load schedules'
  }
}

async function createSchedule() {
  savingSchedule.value = true
  scheduleError.value = ''
  try {
    await api.post('/api/v1/discovery/schedules', {
      name: newSchedule.value.name,
      targets: newSchedule.value.targets.split(/[\s,]+/).filter(Boolean),
      interval_minutes: Number(newSchedule.value.interval_minutes),
    })
    newSchedule.value = { name: '', targets: '', interval_minutes: 1440 }
    await loadSchedules()
  } catch (err: any) {
    scheduleError.value = err.message || 'Could not save the schedule'
  } finally {
    savingSchedule.value = false
  }
}

async function runSchedule(schedule: DiscoverySchedule) {
  try {
    const res = await api.post<DiscoveryScanResponse>(
      `/api/v1/discovery/schedules/${schedule.id}/run`,
    )
    response.value = res
    scanning.value = true
    pollScan(res.scan.id)
  } catch (err: any) {
    scheduleError.value = err.message || 'Could not run the schedule'
  }
}

async function deleteSchedule(schedule: DiscoverySchedule) {
  try {
    await api.delete(`/api/v1/discovery/schedules/${schedule.id}`)
    await loadSchedules()
  } catch (err: any) {
    scheduleError.value = err.message || 'Could not delete the schedule'
  }
}
</script>

<template>
  <div class="space-y-6">
    <p class="text-sm text-[color:var(--text-muted)]">
      Scan endpoints and find the certificates nobody told CertPilot about.
    </p>

    <div class="panel border">
      <div class="panel-body p-5">
        <h2 class="label-rail mb-3">
          <Radar class="w-4 h-4 text-[color:var(--signal)]" /> Scan endpoints
        </h2>
        <form @submit.prevent="runScan" class="flex items-end gap-3">
          <div class="field flex-1">
            <label class="label-micro">Hosts — one or many, separated by spaces or commas</label>
            <input
              v-model="targetInput"
              type="text"
              placeholder="example.com, 10.0.0.0/24, 10.0.0.4-40:8443"
              class="input-console"
              required
            />
          </div>
          <div class="field w-24">
            <label class="label-micro">Default port</label>
            <input v-model="port" type="number" class="input-console" />
          </div>
          <button type="submit" class="btn-console btn-signal gap-2" :disabled="scanning">
            <span v-if="scanning" class="spinner-console"></span>
            <Search v-else class="w-3.5 h-3.5" />
            Scan {{ targets.length || '' }}
          </button>
        </form>
      </div>
    </div>

    <!-- Schedules. A scan run once is a snapshot; this is the version that
         catches an endpoint somebody stood up last Tuesday. -->
    <div class="panel border">
      <div class="panel-body p-5">
        <h2 class="label-rail mb-3">
          <CalendarClock class="w-4 h-4 text-[color:var(--signal)]" /> Scheduled scans
        </h2>

        <div v-if="schedules.length" class="space-y-2 mb-4">
          <div
            v-for="schedule in schedules"
            :key="schedule.id"
            class="flex items-center justify-between gap-3 text-xs border p-3"
          >
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="font-medium">{{ schedule.name }}</span>
                <span v-if="!schedule.is_enabled" class="tag">disabled</span>
              </div>
              <div class="font-mono text-[color:var(--text-muted)] truncate">
                {{ schedule.targets.join(', ') }} · every
                {{ schedule.interval_minutes }} min
              </div>
              <div class="text-[color:var(--text-muted)]">
                last run {{ formatWhen(schedule.last_run_at) }} · next
                {{ formatWhen(schedule.next_run_at) }}
              </div>
              <!-- A schedule that fails every night and is never read is worse
                   than none: it is the appearance of coverage. -->
              <div v-if="schedule.last_error" class="sev-critical mt-1">
                last run did not happen: {{ schedule.last_error }}
              </div>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              <button class="btn-console" @click="runSchedule(schedule)">Run now</button>
              <button class="btn-console btn-danger" @click="deleteSchedule(schedule)">
                <Trash2 class="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
        <p v-else class="text-xs text-[color:var(--text-muted)] mb-4">
          Nothing is being scanned on a schedule, so anything that appears between manual scans
          goes unnoticed.
        </p>

        <form @submit.prevent="createSchedule" class="flex items-end gap-3">
          <div class="field w-40">
            <label class="label-micro">Name</label>
            <input v-model="newSchedule.name" class="input-console" required />
          </div>
          <div class="field flex-1">
            <label class="label-micro">Targets</label>
            <input
              v-model="newSchedule.targets"
              class="input-console"
              placeholder="10.0.0.0/24"
              required
            />
          </div>
          <div class="field w-28">
            <label class="label-micro">Every (min)</label>
            <input
              v-model="newSchedule.interval_minutes"
              type="number"
              class="input-console"
            />
          </div>
          <button type="submit" class="btn-console" :disabled="savingSchedule">Add</button>
        </form>

        <div v-if="scheduleError" role="alert" class="notice mt-3" data-tone="critical">
          <AlertTriangle class="w-4 h-4" />
          <span class="text-sm">{{ scheduleError }}</span>
        </div>
      </div>
    </div>

    <div v-if="scanError" role="alert" class="notice" data-tone="critical">
      <AlertTriangle class="w-4 h-4" />
      <span class="text-sm">{{ scanError }}</span>
    </div>

    <div v-if="importMessage" role="status" class="notice" data-tone="signal">
      <CheckCircle class="w-4 h-4" />
      <span class="text-sm">{{ importMessage }}</span>
    </div>

    <div v-if="response" class="space-y-4">
      <!-- The summary, not the counts, because zero unmanaged and zero
           reachable look identical as numbers and mean opposite things. -->
      <div class="panel border">
        <div class="panel-body p-5 gap-2">
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="text-sm font-medium">{{ response.summary }}</p>
              <p class="text-xs text-[color:var(--text-muted)] font-mono mt-1">
                {{ response.scan.results_count }}<span v-if="response.target_count">
                  of {{ response.target_count }}</span> scanned ·
                {{ response.scan.unmanaged_count }} unmanaged ·
                {{ response.scan.managed_count }} managed ·
                {{ response.scan.unreachable_count }} unreachable
              </p>
            </div>
            <button
              v-if="running"
              class="btn-console btn-danger"
              :disabled="cancelling"
              @click="cancelScan"
            >
              <span v-if="cancelling" class="spinner-console"></span>
              Stop scan
            </button>
          </div>
          <progress
            v-if="running && response.target_count"
            class="meter w-full"
            :value="response.scan.results_count"
            :max="response.target_count"
          ></progress>
        </div>
      </div>

      <div
        v-for="result in results"
        :key="result.id"
        class="panel border"
      >
        <div class="panel-body p-5 gap-3">
          <div class="flex items-center justify-between gap-3">
            <div class="flex items-center gap-3">
              <span class="tag" :class="verdictClass(result.management_state)">
                {{ result.management_state }}
              </span>
              <span class="font-mono text-sm">{{ result.host }}:{{ result.port }}</span>
              <span class="text-xs text-[color:var(--text-muted)]">{{ result.common_name || '—' }}</span>
            </div>
            <button
              v-if="result.management_state === 'UNMANAGED' && result.reachable"
              class="btn-console"
              :disabled="importing === result.id"
              @click="importResult(result)"
            >
              <span v-if="importing === result.id" class="spinner-console"></span>
              Import
            </button>
          </div>

          <p v-if="!result.reachable" class="text-xs font-mono text-[color:var(--text-muted)]">
            {{ result.error }}
          </p>

          <div v-else class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div>
              <div class="text-[color:var(--text-muted)]">Trust</div>
              <div class="font-mono">{{ result.trust_state }}</div>
            </div>
            <div>
              <div class="text-[color:var(--text-muted)]">Expires</div>
              <div class="font-mono">{{ formatDate(result.not_after) }}</div>
            </div>
            <div>
              <div class="text-[color:var(--text-muted)]">Issuer</div>
              <div class="font-mono truncate">{{ result.issuer_dn || '—' }}</div>
            </div>
            <div>
              <div class="text-[color:var(--text-muted)]">Key</div>
              <div class="font-mono">{{ result.key_type }}-{{ result.key_size }}</div>
            </div>
            <div>
              <div class="text-[color:var(--text-muted)]">TLS</div>
              <div class="font-mono">{{ result.tls_version || '—' }}</div>
            </div>
            <div>
              <div class="text-[color:var(--text-muted)]">Cipher</div>
              <div class="font-mono truncate">{{ result.cipher_suite || '—' }}</div>
            </div>
            <div>
              <div class="text-[color:var(--text-muted)]">Key exchange</div>
              <div class="font-mono truncate">{{ result.key_exchange || '—' }}</div>
            </div>
            <div>
              <div class="text-[color:var(--text-muted)]">Chain sent</div>
              <div class="font-mono">{{ result.chain_length }}</div>
            </div>
          </div>

          <ul v-if="result.findings.length" class="space-y-1 text-xs">
            <li v-for="finding in result.findings" :key="finding.code" class="flex gap-2">
              <span class="font-mono shrink-0" :class="severityClass(finding.severity)">
                {{ finding.code }}
              </span>
              <span class="text-[color:var(--text-secondary)]">{{ finding.detail }}</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</template>
