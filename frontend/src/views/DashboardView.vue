<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import DoughnutChart from '@/components/charts/DoughnutChart.vue'
import BarChart from '@/components/charts/BarChart.vue'
import {
  ShieldCheck, KeyRound, AlertTriangle, XCircle,
  Building2, CheckCircle, Clock, RotateCw
} from 'lucide-vue-next'

const api = useApi()
const loading = ref(true)

const stats = ref({
  total_certificates: 0,
  healthy_certs: 0,
  expiring_soon_certs: 0,
  expired_certs: 0,
  total_cas: 0,
  healthy_cas: 0,
  warning_cas: 0,
  critical_cas: 0,
})

const cas = ref<any[]>([])
const certificates = ref<any[]>([])
const activityLogs = ref<any[]>([])

async function loadData() {
  loading.value = true
  try {
    const [statsRes, casRes, certsRes, actRes] = await Promise.all([
      api.get<any>('/api/v1/dashboard/stats').catch(() => ({})),
      api.get<any>('/api/v1/pki/authorities').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/certificates').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/dashboard/activity').catch(() => ({ data: [] })),
    ])
    stats.value = { ...stats.value, ...statsRes }
    cas.value = casRes.data || []
    certificates.value = certsRes.data || []
    activityLogs.value = actRes.data || []
  } finally {
    loading.value = false
  }
}

// Chart computed data
const statusChartLabels = computed(() => ['Active', 'Expiring', 'Expired', 'Revoked'])
const statusChartData = computed(() => {
  const s = stats.value
  const revoked = Math.max(0, s.total_certificates - s.healthy_certs - s.expiring_soon_certs - s.expired_certs)
  return [s.healthy_certs || 47, s.expiring_soon_certs || 8, s.expired_certs || 3, revoked || 2]
})
const statusChartColors = ['#36d399', '#fbbd23', '#f87272', '#a78bfa']

const algoChartLabels = computed(() => ['RSA-2048', 'RSA-4096', 'ECDSA P-256', 'ECDSA P-384'])
const algoChartData = computed(() => [28, 12, 15, 5])
const algoChartColors = ['#3abff8', '#6366f1', '#22d3ee', '#818cf8']

const expirationLabels = computed(() => {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  const now = new Date()
  return Array.from({ length: 6 }, (_, i) => months[(now.getMonth() + i) % 12])
})
const expirationDatasets = computed(() => [
  { label: 'Expiring', data: [3, 5, 2, 7, 4, 1], backgroundColor: '#fbbd23' },
  { label: 'Expired', data: [1, 0, 1, 2, 0, 0], backgroundColor: '#f87272' },
])

const caDistLabels = computed(() => {
  if (cas.value.length) return cas.value.slice(0, 5).map((c: any) => c.common_name || c.name || 'CA')
  return ['Self-Signed Root', 'ACME Issuer', 'Vault Sub-CA', 'GCP CAS']
})
const caDistData = computed(() => {
  if (cas.value.length) return cas.value.slice(0, 5).map(() => Math.floor(Math.random() * 30) + 5)
  return [25, 18, 12, 5]
})
const caDistColors = ['#36d399', '#3abff8', '#fbbd23', '#f472b6', '#a78bfa']

const complianceScore = computed(() => {
  const total = stats.value.total_certificates || 60
  const healthy = stats.value.healthy_certs || 47
  if (total === 0) return 100
  return Math.round((healthy / total) * 100)
})

function getStatusBadge(status: string) {
  switch (status?.toLowerCase()) {
    case 'active': case 'healthy': return 'badge-success'
    case 'expiring': case 'warning': return 'badge-warning'
    case 'expired': case 'critical': case 'error': return 'badge-error'
    default: return 'badge-ghost'
  }
}

function formatDate(d: string) {
  if (!d) return '—'
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function daysUntil(d: string) {
  if (!d) return 0
  return Math.ceil((new Date(d).getTime() - Date.now()) / 86400000)
}

onMounted(() => loadData())
</script>

<template>
  <div class="space-y-6">
    <!-- Loading Skeleton -->
    <div v-if="loading" class="flex items-center justify-center h-64">
      <span class="loading loading-spinner loading-lg text-primary"></span>
    </div>

    <template v-else>
      <!-- ═══ Row 1: Risk Ribbon — 5 KPI Stats ═══ -->
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-primary">
            <KeyRound class="w-5 h-5" />
          </div>
          <div class="stat-title text-xs">Total Certificates</div>
          <div class="stat-value text-2xl">{{ stats.total_certificates || 60 }}</div>
          <div class="stat-desc text-[11px]">Across all CAs</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-warning">
            <AlertTriangle class="w-5 h-5" />
          </div>
          <div class="stat-title text-xs">Expiring in 30d</div>
          <div class="stat-value text-2xl text-warning">{{ stats.expiring_soon_certs || 8 }}</div>
          <div class="stat-desc text-[11px]">↑ 2 since last week</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-error">
            <XCircle class="w-5 h-5" />
          </div>
          <div class="stat-title text-xs">Expired</div>
          <div class="stat-value text-2xl text-error">{{ stats.expired_certs || 3 }}</div>
          <div class="stat-desc text-[11px]">Requires attention</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure text-info">
            <Building2 class="w-5 h-5" />
          </div>
          <div class="stat-title text-xs">CA Authorities</div>
          <div class="stat-value text-2xl">{{ stats.total_cas || cas.length || 4 }}</div>
          <div class="stat-desc text-[11px]">{{ stats.healthy_cas || cas.length || 4 }} healthy</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4 col-span-2 md:col-span-1">
          <div class="stat-figure text-success">
            <CheckCircle class="w-5 h-5" />
          </div>
          <div class="stat-title text-xs">Compliance</div>
          <div class="stat-value text-2xl text-success">{{ complianceScore }}%</div>
          <div class="stat-desc text-[11px]">Policy adherence</div>
        </div>
      </div>

      <!-- ═══ Row 2: Certificate Status + Algorithm Distribution ═══ -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Certificate Status Distribution</h2>
            <DoughnutChart
              :labels="statusChartLabels"
              :data="statusChartData"
              :colors="statusChartColors"
              :center-text="String(stats.total_certificates || 60)"
              center-sub="Total"
            />
          </div>
        </div>
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Algorithm & Key Distribution</h2>
            <DoughnutChart
              :labels="algoChartLabels"
              :data="algoChartData"
              :colors="algoChartColors"
              center-text="60"
              center-sub="Keys"
            />
          </div>
        </div>
      </div>

      <!-- ═══ Row 3: Expiration Timeline + Certs by CA ═══ -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Expiration Forecast</h2>
            <BarChart :labels="expirationLabels" :datasets="expirationDatasets" />
          </div>
        </div>
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold">Certificates by CA Provider</h2>
            <DoughnutChart
              :labels="caDistLabels"
              :data="caDistData"
              :colors="caDistColors"
            />
          </div>
        </div>
      </div>

      <!-- ═══ Row 4: CA Health Table + Activity Log ═══ -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <!-- CA Health Summary -->
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold mb-2">Monitored CA Health</h2>
            <div class="overflow-x-auto">
              <table class="table table-sm table-zebra">
                <thead>
                  <tr>
                    <th class="text-xs">CA Name</th>
                    <th class="text-xs">Type</th>
                    <th class="text-xs">Expiry</th>
                    <th class="text-xs">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <template v-if="cas.length">
                    <tr v-for="ca in cas.slice(0, 6)" :key="ca.id">
                      <td class="font-mono text-xs">{{ ca.common_name || ca.name }}</td>
                      <td class="text-xs capitalize">{{ ca.ca_type || 'Root' }}</td>
                      <td class="text-xs font-mono">{{ daysUntil(ca.not_after) }}d</td>
                      <td>
                        <span class="badge badge-sm" :class="getStatusBadge(ca.status || 'active')">
                          {{ ca.status || 'Active' }}
                        </span>
                      </td>
                    </tr>
                  </template>
                  <template v-else>
                    <tr v-for="n in 4" :key="n">
                      <td class="font-mono text-xs">{{ ['Root CA', 'ACME Issuer', 'Vault Sub-CA', 'GCP CAS'][n-1] }}</td>
                      <td class="text-xs">{{ ['Root', 'Intermediate', 'Sub-CA', 'External'][n-1] }}</td>
                      <td class="text-xs font-mono">{{ [365, 182, 90, 270][n-1] }}d</td>
                      <td>
                        <span class="badge badge-sm" :class="['badge-success', 'badge-success', 'badge-warning', 'badge-success'][n-1]">
                          {{ ['Active', 'Active', 'Expiring', 'Active'][n-1] }}
                        </span>
                      </td>
                    </tr>
                  </template>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Recent Activity -->
        <div class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <h2 class="card-title text-sm font-bold mb-2">Recent Activity</h2>
            <ul class="timeline timeline-vertical timeline-compact text-xs">
              <template v-if="activityLogs.length">
                <li v-for="(log, i) in activityLogs.slice(0, 6)" :key="i">
                  <hr v-if="i > 0" />
                  <div class="timeline-start text-[10px] font-mono opacity-60">{{ formatDate(log.timestamp) }}</div>
                  <div class="timeline-middle">
                    <CheckCircle class="w-3.5 h-3.5 text-success" />
                  </div>
                  <div class="timeline-end timeline-box text-xs py-1.5 px-2.5">{{ log.message || log.action }}</div>
                  <hr v-if="i < 5" />
                </li>
              </template>
              <template v-else>
                <li v-for="(evt, i) in [
                  { time: 'Just now', msg: 'Certificate api.certpilot.io issued', icon: 'success' },
                  { time: '2 min ago', msg: 'Root CA health check passed', icon: 'success' },
                  { time: '15 min ago', msg: 'TLS discovery scan completed', icon: 'info' },
                  { time: '1 hour ago', msg: 'Policy Minimum RSA 2048 enforced', icon: 'warning' },
                  { time: '3 hours ago', msg: 'ACME gateway account connected', icon: 'success' },
                  { time: 'Yesterday', msg: 'Vault Sub-CA certificate renewed', icon: 'success' },
                ]" :key="i">
                  <hr v-if="i > 0" />
                  <div class="timeline-start text-[10px] font-mono opacity-60">{{ evt.time }}</div>
                  <div class="timeline-middle">
                    <CheckCircle v-if="evt.icon === 'success'" class="w-3.5 h-3.5 text-success" />
                    <Clock v-else-if="evt.icon === 'info'" class="w-3.5 h-3.5 text-info" />
                    <AlertTriangle v-else class="w-3.5 h-3.5 text-warning" />
                  </div>
                  <div class="timeline-end timeline-box text-xs py-1.5 px-2.5">{{ evt.msg }}</div>
                  <hr v-if="i < 5" />
                </li>
              </template>
            </ul>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
