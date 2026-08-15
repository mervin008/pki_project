<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import { 
  ShieldCheck, 
  KeyRound, 
  AlertTriangle, 
  Clock, 
  Activity,
  ArrowUpRight,
  RefreshCw,
  Plus
} from 'lucide-vue-next'

const api = useApi()
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
const expiringCerts = ref<any[]>([])
const activityLogs = ref<any[]>([])
const loading = ref(true)

async function loadData() {
  loading.value = true
  try {
    const [statsRes, casRes, expiringRes, actRes] = await Promise.all([
      api.get<any>('/api/v1/dashboard/stats').catch(() => ({})),
      api.get<any>('/api/v1/pki/authorities').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/dashboard/expiring').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/dashboard/activity').catch(() => ({ data: [] })),
    ])

    stats.value = { ...stats.value, ...statsRes }
    cas.value = casRes.data || []
    expiringCerts.value = expiringRes.data || []
    activityLogs.value = actRes.data || []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadData()
})

function getStatusBadgeClass(status: string) {
  switch (status) {
    case 'HEALTHY':
    case 'ISSUED':
      return 'badge-healthy'
    case 'WARNING':
    case 'EXPIRING':
      return 'badge-warning'
    case 'CRITICAL':
    case 'EXPIRED':
    case 'RENEWAL_FAILED':
      return 'badge-critical'
    default:
      return 'badge-info'
  }
}
</script>

<template>
  <div class="space-y-8">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-2xl font-bold tracking-tight text-white">PKI & Certificate Operations</h2>
        <p class="text-sm text-slate-400 mt-1">Real-time control plane for multi-CA orchestration and certificate automation.</p>
      </div>

      <div class="flex items-center gap-3">
        <button @click="loadData" class="btn-secondary">
          <RefreshCw class="w-4 h-4" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
        <router-link to="/certificates" class="btn-primary">
          <Plus class="w-4 h-4" />
          Request Certificate
        </router-link>
      </div>
    </div>

    <!-- Metric Cards Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
      <!-- Total Certs -->
      <div class="glass-panel p-5">
        <div class="flex items-center justify-between text-slate-400 mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider">Total Certificates</span>
          <KeyRound class="w-5 h-5 text-indigo-400" />
        </div>
        <div class="text-3xl font-bold text-white">{{ stats.total_certificates }}</div>
        <div class="mt-2 text-xs text-emerald-400 flex items-center gap-1 font-medium">
          <span>{{ stats.healthy_certs }} healthy & valid</span>
        </div>
      </div>

      <!-- Expiring Soon -->
      <div class="glass-panel p-5">
        <div class="flex items-center justify-between text-slate-400 mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider">Expiring (&le;30d)</span>
          <Clock class="w-5 h-5 text-amber-400" />
        </div>
        <div class="text-3xl font-bold text-amber-400">{{ stats.expiring_soon_certs }}</div>
        <div class="mt-2 text-xs text-slate-400">Scheduled for auto-renewal</div>
      </div>

      <!-- Monitored CAs -->
      <div class="glass-panel p-5">
        <div class="flex items-center justify-between text-slate-400 mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider">Monitored CAs</span>
          <ShieldCheck class="w-5 h-5 text-emerald-400" />
        </div>
        <div class="text-3xl font-bold text-white">{{ stats.total_cas }}</div>
        <div class="mt-2 text-xs text-slate-400">Root & Intermediate CAs</div>
      </div>

      <!-- CA Alerts -->
      <div class="glass-panel p-5">
        <div class="flex items-center justify-between text-slate-400 mb-3">
          <span class="text-xs font-semibold uppercase tracking-wider">CA Status Warnings</span>
          <AlertTriangle class="w-5 h-5" :class="stats.warning_cas + stats.critical_cas > 0 ? 'text-rose-400' : 'text-slate-400'" />
        </div>
        <div class="text-3xl font-bold" :class="stats.warning_cas + stats.critical_cas > 0 ? 'text-rose-400' : 'text-slate-200'">
          {{ stats.warning_cas + stats.critical_cas }}
        </div>
        <div class="mt-2 text-xs text-slate-400">
          {{ stats.critical_cas > 0 ? `${stats.critical_cas} critical expiration risk` : 'All CA authorities operational' }}
        </div>
      </div>
    </div>

    <!-- CA Health & Expiry Section (Pillar 1) -->
    <div class="space-y-4">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <ShieldCheck class="w-5 h-5 text-indigo-400" />
          <h3 class="text-lg font-semibold text-white">Certificate Authority Health & Expiry Monitor</h3>
        </div>
        <router-link to="/pki" class="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium">
          View Trust Chains <ArrowUpRight class="w-3.5 h-3.5" />
        </router-link>
      </div>

      <div v-if="cas.length === 0" class="glass-panel p-8 text-center text-slate-400">
        <ShieldCheck class="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <p class="font-medium text-slate-300">No CA Authorities Registered Yet</p>
        <p class="text-xs text-slate-500 mt-1 mb-4">Register your Root and Intermediate CAs to monitor expiry days and CRL freshness.</p>
        <router-link to="/pki" class="btn-primary">
          Register CA Authority
        </router-link>
      </div>

      <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        <div v-for="ca in cas" :key="ca.id" class="glass-panel p-5 space-y-4">
          <div class="flex items-start justify-between">
            <div>
              <div class="font-bold text-white text-base">{{ ca.name }}</div>
              <div class="text-xs text-slate-400 font-mono mt-0.5">{{ ca.ca_type }} CA</div>
            </div>
            <span class="badge" :class="getStatusBadgeClass(ca.status)">
              {{ ca.status }}
            </span>
          </div>

          <!-- Days Left Progress Gauge -->
          <div class="space-y-1.5">
            <div class="flex justify-between text-xs">
              <span class="text-slate-400">Validity Remaining</span>
              <span class="font-bold font-mono" :class="ca.days_remaining <= 30 ? 'text-rose-400' : ca.days_remaining <= 180 ? 'text-amber-400' : 'text-emerald-400'">
                {{ ca.days_remaining }} days
              </span>
            </div>
            <div class="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div 
                class="h-full rounded-full transition-all duration-500"
                :class="ca.days_remaining <= 30 ? 'bg-rose-500' : ca.days_remaining <= 180 ? 'bg-amber-500' : 'bg-emerald-500'"
                :style="{ width: `${Math.min(100, Math.max(5, (ca.days_remaining / 365) * 100))}%` }"
              ></div>
            </div>
          </div>

          <!-- CRL & OCSP Status -->
          <div class="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-xs">
            <div>
              <span class="text-slate-400 block text-[11px]">CRL Status</span>
              <span class="font-medium" :class="ca.is_crl_fresh ? 'text-emerald-400' : 'text-slate-400'">
                {{ ca.is_crl_fresh ? '✓ Fresh' : 'N/A' }}
              </span>
            </div>
            <div>
              <span class="text-slate-400 block text-[11px]">OCSP Responder</span>
              <span class="font-medium" :class="ca.is_ocsp_responsive ? 'text-emerald-400' : 'text-slate-400'">
                {{ ca.is_ocsp_responsive ? '✓ Responsive' : 'N/A' }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Expiring Certificates & Recent Activity Grid -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
      <!-- Expiring Soon List -->
      <div class="space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <Clock class="w-5 h-5 text-amber-400" />
            <h3 class="text-lg font-semibold text-white">Upcoming Expirations</h3>
          </div>
          <router-link to="/certificates" class="text-xs text-indigo-400 hover:text-indigo-300 font-medium">
            View All
          </router-link>
        </div>

        <div class="glass-panel divide-y divide-slate-800/60 overflow-hidden">
          <div v-if="expiringCerts.length === 0" class="p-6 text-center text-sm text-slate-400">
            No certificates expiring within the next 30 days.
          </div>
          <div v-for="cert in expiringCerts" :key="cert.id" class="p-4 flex items-center justify-between hover:bg-slate-800/30 transition-colors">
            <div>
              <div class="font-semibold text-slate-100 text-sm">{{ cert.common_name }}</div>
              <div class="text-xs text-slate-400 font-mono mt-0.5">
                {{ cert.environment || 'production' }} &bull; {{ cert.key_type }} {{ cert.key_size }}
              </div>
            </div>
            <div class="text-right">
              <div class="text-xs font-bold font-mono text-amber-400">{{ cert.days_remaining }}d left</div>
              <span class="badge badge-warning text-[10px] mt-1">Auto-Renewing</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Live Activity Log Feed -->
      <div class="space-y-4">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <Activity class="w-5 h-5 text-indigo-400" />
            <h3 class="text-lg font-semibold text-white">Audit & Operations Feed</h3>
          </div>
        </div>

        <div class="glass-panel divide-y divide-slate-800/60 overflow-hidden">
          <div v-if="activityLogs.length === 0" class="p-6 text-center text-sm text-slate-400">
            No recent activity recorded.
          </div>
          <div v-for="log in activityLogs.slice(0, 6)" :key="log.id" class="p-4 flex items-start gap-3 hover:bg-slate-800/30 transition-colors">
            <div class="w-2 h-2 rounded-full bg-indigo-400 mt-1.5 flex-shrink-0"></div>
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium text-slate-200 truncate">{{ log.action }}</div>
              <div class="text-xs text-slate-400 font-mono mt-0.5">{{ log.actor_email || 'System' }} &bull; {{ new Date(log.created_at).toLocaleTimeString() }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
