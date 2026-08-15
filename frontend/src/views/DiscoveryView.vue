<script setup lang="ts">
import { ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { 
  Radar, 
  Search, 
  Download, 
  CheckCircle2, 
  AlertCircle,
  Globe,
  Lock
} from 'lucide-vue-next'

const api = useApi()
const host = ref('google.com')
const port = ref(443)
const scanning = ref(false)
const scanResult = ref<any>(null)
const scanError = ref('')

async function runScan() {
  scanning.value = true
  scanError.value = ''
  scanResult.value = null
  try {
    const res = await api.post<any>('/api/v1/discovery/scan', {
      host: host.value,
      port: port.value,
    })
    scanResult.value = res
  } catch (err: any) {
    scanError.value = err.message
  } finally {
    scanning.value = false
  }
}
</script>

<template>
  <div class="space-y-8">
    <!-- Header -->
    <div>
      <h2 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
        <Radar class="w-7 h-7 text-indigo-400" />
        Certificate Discovery & Network Scanner
      </h2>
      <p class="text-sm text-slate-400 mt-1">
        Probe network endpoints via TLS handshake to discover unmanaged, rogue, or shadow certificates across your infrastructure.
      </p>
    </div>

    <!-- Scan Bar -->
    <div class="glass-panel p-6">
      <form @submit.prevent="runScan" class="flex flex-col md:flex-row items-end gap-4">
        <div class="flex-1 w-full">
          <label class="block text-xs font-semibold text-slate-300 mb-1.5">Target Hostname or IP</label>
          <div class="relative">
            <Globe class="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
            <input v-model="host" class="input-field pl-10 font-mono text-sm" placeholder="app.internal.corp or 10.0.0.1" required />
          </div>
        </div>

        <div class="w-full md:w-36">
          <label class="block text-xs font-semibold text-slate-300 mb-1.5">TLS Port</label>
          <input v-model.number="port" type="number" class="input-field font-mono text-sm" placeholder="443" required />
        </div>

        <button type="submit" class="btn-primary w-full md:w-auto h-[42px] px-6" :disabled="scanning">
          <Search class="w-4 h-4" :class="{ 'animate-spin': scanning }" />
          {{ scanning ? 'Scanning Handshake...' : 'Scan Endpoint' }}
        </button>
      </form>
    </div>

    <!-- Error state -->
    <div v-if="scanError" class="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-center gap-3">
      <AlertCircle class="w-5 h-5 flex-shrink-0" />
      <span>Scan failed: {{ scanError }}</span>
    </div>

    <!-- Scan Results Card -->
    <div v-if="scanResult" class="space-y-4">
      <h3 class="text-base font-semibold text-white flex items-center gap-2">
        <Lock class="w-4 h-4 text-emerald-400" />
        Discovered Certificate Details
      </h3>

      <div v-if="scanResult.error" class="glass-panel p-6 text-rose-400 text-sm">
        Remote host failed TLS handshake: {{ scanResult.error }}
      </div>

      <div v-else-if="scanResult.certificate" class="glass-panel p-6 space-y-6">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-xl font-bold text-white">{{ scanResult.certificate.common_name }}</div>
            <div class="text-xs text-slate-400 font-mono mt-1">
              {{ scanResult.host }}:{{ scanResult.port }} &bull; Fingerprint: {{ scanResult.certificate.fingerprint_sha256 }}
            </div>
          </div>
          <span class="badge" :class="scanResult.certificate.days_remaining <= 30 ? 'badge-warning' : 'badge-healthy'">
            {{ scanResult.certificate.days_remaining }} days left
          </span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
          <div>
            <span class="text-slate-400 block mb-1">Issuer DN</span>
            <span class="text-slate-200 font-mono break-all">{{ scanResult.certificate.issuer_dn }}</span>
          </div>
          <div>
            <span class="text-slate-400 block mb-1">Key Algorithm</span>
            <span class="text-slate-200 font-mono">{{ scanResult.certificate.key_type }} ({{ scanResult.certificate.key_size }} bits)</span>
          </div>
          <div>
            <span class="text-slate-400 block mb-1">Expiration Date</span>
            <span class="text-slate-200 font-mono">{{ new Date(scanResult.certificate.not_after).toLocaleString() }}</span>
          </div>
        </div>

        <div v-if="scanResult.certificate.sans && scanResult.certificate.sans.length > 0">
          <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">Subject Alternative Names</span>
          <div class="flex flex-wrap gap-2">
            <span v-for="san in scanResult.certificate.sans" :key="san" class="px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300 font-mono text-xs border border-slate-700">
              {{ san }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
