<script setup lang="ts">
import { ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { Radar, Search, AlertTriangle, CheckCircle, Lock } from 'lucide-vue-next'

const api = useApi()
const target = ref('')
const port = ref('443')
const scanning = ref(false)
const scanError = ref('')
const results = ref<any>(null)

async function runScan() {
  if (!target.value) return
  scanning.value = true
  scanError.value = ''
  results.value = null
  try {
    const res = await api.post<any>('/api/v1/discovery/scan', {
      target: target.value,
      port: parseInt(port.value) || 443,
    })
    results.value = res
  } catch (err: any) {
    scanError.value = err.message || 'Scan failed'
  } finally {
    scanning.value = false
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
</script>

<template>
  <div class="space-y-6">
    <p class="text-sm text-base-content/60">Scan remote endpoints to discover and analyze TLS certificates</p>

    <!-- Scan Form -->
    <div class="card bg-base-100 border border-base-300">
      <div class="card-body p-5">
        <h2 class="card-title text-sm font-bold mb-3">
          <Radar class="w-4 h-4 text-primary" /> Scan Endpoint
        </h2>
        <form @submit.prevent="runScan" class="flex items-end gap-3">
          <div class="form-control flex-1">
            <label class="label"><span class="label-text text-xs">Hostname / IP</span></label>
            <input v-model="target" type="text" placeholder="e.g. google.com" class="input input-bordered input-sm" required />
          </div>
          <div class="form-control w-24">
            <label class="label"><span class="label-text text-xs">Port</span></label>
            <input v-model="port" type="number" class="input input-bordered input-sm" />
          </div>
          <button type="submit" class="btn btn-primary btn-sm gap-2" :disabled="scanning">
            <span v-if="scanning" class="loading loading-spinner loading-xs"></span>
            <Search v-else class="w-3.5 h-3.5" />
            Scan
          </button>
        </form>
      </div>
    </div>

    <!-- Error -->
    <div v-if="scanError" role="alert" class="alert alert-error">
      <AlertTriangle class="w-4 h-4" />
      <span class="text-sm">{{ scanError }}</span>
    </div>

    <!-- Results -->
    <div v-if="results" class="space-y-4">
      <!-- Stats -->
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-title text-xs">Subject</div>
          <div class="stat-value text-sm font-mono truncate">{{ results.subject || results.common_name || target }}</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-title text-xs">Issuer</div>
          <div class="stat-value text-sm font-mono truncate">{{ results.issuer || '—' }}</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-title text-xs">Valid Until</div>
          <div class="stat-value text-sm font-mono">{{ formatDate(results.not_after) }}</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-figure" :class="daysUntil(results.not_after) > 30 ? 'text-success' : 'text-warning'">
            <CheckCircle v-if="daysUntil(results.not_after) > 30" class="w-5 h-5" />
            <AlertTriangle v-else class="w-5 h-5" />
          </div>
          <div class="stat-title text-xs">Days Remaining</div>
          <div class="stat-value text-sm font-mono">{{ daysUntil(results.not_after) }}d</div>
        </div>
      </div>

      <!-- Detail Card -->
      <div class="card bg-base-100 border border-base-300">
        <div class="card-body p-5">
          <h2 class="card-title text-sm font-bold mb-3">
            <Lock class="w-4 h-4 text-primary" /> Certificate Details
          </h2>
          <div class="grid grid-cols-2 gap-4 text-xs">
            <div>
              <div class="text-base-content/60 mb-1">Protocol</div>
              <div class="font-mono">{{ results.protocol || 'TLSv1.3' }}</div>
            </div>
            <div>
              <div class="text-base-content/60 mb-1">Cipher Suite</div>
              <div class="font-mono">{{ results.cipher || '—' }}</div>
            </div>
            <div>
              <div class="text-base-content/60 mb-1">Key Algorithm</div>
              <div class="font-mono">{{ results.key_algorithm || results.public_key_algorithm || '—' }}</div>
            </div>
            <div>
              <div class="text-base-content/60 mb-1">Serial Number</div>
              <div class="font-mono truncate">{{ results.serial_number || '—' }}</div>
            </div>
            <div class="col-span-2" v-if="results.san_domains?.length">
              <div class="text-base-content/60 mb-1">Subject Alternative Names</div>
              <div class="flex flex-wrap gap-1.5">
                <span v-for="san in results.san_domains" :key="san" class="badge badge-sm badge-ghost font-mono">{{ san }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
