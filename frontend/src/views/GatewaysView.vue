<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import { 
  Cpu, 
  Plus, 
  RefreshCw, 
  CheckCircle2, 
  AlertCircle, 
  Activity, 
  Trash2,
  X,
  Server
} from 'lucide-vue-next'

const api = useApi()
const gateways = ref<any[]>([])
const caAccounts = ref<any[]>([])
const loading = ref(true)
const showAddAccountModal = ref(false)

const newAccount = ref({
  name: '',
  provider_type: 'selfsigned',
  gateway_addr: 'localhost:9091',
  config_encrypted: '',
})

const submitting = ref(false)
const checkingId = ref<string | null>(null)
const errorMessage = ref('')

async function loadData() {
  loading.value = true
  try {
    const [gwRes, accRes] = await Promise.all([
      api.get<any>('/api/v1/gateways').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/ca-accounts').catch(() => ({ data: [] })),
    ])
    gateways.value = gwRes.data || []
    caAccounts.value = accRes.data || []
  } finally {
    loading.value = false
  }
}

async function submitAccount() {
  submitting.value = true
  errorMessage.value = ''
  try {
    await api.post('/api/v1/ca-accounts', newAccount.value)
    showAddAccountModal.value = false
    newAccount.value = {
      name: '',
      provider_type: 'selfsigned',
      gateway_addr: 'localhost:9091',
      config_encrypted: '',
    }
    await loadData()
  } catch (err: any) {
    errorMessage.value = err.message
  } finally {
    submitting.value = false
  }
}

async function testHealth(account: any) {
  checkingId.value = account.id
  try {
    const res = await api.post<any>(`/api/v1/ca-accounts/${account.id}/health`)
    alert(`Gateway Health: ${res.status}\nMessage: ${res.message}\nLatency: ${res.latency_ms}ms`)
    await loadData()
  } catch (err: any) {
    alert('Health check failed: ' + err.message)
  } finally {
    checkingId.value = null
  }
}

async function deleteAccount(id: string) {
  if (!confirm('Are you sure you want to remove this CA account configuration?')) return
  try {
    await api.delete(`/api/v1/ca-accounts/${id}`)
    await loadData()
  } catch (err: any) {
    alert('Delete failed: ' + err.message)
  }
}

onMounted(() => {
  loadData()
})
</script>

<template>
  <div class="space-y-8">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Cpu class="w-7 h-7 text-indigo-400" />
          Gateway Plugins & Provider Connections
        </h2>
        <p class="text-sm text-slate-400 mt-1">
          Every CA runs as an isolated gateway container communicating over high-speed gRPC.
        </p>
      </div>

      <div class="flex items-center gap-3">
        <button @click="loadData" class="btn-secondary">
          <RefreshCw class="w-4 h-4" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
        <button @click="showAddAccountModal = true" class="btn-primary">
          <Plus class="w-4 h-4" />
          Connect CA Gateway
        </button>
      </div>
    </div>

    <!-- Active Connected Gateways (Process Level) -->
    <div class="space-y-4">
      <div class="flex items-center justify-between">
        <h3 class="text-base font-semibold text-white">Active Connected Gateway Plugins (gRPC)</h3>
        <span class="text-xs text-slate-400 font-mono">{{ gateways.length }} active connections</span>
      </div>

      <div v-if="gateways.length === 0" class="glass-panel p-8 text-center text-slate-400">
        <Server class="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <p class="font-medium text-slate-300">No Gateway Plugins Currently Connected</p>
        <p class="text-xs text-slate-500 mt-1 mb-4">Start a gateway plugin container or local binary (e.g. <code>make run-gateway-selfsigned</code> on port 9091).</p>
      </div>

      <div v-else class="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div v-for="gw in gateways" :key="gw.name" class="glass-panel p-5 space-y-4">
          <div class="flex items-start justify-between">
            <div>
              <div class="font-bold text-white text-base">{{ gw.name }}</div>
              <div class="text-xs text-slate-400 font-mono mt-0.5">{{ gw.addr }} &bull; {{ gw.type }}</div>
            </div>
            <span class="badge" :class="gw.is_connected ? 'badge-healthy' : 'badge-critical'">
              <span class="w-2 h-2 rounded-full" :class="gw.is_connected ? 'bg-emerald-400' : 'bg-rose-400'"></span>
              {{ gw.is_connected ? 'Connected' : 'Disconnected' }}
            </span>
          </div>

          <!-- Capabilities Matrix -->
          <div v-if="gw.capabilities" class="space-y-2 pt-2 border-t border-slate-800/80 text-xs">
            <div class="text-[11px] text-slate-400 uppercase font-semibold">Capabilities</div>
            <div class="flex flex-wrap gap-2">
              <span v-if="gw.capabilities.supports_wildcard" class="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 text-[11px] border border-indigo-500/30">
                Wildcards
              </span>
              <span v-if="gw.capabilities.supports_multi_domain" class="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 text-[11px] border border-indigo-500/30">
                Multi-Domain SANs
              </span>
              <span v-for="kt in gw.capabilities.supported_key_types" :key="kt" class="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px]">
                {{ kt }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- CA Accounts Table (Database Configured) -->
    <div class="space-y-4">
      <h3 class="text-base font-semibold text-white">Configured CA Accounts</h3>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Account Name</th>
              <th>Provider Type</th>
              <th>Gateway Address</th>
              <th>Connection Status</th>
              <th>Last Checked</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="caAccounts.length === 0">
              <td colspan="6" class="text-center py-8 text-slate-400">
                No CA accounts configured yet. Click "Connect CA Gateway" above.
              </td>
            </tr>
            <tr v-for="acc in caAccounts" :key="acc.id">
              <td class="font-semibold text-white">{{ acc.name }}</td>
              <td>
                <span class="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {{ acc.provider_type }}
                </span>
              </td>
              <td class="font-mono text-xs text-slate-300">{{ acc.gateway_addr }}</td>
              <td>
                <span class="badge" :class="acc.status === 'CONNECTED' ? 'badge-healthy' : 'badge-critical'">
                  {{ acc.status }}
                </span>
              </td>
              <td class="text-xs text-slate-400">
                {{ acc.last_health_at ? new Date(acc.last_health_at).toLocaleString() : 'Never' }}
              </td>
              <td>
                <div class="flex items-center gap-2">
                  <button 
                    @click="testHealth(acc)" 
                    class="p-1.5 text-slate-400 hover:text-indigo-400 hover:bg-slate-800 rounded transition-colors"
                    :disabled="checkingId === acc.id"
                    title="Test Gateway Health"
                  >
                    <Activity class="w-4 h-4" :class="{ 'animate-spin': checkingId === acc.id }" />
                  </button>
                  <button 
                    @click="deleteAccount(acc.id)" 
                    class="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                    title="Delete Account"
                  >
                    <Trash2 class="w-4 h-4" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Connect CA Account Modal -->
    <div v-if="showAddAccountModal" class="modal-backdrop">
      <div class="modal-content">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <h3 class="text-lg font-bold text-white">Connect CA Gateway Plugin</h3>
          <button @click="showAddAccountModal = false" class="text-slate-400 hover:text-white">
            <X class="w-5 h-5" />
          </button>
        </div>

        <div v-if="errorMessage" class="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          {{ errorMessage }}
        </div>

        <form @submit.prevent="submitAccount" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Account / Identifier Name</label>
            <input v-model="newAccount.name" class="input-field" placeholder="e.g. selfsigned-local or letsencrypt-prod" required />
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">Provider Type</label>
              <select v-model="newAccount.provider_type" class="input-field">
                <option value="selfsigned">Self-Signed (Dev/Testing)</option>
                <option value="acme">ACME (Let's Encrypt / ZeroSSL)</option>
                <option value="vault">HashiCorp Vault PKI</option>
                <option value="gcp_cas">Google Cloud CAS</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">gRPC Gateway Address</label>
              <input v-model="newAccount.gateway_addr" class="input-field font-mono text-xs" placeholder="localhost:9091" required />
            </div>
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Provider Config (JSON)</label>
            <textarea 
              v-model="newAccount.config_encrypted" 
              class="input-field font-mono text-xs h-24" 
              placeholder='{"directory_url": "https://acme-v02.api.letsencrypt.org/directory", "email": "admin@example.com"}'
            ></textarea>
          </div>

          <div class="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <button type="button" @click="showAddAccountModal = false" class="btn-secondary">
              Cancel
            </button>
            <button type="submit" class="btn-primary" :disabled="submitting">
              {{ submitting ? 'Connecting...' : 'Connect Gateway' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
