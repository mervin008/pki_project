<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import { 
  ShieldCheck, 
  Plus, 
  RefreshCw, 
  GitFork, 
  Activity, 
  AlertTriangle,
  X,
  CheckCircle2,
  Trash2
} from 'lucide-vue-next'

const api = useApi()
const cas = ref<any[]>([])
const tree = ref<any[]>([])
const loading = ref(true)
const showRegisterModal = ref(false)

const newCA = ref({
  name: '',
  certificate_pem: '',
  parent_ca_id: '',
  crl_distribution_url: '',
  ocsp_responder_url: '',
  notes: '',
})

const submitting = ref(false)
const errorMessage = ref('')

async function loadCAs() {
  loading.value = true
  try {
    const [casRes, treeRes] = await Promise.all([
      api.get<any>('/api/v1/pki/authorities').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/pki/tree').catch(() => ({ data: [] })),
    ])
    cas.value = casRes.data || []
    tree.value = treeRes.data || []
  } finally {
    loading.value = false
  }
}

async function triggerHealthCheck(id: string) {
  try {
    await api.post(`/api/v1/pki/authorities/${id}/check`)
    await loadCAs()
  } catch (err: any) {
    alert('Health check failed: ' + err.message)
  }
}

async function deleteCA(id: string) {
  if (!confirm('Are you sure you want to unregister this CA authority?')) return
  try {
    await api.delete(`/api/v1/pki/authorities/${id}`)
    await loadCAs()
  } catch (err: any) {
    alert('Failed to delete CA: ' + err.message)
  }
}

async function submitCA() {
  submitting.value = true
  errorMessage.value = ''
  try {
    const payload = {
      ...newCA.value,
      parent_ca_id: newCA.value.parent_ca_id ? newCA.value.parent_ca_id : undefined,
    }
    await api.post('/api/v1/pki/authorities', payload)
    showRegisterModal.value = false
    newCA.value = {
      name: '',
      certificate_pem: '',
      parent_ca_id: '',
      crl_distribution_url: '',
      ocsp_responder_url: '',
      notes: '',
    }
    await loadCAs()
  } catch (err: any) {
    errorMessage.value = err.message
  } finally {
    submitting.value = false
  }
}

onMounted(() => {
  loadCAs()
})
</script>

<template>
  <div class="space-y-8">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <ShieldCheck class="w-7 h-7 text-indigo-400" />
          PKI & Certificate Authority Management
        </h2>
        <p class="text-sm text-slate-400 mt-1">
          Monitor Root and Intermediate CAs, inspect trust hierarchies, track validity expiration, and verify CRL/OCSP freshness.
        </p>
      </div>

      <div class="flex items-center gap-3">
        <button @click="loadCAs" class="btn-secondary">
          <RefreshCw class="w-4 h-4" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
        <button @click="showRegisterModal = true" class="btn-primary">
          <Plus class="w-4 h-4" />
          Register CA Authority
        </button>
      </div>
    </div>

    <!-- Trust Chain Tree Visualization -->
    <div class="glass-panel p-6 space-y-4">
      <div class="flex items-center justify-between border-b border-slate-800/80 pb-4">
        <div class="flex items-center gap-2">
          <GitFork class="w-5 h-5 text-indigo-400" />
          <h3 class="text-base font-semibold text-white">Trust Chain Hierarchy</h3>
        </div>
        <span class="text-xs text-slate-400">Root &rarr; Intermediate &rarr; Issuing CAs</span>
      </div>

      <div v-if="tree.length === 0" class="py-6 text-center text-sm text-slate-400">
        No hierarchy chains constructed yet. Register a Root CA and its intermediate subordinates below.
      </div>

      <div v-else class="space-y-4 pt-2">
        <div v-for="node in tree" :key="node.authority.id" class="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-3 h-3 rounded-full bg-emerald-500"></div>
              <div>
                <span class="font-bold text-white text-sm">{{ node.authority.name }}</span>
                <span class="text-xs text-slate-400 ml-2 font-mono">({{ node.authority.ca_type }})</span>
              </div>
            </div>
            <div class="text-xs font-mono text-emerald-400 font-bold">
              {{ node.authority.days_remaining }} days left
            </div>
          </div>

          <!-- Children Intermediates -->
          <div v-if="node.children && node.children.length > 0" class="mt-4 pl-6 border-l-2 border-indigo-500/30 space-y-3">
            <div v-for="child in node.children" :key="child.authority.id" class="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between">
              <div class="flex items-center gap-2.5">
                <div class="w-2.5 h-2.5 rounded-full bg-indigo-400"></div>
                <div>
                  <span class="font-semibold text-slate-200 text-xs">{{ child.authority.name }}</span>
                  <span class="text-[11px] text-slate-400 ml-2 font-mono">({{ child.authority.ca_type }})</span>
                </div>
              </div>
              <div class="text-xs font-mono text-indigo-300 font-medium">
                {{ child.authority.days_remaining }}d remaining
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- CA Authorities Inventory Table -->
    <div class="space-y-4">
      <h3 class="text-base font-semibold text-white">All Monitored Certificate Authorities</h3>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>CA Name & Type</th>
              <th>Subject DN</th>
              <th>Algorithm</th>
              <th>Validity Remaining</th>
              <th>Status</th>
              <th>CRL / OCSP</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="cas.length === 0">
              <td colspan="7" class="text-center py-8 text-slate-400">
                No CA authorities recorded yet. Click "Register CA Authority" above.
              </td>
            </tr>
            <tr v-for="ca in cas" :key="ca.id">
              <td>
                <div class="font-semibold text-white">{{ ca.name }}</div>
                <div class="text-xs text-slate-400 font-mono">{{ ca.ca_type }} CA</div>
              </td>
              <td class="font-mono text-xs text-slate-300 max-w-xs truncate" :title="ca.subject_dn">
                {{ ca.subject_dn }}
              </td>
              <td class="font-mono text-xs text-slate-400">
                {{ ca.key_type }} {{ ca.key_size }}
              </td>
              <td>
                <div class="font-mono font-bold text-xs" :class="ca.days_remaining <= 30 ? 'text-rose-400' : ca.days_remaining <= 180 ? 'text-amber-400' : 'text-emerald-400'">
                  {{ ca.days_remaining }} days
                </div>
                <div class="text-[11px] text-slate-400">Expires {{ new Date(ca.not_after).toLocaleDateString() }}</div>
              </td>
              <td>
                <span class="badge" :class="ca.status === 'HEALTHY' ? 'badge-healthy' : ca.status === 'WARNING' ? 'badge-warning' : 'badge-critical'">
                  {{ ca.status }}
                </span>
              </td>
              <td class="text-xs">
                <div class="flex items-center gap-1.5" :class="ca.is_crl_fresh ? 'text-emerald-400' : 'text-slate-400'">
                  <span>CRL: {{ ca.is_crl_fresh ? 'Fresh' : 'Unknown' }}</span>
                </div>
                <div class="flex items-center gap-1.5" :class="ca.is_ocsp_responsive ? 'text-emerald-400' : 'text-slate-400'">
                  <span>OCSP: {{ ca.is_ocsp_responsive ? 'Online' : 'Unknown' }}</span>
                </div>
              </td>
              <td>
                <div class="flex items-center gap-2">
                  <button @click="triggerHealthCheck(ca.id)" class="p-1.5 text-slate-400 hover:text-indigo-300 hover:bg-slate-800 rounded transition-colors" title="Check Health Now">
                    <Activity class="w-4 h-4" />
                  </button>
                  <button @click="deleteCA(ca.id)" class="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors" title="Delete CA">
                    <Trash2 class="w-4 h-4" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Register CA Authority Modal -->
    <div v-if="showRegisterModal" class="modal-backdrop">
      <div class="modal-content">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <h3 class="text-lg font-bold text-white">Register Certificate Authority</h3>
          <button @click="showRegisterModal = false" class="text-slate-400 hover:text-white">
            <X class="w-5 h-5" />
          </button>
        </div>

        <div v-if="errorMessage" class="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          {{ errorMessage }}
        </div>

        <form @submit.prevent="submitCA" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Authority Name</label>
            <input v-model="newCA.name" class="input-field" placeholder="e.g. Corporate Root CA 2026" required />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">CA Certificate (PEM Format)</label>
            <textarea 
              v-model="newCA.certificate_pem" 
              class="input-field font-mono text-xs h-36" 
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" 
              required
            ></textarea>
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Parent CA (Optional - for Intermediate CAs)</label>
            <select v-model="newCA.parent_ca_id" class="input-field">
              <option value="">None (Top-Level Root CA)</option>
              <option v-for="ca in cas" :key="ca.id" :value="ca.id">{{ ca.name }} ({{ ca.ca_type }})</option>
            </select>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">CRL Distribution URL</label>
              <input v-model="newCA.crl_distribution_url" class="input-field text-xs font-mono" placeholder="http://crl.example.com/ca.crl" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">OCSP Responder URL</label>
              <input v-model="newCA.ocsp_responder_url" class="input-field text-xs font-mono" placeholder="http://ocsp.example.com" />
            </div>
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Notes & Scope</label>
            <input v-model="newCA.notes" class="input-field" placeholder="Internal issuance for production Kubernetes clusters" />
          </div>

          <div class="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <button type="button" @click="showRegisterModal = false" class="btn-secondary">
              Cancel
            </button>
            <button type="submit" class="btn-primary" :disabled="submitting">
              {{ submitting ? 'Registering...' : 'Register CA' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
