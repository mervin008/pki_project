<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useApi } from '@/composables/useApi'
import { 
  KeyRound, 
  Plus, 
  RefreshCw, 
  Search, 
  Filter, 
  RotateCw, 
  Trash2, 
  X,
  FileCode,
  CheckCircle2,
  AlertCircle
} from 'lucide-vue-next'

const api = useApi()
const certificates = ref<any[]>([])
const caAccounts = ref<any[]>([])
const loading = ref(true)
const search = ref('')
const statusFilter = ref('')

const showRequestModal = ref(false)
const showDetailModal = ref(false)
const selectedCert = ref<any>(null)

const newCert = ref({
  common_name: '',
  sans_input: '',
  ca_account_id: '',
  key_type: 'RSA',
  key_size: 2048,
  validity_days: 90,
  environment: 'production',
  team: 'Platform Engineering',
  auto_renew: true,
  renewal_lead_days: 30,
})

const submitting = ref(false)
const renewingId = ref<string | null>(null)
const errorMessage = ref('')

async function loadData() {
  loading.value = true
  try {
    const [certsRes, caAccRes] = await Promise.all([
      api.get<any>('/api/v1/certificates').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/ca-accounts').catch(() => ({ data: [] })),
    ])
    certificates.value = certsRes.data || []
    caAccounts.value = caAccRes.data || []

    if (caAccounts.value.length > 0 && !newCert.value.ca_account_id) {
      newCert.value.ca_account_id = caAccounts.value[0].id
    }
  } finally {
    loading.value = false
  }
}

const filteredCerts = computed(() => {
  return certificates.value.filter(c => {
    const matchesSearch = !search.value || 
      c.common_name.toLowerCase().includes(search.value.toLowerCase()) ||
      (c.sans && c.sans.some((s: string) => s.toLowerCase().includes(search.value.toLowerCase())))
    const matchesStatus = !statusFilter.value || c.status === statusFilter.value
    return matchesSearch && matchesStatus
  })
})

async function submitRequest() {
  submitting.value = true
  errorMessage.value = ''
  try {
    const sans = newCert.value.sans_input
      ? newCert.value.sans_input.split(',').map(s => s.trim()).filter(Boolean)
      : []

    const payload = {
      ...newCert.value,
      sans,
    }

    await api.post('/api/v1/certificates', payload)
    showRequestModal.value = false
    newCert.value.common_name = ''
    newCert.value.sans_input = ''
    await loadData()
  } catch (err: any) {
    errorMessage.value = err.message
  } finally {
    submitting.value = false
  }
}

async function triggerRenew(cert: any) {
  renewingId.value = cert.id
  try {
    await api.post(`/api/v1/certificates/${cert.id}/renew`)
    await loadData()
  } catch (err: any) {
    alert('Renewal failed: ' + err.message)
  } finally {
    renewingId.value = null
  }
}

async function deleteCert(id: string) {
  if (!confirm('Are you sure you want to delete this certificate?')) return
  try {
    await api.delete(`/api/v1/certificates/${id}`)
    await loadData()
  } catch (err: any) {
    alert('Delete failed: ' + err.message)
  }
}

function viewDetail(cert: any) {
  selectedCert.value = cert
  showDetailModal.value = true
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
          <KeyRound class="w-7 h-7 text-indigo-400" />
          Managed Certificates Inventory
        </h2>
        <p class="text-sm text-slate-400 mt-1">
          Automated issuance, auto-renewal pipelines, and lifecycle visibility across public and private CAs.
        </p>
      </div>

      <div class="flex items-center gap-3">
        <button @click="loadData" class="btn-secondary">
          <RefreshCw class="w-4 h-4" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
        <button @click="showRequestModal = true" class="btn-primary">
          <Plus class="w-4 h-4" />
          Request Certificate
        </button>
      </div>
    </div>

    <!-- Filters and Search Bar -->
    <div class="flex items-center justify-between gap-4">
      <div class="relative flex-1 max-w-md">
        <Search class="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
        <input 
          v-model="search" 
          type="text" 
          placeholder="Search by Common Name or SAN (e.g. api.example.com)..." 
          class="input-field pl-10"
        />
      </div>

      <div class="flex items-center gap-3">
        <select v-model="statusFilter" class="input-field w-44 text-xs font-medium">
          <option value="">All Statuses</option>
          <option value="ISSUED">Issued (Valid)</option>
          <option value="EXPIRING">Expiring Soon</option>
          <option value="RENEWAL_FAILED">Renewal Failed</option>
          <option value="EXPIRED">Expired</option>
        </select>
      </div>
    </div>

    <!-- Certificates Table -->
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Common Name & SANs</th>
            <th>Environment</th>
            <th>Algorithm</th>
            <th>Validity Remaining</th>
            <th>Status</th>
            <th>Auto-Renew</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="filteredCerts.length === 0">
            <td colspan="7" class="text-center py-10 text-slate-400">
              No certificates found matching your criteria.
            </td>
          </tr>
          <tr v-for="cert in filteredCerts" :key="cert.id">
            <td>
              <div class="font-semibold text-white cursor-pointer hover:text-indigo-300" @click="viewDetail(cert)">
                {{ cert.common_name }}
              </div>
              <div v-if="cert.sans && cert.sans.length > 0" class="text-[11px] text-slate-400 truncate max-w-xs font-mono">
                + {{ cert.sans.join(', ') }}
              </div>
            </td>
            <td>
              <span class="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {{ cert.environment || 'prod' }}
              </span>
            </td>
            <td class="font-mono text-xs text-slate-400">
              {{ cert.key_type }} {{ cert.key_size }}
            </td>
            <td>
              <div class="font-mono font-bold text-xs" :class="cert.days_remaining <= 30 ? 'text-amber-400' : 'text-emerald-400'">
                {{ cert.days_remaining }} days
              </div>
              <div v-if="cert.not_after" class="text-[11px] text-slate-400">
                Expires {{ new Date(cert.not_after).toLocaleDateString() }}
              </div>
            </td>
            <td>
              <span class="badge" :class="cert.status === 'ISSUED' ? 'badge-healthy' : cert.status === 'EXPIRING' ? 'badge-warning' : 'badge-critical'">
                {{ cert.status }}
              </span>
            </td>
            <td>
              <div class="flex items-center gap-1.5 text-xs" :class="cert.auto_renew ? 'text-emerald-400' : 'text-slate-400'">
                <span class="w-2 h-2 rounded-full" :class="cert.auto_renew ? 'bg-emerald-500' : 'bg-slate-600'"></span>
                <span>{{ cert.auto_renew ? `${cert.renewal_lead_days || 30}d lead` : 'Disabled' }}</span>
              </div>
            </td>
            <td>
              <div class="flex items-center gap-2">
                <button 
                  @click="triggerRenew(cert)" 
                  class="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition-colors"
                  :disabled="renewingId === cert.id"
                  title="Renew Now"
                >
                  <RotateCw class="w-4 h-4" :class="{ 'animate-spin text-emerald-400': renewingId === cert.id }" />
                </button>
                <button 
                  @click="viewDetail(cert)" 
                  class="p-1.5 text-slate-400 hover:text-indigo-400 hover:bg-slate-800 rounded transition-colors"
                  title="View Certificate Details"
                >
                  <FileCode class="w-4 h-4" />
                </button>
                <button 
                  @click="deleteCert(cert.id)" 
                  class="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
                  title="Delete Certificate"
                >
                  <Trash2 class="w-4 h-4" />
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Request Certificate Modal -->
    <div v-if="showRequestModal" class="modal-backdrop">
      <div class="modal-content">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <h3 class="text-lg font-bold text-white">Request / Issue Certificate</h3>
          <button @click="showRequestModal = false" class="text-slate-400 hover:text-white">
            <X class="w-5 h-5" />
          </button>
        </div>

        <div v-if="errorMessage" class="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
          {{ errorMessage }}
        </div>

        <form @submit.prevent="submitRequest" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Common Name (Primary Domain)</label>
            <input v-model="newCert.common_name" class="input-field font-mono" placeholder="app.example.com" required />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Subject Alternative Names (Comma Separated)</label>
            <input v-model="newCert.sans_input" class="input-field font-mono" placeholder="api.example.com, www.example.com" />
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">CA Provider / Account</label>
              <select v-model="newCert.ca_account_id" class="input-field" required>
                <option v-for="acc in caAccounts" :key="acc.id" :value="acc.id">
                  {{ acc.name }} ({{ acc.provider_type }})
                </option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">Environment</label>
              <select v-model="newCert.environment" class="input-field">
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
          </div>

          <div class="grid grid-cols-3 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">Key Type</label>
              <select v-model="newCert.key_type" class="input-field">
                <option value="RSA">RSA</option>
                <option value="ECDSA">ECDSA</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">Key Size</label>
              <select v-model="newCert.key_size" class="input-field">
                <option :value="2048">2048 bits</option>
                <option :value="4096">4096 bits</option>
                <option :value="256">256 bits (EC)</option>
                <option :value="384">384 bits (EC)</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">Validity Days</label>
              <input v-model.number="newCert.validity_days" type="number" class="input-field" min="1" max="398" />
            </div>
          </div>

          <div class="flex items-center gap-3 pt-2">
            <input type="checkbox" id="auto_renew" v-model="newCert.auto_renew" class="rounded bg-slate-800 border-slate-700 text-indigo-600 focus:ring-indigo-500 h-4 w-4" />
            <label for="auto_renew" class="text-xs text-slate-300 font-medium">Enable Automated Renewal (30 days before expiration)</label>
          </div>

          <div class="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <button type="button" @click="showRequestModal = false" class="btn-secondary">
              Cancel
            </button>
            <button type="submit" class="btn-primary" :disabled="submitting">
              {{ submitting ? 'Issuing via Gateway...' : 'Issue Certificate' }}
            </button>
          </div>
        </form>
      </div>
    </div>

    <!-- Certificate Details Modal -->
    <div v-if="showDetailModal && selectedCert" class="modal-backdrop">
      <div class="modal-content max-w-3xl">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <div>
            <h3 class="text-lg font-bold text-white">{{ selectedCert.common_name }}</h3>
            <span class="text-xs text-slate-400 font-mono">{{ selectedCert.fingerprint_sha256 }}</span>
          </div>
          <button @click="showDetailModal = false" class="text-slate-400 hover:text-white">
            <X class="w-5 h-5" />
          </button>
        </div>

        <div class="space-y-4 text-xs">
          <div class="grid grid-cols-2 gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
            <div>
              <span class="text-slate-400 block mb-0.5">Serial Number</span>
              <span class="font-mono text-slate-200">{{ selectedCert.serial_number || 'N/A' }}</span>
            </div>
            <div>
              <span class="text-slate-400 block mb-0.5">Issuer DN</span>
              <span class="font-mono text-slate-200 truncate block">{{ selectedCert.issuer_dn || 'N/A' }}</span>
            </div>
            <div>
              <span class="text-slate-400 block mb-0.5">Not Before</span>
              <span class="font-mono text-slate-200">{{ selectedCert.not_before ? new Date(selectedCert.not_before).toLocaleString() : 'N/A' }}</span>
            </div>
            <div>
              <span class="text-slate-400 block mb-0.5">Not After</span>
              <span class="font-mono text-slate-200">{{ selectedCert.not_after ? new Date(selectedCert.not_after).toLocaleString() : 'N/A' }}</span>
            </div>
          </div>

          <div v-if="selectedCert.certificate_pem">
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Certificate PEM</label>
            <textarea 
              readonly 
              class="input-field font-mono text-[11px] h-44 select-all" 
              :value="selectedCert.certificate_pem"
            ></textarea>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
