<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import {
  Plus, Search, Download, RotateCw, Eye,
  CheckCircle, AlertTriangle, XCircle, Clock
} from 'lucide-vue-next'

const api = useApi()
const certificates = ref<any[]>([])
const loading = ref(true)
const searchQuery = ref('')
const filterStatus = ref('all')
const showRequestModal = ref(false)
const showDetailModal = ref(false)
const selectedCert = ref<any>(null)
const renewingId = ref<string | null>(null)

// Request form
const reqForm = ref({
  common_name: '',
  san_domains: '',
  ca_id: '',
  key_algorithm: 'RSA',
  key_size: '2048',
  validity_days: '365',
})

async function loadData() {
  loading.value = true
  try {
    const res = await api.get<any>('/api/v1/certificates').catch(() => ({ data: [] }))
    certificates.value = res.data || []
  } finally {
    loading.value = false
  }
}

async function requestCert() {
  try {
    await api.post('/api/v1/certificates', {
      common_name: reqForm.value.common_name,
      san_domains: reqForm.value.san_domains.split(',').map(d => d.trim()).filter(Boolean),
      ca_id: reqForm.value.ca_id || undefined,
      key_algorithm: reqForm.value.key_algorithm,
      key_size: parseInt(reqForm.value.key_size),
      validity_days: parseInt(reqForm.value.validity_days),
    })
    showRequestModal.value = false
    reqForm.value = { common_name: '', san_domains: '', ca_id: '', key_algorithm: 'RSA', key_size: '2048', validity_days: '365' }
    await loadData()
  } catch (err: any) {
    alert('Request failed: ' + (err.message || err))
  }
}

async function renewCert(cert: any) {
  renewingId.value = cert.id
  try {
    await api.post(`/api/v1/certificates/${cert.id}/renew`)
    await loadData()
  } catch (err: any) {
    alert('Renewal failed: ' + (err.message || err))
  } finally {
    renewingId.value = null
  }
}

function viewDetail(cert: any) {
  selectedCert.value = cert
  showDetailModal.value = true
}

// Demo certificates
const demoCerts = [
  { id: '1', common_name: 'api.certpilot.io', status: 'active', issuer: 'Root CA', key_algorithm: 'RSA-2048', not_before: '2026-01-15', not_after: '2027-01-15', serial: 'A1B2C3D4' },
  { id: '2', common_name: '*.internal.dev', status: 'active', issuer: 'ACME Issuer', key_algorithm: 'ECDSA-256', not_before: '2026-03-01', not_after: '2027-03-01', serial: 'E5F6G7H8' },
  { id: '3', common_name: 'vault.service.mesh', status: 'expiring', issuer: 'Vault Sub-CA', key_algorithm: 'RSA-4096', not_before: '2025-06-01', not_after: '2026-09-01', serial: 'I9J0K1L2' },
  { id: '4', common_name: 'auth.platform.io', status: 'active', issuer: 'Root CA', key_algorithm: 'RSA-2048', not_before: '2026-02-10', not_after: '2027-02-10', serial: 'M3N4O5P6' },
  { id: '5', common_name: 'legacy.app.internal', status: 'expired', issuer: 'Root CA', key_algorithm: 'RSA-2048', not_before: '2024-01-01', not_after: '2025-01-01', serial: 'Q7R8S9T0' },
  { id: '6', common_name: 'cdn.assets.io', status: 'active', issuer: 'ACME Issuer', key_algorithm: 'ECDSA-384', not_before: '2026-04-15', not_after: '2027-04-15', serial: 'U1V2W3X4' },
  { id: '7', common_name: 'monitoring.ops.net', status: 'active', issuer: 'GCP CAS', key_algorithm: 'ECDSA-256', not_before: '2026-05-20', not_after: '2027-05-20', serial: 'Y5Z6A7B8' },
  { id: '8', common_name: 'staging.preview.io', status: 'expiring', issuer: 'Root CA', key_algorithm: 'RSA-2048', not_before: '2025-09-01', not_after: '2026-09-15', serial: 'C9D0E1F2' },
]

const displayCerts = computed(() => {
  const src = certificates.value.length ? certificates.value : demoCerts
  return src.filter(c => {
    const matchSearch = !searchQuery.value || (c.common_name || '').toLowerCase().includes(searchQuery.value.toLowerCase())
    const matchStatus = filterStatus.value === 'all' || c.status === filterStatus.value
    return matchSearch && matchStatus
  })
})

const statusCounts = computed(() => {
  const src = certificates.value.length ? certificates.value : demoCerts
  return {
    all: src.length,
    active: src.filter(c => c.status === 'active').length,
    expiring: src.filter(c => c.status === 'expiring').length,
    expired: src.filter(c => c.status === 'expired').length,
  }
})

function getStatusBadge(status: string) {
  switch (status?.toLowerCase()) {
    case 'active': return 'badge-success'
    case 'expiring': return 'badge-warning'
    case 'expired': return 'badge-error'
    case 'revoked': return 'badge-error'
    default: return 'badge-ghost'
  }
}

function getStatusIcon(status: string) {
  switch (status?.toLowerCase()) {
    case 'active': return CheckCircle
    case 'expiring': return AlertTriangle
    case 'expired': return XCircle
    default: return Clock
  }
}

function daysUntil(d: string) {
  if (!d) return 0
  return Math.ceil((new Date(d).getTime() - Date.now()) / 86400000)
}

function formatDate(d: string) {
  if (!d) return '—'
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

onMounted(() => loadData())
</script>

<template>
  <div class="space-y-5">
    <!-- Status Stats -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <button
        v-for="s in [
          { key: 'all', label: 'All Certificates', color: 'text-base-content' },
          { key: 'active', label: 'Active', color: 'text-success' },
          { key: 'expiring', label: 'Expiring', color: 'text-warning' },
          { key: 'expired', label: 'Expired', color: 'text-error' },
        ]"
        :key="s.key"
        @click="filterStatus = s.key"
        class="stat bg-base-100 rounded-xl border cursor-pointer transition-all hover:shadow-md p-4"
        :class="filterStatus === s.key ? 'border-primary shadow-sm' : 'border-base-300'"
      >
        <div class="stat-title text-xs">{{ s.label }}</div>
        <div class="stat-value text-xl" :class="s.color">{{ statusCounts[s.key as keyof typeof statusCounts] }}</div>
      </button>
    </div>

    <!-- Toolbar -->
    <div class="flex items-center justify-between gap-4">
      <label class="input input-bordered input-sm flex items-center gap-2 w-72 bg-base-100">
        <Search class="w-3.5 h-3.5 opacity-50" />
        <input v-model="searchQuery" type="text" class="grow" placeholder="Search by common name…" />
      </label>
      <div class="flex items-center gap-2">
        <button class="btn btn-ghost btn-sm gap-1.5">
          <Download class="w-3.5 h-3.5" /> Export
        </button>
        <button class="btn btn-primary btn-sm gap-1.5" @click="showRequestModal = true">
          <Plus class="w-3.5 h-3.5" /> Request Certificate
        </button>
      </div>
    </div>

    <!-- Certificates Table -->
    <div class="card bg-base-100 border border-base-300">
      <div class="overflow-x-auto">
        <table class="table table-sm table-zebra">
          <thead>
            <tr>
              <th class="text-xs">Common Name</th>
              <th class="text-xs">Issuer</th>
              <th class="text-xs">Algorithm</th>
              <th class="text-xs">Expires</th>
              <th class="text-xs">Days Left</th>
              <th class="text-xs">Status</th>
              <th class="text-xs text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading">
              <td colspan="7" class="text-center py-8">
                <span class="loading loading-spinner loading-md text-primary"></span>
              </td>
            </tr>
            <tr v-else-if="!displayCerts.length">
              <td colspan="7" class="text-center py-8 text-base-content/60 text-sm">
                No certificates found
              </td>
            </tr>
            <tr v-for="cert in displayCerts" :key="cert.id" class="hover:bg-base-200/50">
              <td class="font-mono text-xs font-medium">{{ cert.common_name }}</td>
              <td class="text-xs">{{ cert.issuer || '—' }}</td>
              <td class="text-xs font-mono">{{ cert.key_algorithm || '—' }}</td>
              <td class="text-xs font-mono">{{ formatDate(cert.not_after) }}</td>
              <td class="text-xs font-mono">
                <span :class="daysUntil(cert.not_after) < 30 ? 'text-warning font-bold' : daysUntil(cert.not_after) < 0 ? 'text-error font-bold' : ''">
                  {{ daysUntil(cert.not_after) }}d
                </span>
              </td>
              <td>
                <span class="badge badge-sm" :class="getStatusBadge(cert.status)">{{ cert.status }}</span>
              </td>
              <td class="text-right">
                <div class="flex items-center justify-end gap-1">
                  <button class="btn btn-ghost btn-xs" @click="viewDetail(cert)">
                    <Eye class="w-3.5 h-3.5" />
                  </button>
                  <button
                    class="btn btn-ghost btn-xs"
                    :disabled="renewingId === cert.id"
                    @click="renewCert(cert)"
                  >
                    <RotateCw class="w-3.5 h-3.5" :class="{ 'animate-spin': renewingId === cert.id }" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Request Certificate Modal -->
    <dialog class="modal" :class="{ 'modal-open': showRequestModal }">
      <div class="modal-box max-w-md">
        <h3 class="text-base font-bold mb-4">Request Certificate</h3>
        <form @submit.prevent="requestCert" class="space-y-3">
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Common Name (FQDN)</span></label>
            <input v-model="reqForm.common_name" type="text" placeholder="e.g. api.example.com" class="input input-bordered input-sm" required />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">SAN Domains (comma-separated)</span></label>
            <input v-model="reqForm.san_domains" type="text" placeholder="e.g. www.example.com, mail.example.com" class="input input-bordered input-sm" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div class="form-control">
              <label class="label"><span class="label-text text-xs">Algorithm</span></label>
              <select v-model="reqForm.key_algorithm" class="select select-bordered select-sm">
                <option value="RSA">RSA</option>
                <option value="ECDSA">ECDSA</option>
              </select>
            </div>
            <div class="form-control">
              <label class="label"><span class="label-text text-xs">Key Size</span></label>
              <select v-model="reqForm.key_size" class="select select-bordered select-sm">
                <option value="2048">2048</option>
                <option value="4096">4096</option>
              </select>
            </div>
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Validity (Days)</span></label>
            <input v-model="reqForm.validity_days" type="number" min="1" max="3650" class="input input-bordered input-sm" />
          </div>
          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" @click="showRequestModal = false">Cancel</button>
            <button type="submit" class="btn btn-primary btn-sm">Submit Request</button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showRequestModal = false"><button>close</button></form>
    </dialog>

    <!-- Certificate Detail Modal -->
    <dialog class="modal" :class="{ 'modal-open': showDetailModal }">
      <div class="modal-box max-w-lg" v-if="selectedCert">
        <h3 class="text-base font-bold mb-4 font-mono">{{ selectedCert.common_name }}</h3>
        <div class="grid grid-cols-2 gap-4 text-xs">
          <div>
            <div class="text-base-content/60 mb-1">Status</div>
            <span class="badge badge-sm" :class="getStatusBadge(selectedCert.status)">{{ selectedCert.status }}</span>
          </div>
          <div>
            <div class="text-base-content/60 mb-1">Serial</div>
            <div class="font-mono">{{ selectedCert.serial || selectedCert.serial_number || '—' }}</div>
          </div>
          <div>
            <div class="text-base-content/60 mb-1">Issuer</div>
            <div>{{ selectedCert.issuer || '—' }}</div>
          </div>
          <div>
            <div class="text-base-content/60 mb-1">Algorithm</div>
            <div class="font-mono">{{ selectedCert.key_algorithm || '—' }}</div>
          </div>
          <div>
            <div class="text-base-content/60 mb-1">Issued</div>
            <div class="font-mono">{{ formatDate(selectedCert.not_before) }}</div>
          </div>
          <div>
            <div class="text-base-content/60 mb-1">Expires</div>
            <div class="font-mono">{{ formatDate(selectedCert.not_after) }}</div>
          </div>
        </div>
        <div v-if="selectedCert.pem_certificate" class="mt-4">
          <div class="text-xs text-base-content/60 mb-1">PEM Certificate</div>
          <pre class="bg-base-200 rounded-lg p-3 text-[10px] font-mono overflow-x-auto max-h-40">{{ selectedCert.pem_certificate }}</pre>
        </div>
        <div class="modal-action">
          <button class="btn btn-ghost btn-sm" @click="showDetailModal = false">Close</button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showDetailModal = false"><button>close</button></form>
    </dialog>
  </div>
</template>
