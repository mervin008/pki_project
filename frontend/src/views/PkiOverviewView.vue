<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import DoughnutChart from '@/components/charts/DoughnutChart.vue'
import {
  ShieldCheck, Plus, ChevronDown, ChevronRight,
  Lock, Globe, Server, KeyRound
} from 'lucide-vue-next'

const api = useApi()
const authorities = ref<any[]>([])
const loading = ref(true)
const showCreateModal = ref(false)
const expandedCa = ref<string | null>(null)

// Create form
const form = ref({
  common_name: '',
  organization: '',
  country: 'US',
  key_algorithm: 'RSA',
  key_size: '4096',
  validity_years: '10',
  ca_type: 'root',
})

async function loadData() {
  loading.value = true
  try {
    const res = await api.get<any>('/api/v1/pki/authorities').catch(() => ({ data: [] }))
    authorities.value = res.data || []
  } finally {
    loading.value = false
  }
}

async function createCA() {
  try {
    await api.post('/api/v1/pki/authorities', {
      common_name: form.value.common_name,
      organization: form.value.organization,
      country: form.value.country,
      key_algorithm: form.value.key_algorithm,
      key_size: parseInt(form.value.key_size),
      validity_years: parseInt(form.value.validity_years),
      ca_type: form.value.ca_type,
    })
    showCreateModal.value = false
    form.value = { common_name: '', organization: '', country: 'US', key_algorithm: 'RSA', key_size: '4096', validity_years: '10', ca_type: 'root' }
    await loadData()
  } catch (err: any) {
    alert('Failed to create CA: ' + (err.message || err))
  }
}

function toggleExpand(id: string) {
  expandedCa.value = expandedCa.value === id ? null : id
}

function daysUntil(d: string) {
  if (!d) return 0
  return Math.ceil((new Date(d).getTime() - Date.now()) / 86400000)
}

function getStatusBadge(status: string) {
  switch (status?.toLowerCase()) {
    case 'active': case 'healthy': return 'badge-success'
    case 'expiring': case 'warning': return 'badge-warning'
    case 'expired': case 'critical': return 'badge-error'
    default: return 'badge-ghost'
  }
}

function getTypeIcon(type: string) {
  switch (type?.toLowerCase()) {
    case 'root': return Lock
    case 'intermediate': return Server
    case 'external': return Globe
    default: return ShieldCheck
  }
}

// Demo CAs for fallback
const demoCAs = [
  { id: '1', common_name: 'CertPilot Root CA', ca_type: 'root', key_algorithm: 'RSA', key_size: 4096, status: 'active', not_after: '2035-01-15', organization: 'CertPilot Inc', certs_issued: 24 },
  { id: '2', common_name: 'ACME Issuing CA', ca_type: 'intermediate', key_algorithm: 'ECDSA', key_size: 256, status: 'active', not_after: '2028-06-20', organization: 'CertPilot Inc', certs_issued: 18 },
  { id: '3', common_name: 'Vault Sub-CA', ca_type: 'intermediate', key_algorithm: 'RSA', key_size: 2048, status: 'expiring', not_after: '2026-11-10', organization: 'HashiCorp Vault', certs_issued: 12 },
  { id: '4', common_name: 'GCP CAS Authority', ca_type: 'external', key_algorithm: 'ECDSA', key_size: 384, status: 'active', not_after: '2030-03-01', organization: 'Google Cloud', certs_issued: 6 },
]

const displayCAs = ref<any[]>([])

onMounted(async () => {
  await loadData()
  displayCAs.value = authorities.value.length ? authorities.value : demoCAs
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header + Action -->
    <div class="flex items-center justify-between">
      <div>
        <p class="text-sm text-base-content/60">Manage your Certificate Authority hierarchy and trust chains</p>
      </div>
      <button class="btn btn-primary btn-sm gap-2" @click="showCreateModal = true">
        <Plus class="w-4 h-4" /> Create CA
      </button>
    </div>

    <!-- Loading -->
    <div v-if="loading" class="flex justify-center py-12">
      <span class="loading loading-spinner loading-lg text-primary"></span>
    </div>

    <!-- Stats Row -->
    <div v-else class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
        <div class="stat-title text-xs">Total CAs</div>
        <div class="stat-value text-xl">{{ displayCAs.length }}</div>
      </div>
      <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
        <div class="stat-title text-xs">Root CAs</div>
        <div class="stat-value text-xl">{{ displayCAs.filter(c => c.ca_type === 'root').length }}</div>
      </div>
      <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
        <div class="stat-title text-xs">Intermediates</div>
        <div class="stat-value text-xl">{{ displayCAs.filter(c => c.ca_type === 'intermediate').length }}</div>
      </div>
      <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
        <div class="stat-title text-xs">External</div>
        <div class="stat-value text-xl">{{ displayCAs.filter(c => c.ca_type === 'external').length }}</div>
      </div>
    </div>

    <!-- CA Cards -->
    <div v-if="!loading" class="space-y-3">
      <div
        v-for="ca in displayCAs"
        :key="ca.id"
        class="card bg-base-100 border border-base-300"
      >
        <div class="card-body p-4">
          <div class="flex items-center justify-between cursor-pointer" @click="toggleExpand(ca.id)">
            <div class="flex items-center gap-3">
              <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
                <component :is="getTypeIcon(ca.ca_type)" class="w-4 h-4 text-primary" />
              </div>
              <div>
                <div class="font-bold text-sm font-mono">{{ ca.common_name }}</div>
                <div class="text-[11px] text-base-content/60">{{ ca.organization }} · {{ ca.key_algorithm }}-{{ ca.key_size }}</div>
              </div>
            </div>
            <div class="flex items-center gap-3">
              <span class="badge badge-sm" :class="getStatusBadge(ca.status)">{{ ca.status }}</span>
              <span class="text-xs font-mono text-base-content/60">{{ daysUntil(ca.not_after) }}d remaining</span>
              <ChevronDown v-if="expandedCa === ca.id" class="w-4 h-4 opacity-50" />
              <ChevronRight v-else class="w-4 h-4 opacity-50" />
            </div>
          </div>

          <!-- Expanded Details -->
          <div v-if="expandedCa === ca.id" class="mt-4 pt-4 border-t border-base-300 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <div class="text-base-content/60 mb-1">Type</div>
              <div class="font-medium capitalize">{{ ca.ca_type }}</div>
            </div>
            <div>
              <div class="text-base-content/60 mb-1">Algorithm</div>
              <div class="font-mono">{{ ca.key_algorithm }}-{{ ca.key_size }}</div>
            </div>
            <div>
              <div class="text-base-content/60 mb-1">Valid Until</div>
              <div class="font-mono">{{ ca.not_after || '—' }}</div>
            </div>
            <div>
              <div class="text-base-content/60 mb-1">Certs Issued</div>
              <div class="font-bold">{{ ca.certs_issued || 0 }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create CA Modal -->
    <dialog class="modal" :class="{ 'modal-open': showCreateModal }">
      <div class="modal-box max-w-md">
        <h3 class="text-base font-bold mb-4">Create Certificate Authority</h3>
        <form @submit.prevent="createCA" class="space-y-3">
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Common Name</span></label>
            <input v-model="form.common_name" type="text" placeholder="e.g. My Root CA" class="input input-bordered input-sm" required />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Organization</span></label>
            <input v-model="form.organization" type="text" placeholder="e.g. Acme Corp" class="input input-bordered input-sm" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div class="form-control">
              <label class="label"><span class="label-text text-xs">CA Type</span></label>
              <select v-model="form.ca_type" class="select select-bordered select-sm">
                <option value="root">Root</option>
                <option value="intermediate">Intermediate</option>
              </select>
            </div>
            <div class="form-control">
              <label class="label"><span class="label-text text-xs">Country</span></label>
              <input v-model="form.country" type="text" class="input input-bordered input-sm" maxlength="2" />
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div class="form-control">
              <label class="label"><span class="label-text text-xs">Algorithm</span></label>
              <select v-model="form.key_algorithm" class="select select-bordered select-sm">
                <option value="RSA">RSA</option>
                <option value="ECDSA">ECDSA</option>
              </select>
            </div>
            <div class="form-control">
              <label class="label"><span class="label-text text-xs">Key Size</span></label>
              <select v-model="form.key_size" class="select select-bordered select-sm">
                <option value="2048">2048</option>
                <option value="4096">4096</option>
              </select>
            </div>
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Validity (Years)</span></label>
            <input v-model="form.validity_years" type="number" min="1" max="30" class="input input-bordered input-sm" />
          </div>
          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" @click="showCreateModal = false">Cancel</button>
            <button type="submit" class="btn btn-primary btn-sm">Create CA</button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showCreateModal = false">
        <button>close</button>
      </form>
    </dialog>
  </div>
</template>
