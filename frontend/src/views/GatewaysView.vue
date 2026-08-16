<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import { Cpu, Plus, CheckCircle, XCircle, Server, Globe } from 'lucide-vue-next'

const api = useApi()
const gateways = ref<any[]>([])
const accounts = ref<any[]>([])
const loading = ref(true)
const showAddModal = ref(false)

const form = ref({
  gateway_type: 'acme',
  name: '',
  server_url: '',
  email: '',
  credentials: '',
})

const demoGateways = [
  { type: 'acme', name: "Let's Encrypt", status: 'connected', url: 'https://acme-v02.api.letsencrypt.org/directory', accounts: 2 },
  { type: 'vault', name: 'HashiCorp Vault', status: 'connected', url: 'https://vault.internal:8200', accounts: 1 },
  { type: 'gcp', name: 'GCP CAS', status: 'disconnected', url: 'projects/my-project/locations/us-east1', accounts: 0 },
]

async function loadData() {
  loading.value = true
  try {
    const [gwRes, accRes] = await Promise.all([
      api.get<any>('/api/v1/gateways').catch(() => ({ data: [] })),
      api.get<any>('/api/v1/gateways/accounts').catch(() => ({ data: [] })),
    ])
    gateways.value = gwRes.data || []
    accounts.value = accRes.data || []
  } finally {
    loading.value = false
  }
}

async function addAccount() {
  try {
    await api.post('/api/v1/gateways/accounts', {
      gateway_type: form.value.gateway_type,
      name: form.value.name,
      server_url: form.value.server_url,
      email: form.value.email,
    })
    showAddModal.value = false
    form.value = { gateway_type: 'acme', name: '', server_url: '', email: '', credentials: '' }
    await loadData()
  } catch (err: any) {
    alert('Failed: ' + (err.message || err))
  }
}

function getGatewayIcon(type: string) {
  switch (type) {
    case 'vault': return Server
    case 'gcp': return Globe
    default: return Cpu
  }
}

onMounted(() => loadData())
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <p class="text-sm text-base-content/60">Connect external CA providers and manage gateway accounts</p>
      <button class="btn btn-primary btn-sm gap-2" @click="showAddModal = true">
        <Plus class="w-4 h-4" /> Add Account
      </button>
    </div>

    <div v-if="loading" class="flex justify-center py-12">
      <span class="loading loading-spinner loading-lg text-primary"></span>
    </div>

    <!-- Gateway Cards -->
    <div v-else class="grid grid-cols-1 md:grid-cols-3 gap-4">
      <div
        v-for="gw in (gateways.length ? gateways : demoGateways)"
        :key="gw.name"
        class="card bg-base-100 border border-base-300"
      >
        <div class="card-body p-5">
          <div class="flex items-center gap-3 mb-3">
            <div class="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
              <component :is="getGatewayIcon(gw.type)" class="w-5 h-5 text-primary" />
            </div>
            <div class="flex-1">
              <div class="font-bold text-sm">{{ gw.name }}</div>
              <div class="text-[11px] font-mono text-base-content/60 uppercase">{{ gw.type }}</div>
            </div>
            <span class="badge badge-sm" :class="gw.status === 'connected' ? 'badge-success' : 'badge-error'">
              {{ gw.status }}
            </span>
          </div>
          <div class="text-xs space-y-1.5">
            <div class="flex justify-between">
              <span class="text-base-content/60">Endpoint</span>
              <span class="font-mono text-[11px] truncate max-w-[180px]">{{ gw.url }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-base-content/60">Accounts</span>
              <span class="font-mono">{{ gw.accounts }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- CA Accounts Table -->
    <div v-if="!loading" class="card bg-base-100 border border-base-300">
      <div class="card-body p-5">
        <h2 class="card-title text-sm font-bold mb-3">CA Accounts</h2>
        <div class="overflow-x-auto">
          <table class="table table-sm table-zebra">
            <thead>
              <tr>
                <th class="text-xs">Account Name</th>
                <th class="text-xs">Gateway</th>
                <th class="text-xs">Server URL</th>
                <th class="text-xs">Status</th>
              </tr>
            </thead>
            <tbody>
              <template v-if="accounts.length">
                <tr v-for="acc in accounts" :key="acc.id">
                  <td class="font-mono text-xs">{{ acc.name }}</td>
                  <td class="text-xs capitalize">{{ acc.gateway_type }}</td>
                  <td class="text-xs font-mono truncate max-w-[200px]">{{ acc.server_url }}</td>
                  <td><span class="badge badge-sm badge-success">Active</span></td>
                </tr>
              </template>
              <template v-else>
                <tr>
                  <td class="font-mono text-xs">LE Production</td>
                  <td class="text-xs">ACME</td>
                  <td class="text-xs font-mono">acme-v02.api.letsencrypt.org</td>
                  <td><span class="badge badge-sm badge-success">Active</span></td>
                </tr>
                <tr>
                  <td class="font-mono text-xs">Vault PKI Mount</td>
                  <td class="text-xs">Vault</td>
                  <td class="text-xs font-mono">vault.internal:8200</td>
                  <td><span class="badge badge-sm badge-success">Active</span></td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Add Account Modal -->
    <dialog class="modal" :class="{ 'modal-open': showAddModal }">
      <div class="modal-box max-w-md">
        <h3 class="text-base font-bold mb-4">Add Gateway Account</h3>
        <form @submit.prevent="addAccount" class="space-y-3">
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Gateway Type</span></label>
            <select v-model="form.gateway_type" class="select select-bordered select-sm">
              <option value="acme">ACME (Let's Encrypt)</option>
              <option value="vault">HashiCorp Vault</option>
              <option value="gcp">GCP Certificate Authority Service</option>
              <option value="selfsigned">Self-Signed</option>
            </select>
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Account Name</span></label>
            <input v-model="form.name" type="text" placeholder="e.g. LE Production" class="input input-bordered input-sm" required />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Server URL</span></label>
            <input v-model="form.server_url" type="text" placeholder="https://acme-v02.api.letsencrypt.org/directory" class="input input-bordered input-sm" />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Email</span></label>
            <input v-model="form.email" type="email" placeholder="admin@example.com" class="input input-bordered input-sm" />
          </div>
          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" @click="showAddModal = false">Cancel</button>
            <button type="submit" class="btn btn-primary btn-sm">Add Account</button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showAddModal = false"><button>close</button></form>
    </dialog>
  </div>
</template>
