<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import { Sliders, Plus, CheckCircle, XCircle } from 'lucide-vue-next'

const api = useApi()
const policies = ref<any[]>([])
const loading = ref(true)
const showCreateModal = ref(false)

const form = ref({
  name: '',
  description: '',
  type: 'key_strength',
  min_key_size: '2048',
  allowed_algorithms: 'RSA,ECDSA',
  max_validity_days: '365',
  enforce: true,
})

const demoPolicies = [
  { id: '1', name: 'Minimum RSA 2048', description: 'Require all RSA keys to be at least 2048 bits', type: 'key_strength', enforce: true, violations: 0 },
  { id: '2', name: 'Max Validity 1 Year', description: 'Certificate validity must not exceed 365 days', type: 'validity', enforce: true, violations: 2 },
  { id: '3', name: 'ECDSA Preferred', description: 'Prefer ECDSA over RSA for new certificates', type: 'algorithm', enforce: false, violations: 0 },
  { id: '4', name: 'Auto-Renewal at 30d', description: 'Auto-renew certificates expiring within 30 days', type: 'renewal', enforce: true, violations: 0 },
]

async function loadData() {
  loading.value = true
  try {
    const res = await api.get<any>('/api/v1/policies').catch(() => ({ data: [] }))
    policies.value = res.data || []
  } finally {
    loading.value = false
  }
}

async function createPolicy() {
  try {
    await api.post('/api/v1/policies', form.value)
    showCreateModal.value = false
    form.value = { name: '', description: '', type: 'key_strength', min_key_size: '2048', allowed_algorithms: 'RSA,ECDSA', max_validity_days: '365', enforce: true }
    await loadData()
  } catch (err: any) {
    alert('Failed: ' + (err.message || err))
  }
}

onMounted(() => loadData())
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <p class="text-sm text-base-content/60">Define and enforce certificate issuance policies</p>
      <button class="btn btn-primary btn-sm gap-2" @click="showCreateModal = true">
        <Plus class="w-4 h-4" /> Create Policy
      </button>
    </div>

    <div v-if="loading" class="flex justify-center py-12">
      <span class="loading loading-spinner loading-lg text-primary"></span>
    </div>

    <!-- Policy Grid -->
    <div v-else class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div
        v-for="policy in (policies.length ? policies : demoPolicies)"
        :key="policy.id"
        class="card bg-base-100 border border-base-300"
      >
        <div class="card-body p-5">
          <div class="flex items-start justify-between">
            <div class="flex items-center gap-3">
              <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
                <Sliders class="w-4 h-4 text-primary" />
              </div>
              <div>
                <div class="font-bold text-sm">{{ policy.name }}</div>
                <div class="text-[11px] text-base-content/60 capitalize">{{ policy.type?.replace('_', ' ') }}</div>
              </div>
            </div>
            <input type="checkbox" class="toggle toggle-sm toggle-primary" :checked="policy.enforce" />
          </div>
          <p class="text-xs text-base-content/70 mt-2">{{ policy.description }}</p>
          <div class="flex items-center justify-between mt-3 pt-3 border-t border-base-300">
            <div class="flex items-center gap-1.5 text-xs">
              <CheckCircle v-if="!policy.violations" class="w-3.5 h-3.5 text-success" />
              <XCircle v-else class="w-3.5 h-3.5 text-error" />
              <span :class="policy.violations ? 'text-error' : 'text-success'">
                {{ policy.violations || 0 }} violations
              </span>
            </div>
            <span class="badge badge-sm" :class="policy.enforce ? 'badge-primary' : 'badge-ghost'">
              {{ policy.enforce ? 'Enforcing' : 'Monitor' }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Policy Modal -->
    <dialog class="modal" :class="{ 'modal-open': showCreateModal }">
      <div class="modal-box max-w-md">
        <h3 class="text-base font-bold mb-4">Create Policy</h3>
        <form @submit.prevent="createPolicy" class="space-y-3">
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Policy Name</span></label>
            <input v-model="form.name" type="text" placeholder="e.g. Minimum Key Size" class="input input-bordered input-sm" required />
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Description</span></label>
            <textarea v-model="form.description" class="textarea textarea-bordered textarea-sm" rows="2" placeholder="What does this policy enforce?"></textarea>
          </div>
          <div class="form-control">
            <label class="label"><span class="label-text text-xs">Policy Type</span></label>
            <select v-model="form.type" class="select select-bordered select-sm">
              <option value="key_strength">Key Strength</option>
              <option value="validity">Validity Duration</option>
              <option value="algorithm">Algorithm Restriction</option>
              <option value="renewal">Auto-Renewal</option>
            </select>
          </div>
          <div class="form-control">
            <label class="label cursor-pointer justify-start gap-3">
              <input v-model="form.enforce" type="checkbox" class="toggle toggle-sm toggle-primary" />
              <span class="label-text text-xs">Enforce (block violations)</span>
            </label>
          </div>
          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" @click="showCreateModal = false">Cancel</button>
            <button type="submit" class="btn btn-primary btn-sm">Create</button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showCreateModal = false"><button>close</button></form>
    </dialog>
  </div>
</template>
