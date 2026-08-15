<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import { 
  Sliders, 
  Plus, 
  RefreshCw, 
  Check, 
  X, 
  Trash2,
  ShieldAlert,
  ShieldCheck
} from 'lucide-vue-next'

const api = useApi()
const policies = ref<any[]>([])
const loading = ref(true)
const showModal = ref(false)

const newPolicy = ref({
  name: '',
  description: '',
  rule_type: 'key_size',
  rule_config: '{"min_key_size": 2048}',
  domain_pattern: '*',
  severity: 'BLOCK',
  is_enabled: true,
})

async function loadPolicies() {
  loading.value = true
  try {
    const res = await api.get<any>('/api/v1/policies').catch(() => ({ data: [] }))
    policies.value = res.data || []
  } finally {
    loading.value = false
  }
}

async function togglePolicy(p: any) {
  p.is_enabled = !p.is_enabled
  try {
    await api.put(`/api/v1/policies/${p.id}`, p)
  } catch (err: any) {
    p.is_enabled = !p.is_enabled
    alert('Failed to update policy: ' + err.message)
  }
}

async function submitPolicy() {
  try {
    await api.post('/api/v1/policies', newPolicy.value)
    showModal.value = false
    await loadPolicies()
  } catch (err: any) {
    alert('Failed to create policy: ' + err.message)
  }
}

async function deletePolicy(id: string) {
  if (!confirm('Are you sure you want to delete this policy rule?')) return
  try {
    await api.delete(`/api/v1/policies/${id}`)
    await loadPolicies()
  } catch (err: any) {
    alert('Delete failed: ' + err.message)
  }
}

onMounted(() => {
  loadPolicies()
})
</script>

<template>
  <div class="space-y-8">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Sliders class="w-7 h-7 text-indigo-400" />
          Security & Compliance Policy Engine
        </h2>
        <p class="text-sm text-slate-400 mt-1">
          Enforce cryptographic standards, maximum lifetimes, and approved Certificate Authorities across issuance workflows.
        </p>
      </div>

      <div class="flex items-center gap-3">
        <button @click="loadPolicies" class="btn-secondary">
          <RefreshCw class="w-4 h-4" :class="{ 'animate-spin': loading }" />
          Refresh
        </button>
        <button @click="showModal = true" class="btn-primary">
          <Plus class="w-4 h-4" />
          Add Policy Rule
        </button>
      </div>
    </div>

    <!-- Policy Cards Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
      <div v-if="policies.length === 0" class="col-span-2 glass-panel p-8 text-center text-slate-400">
        <ShieldCheck class="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <p class="font-medium text-slate-300">No Custom Policy Rules Configured</p>
        <p class="text-xs text-slate-500 mt-1 mb-4">Add compliance rules like minimum RSA 2048-bit key size or CA restrictions.</p>
        <button @click="showModal = true" class="btn-primary">Add Policy Rule</button>
      </div>

      <div v-for="p in policies" :key="p.id" class="glass-panel p-5 space-y-4">
        <div class="flex items-start justify-between">
          <div>
            <div class="font-bold text-white text-base">{{ p.name }}</div>
            <div class="text-xs text-slate-400 mt-0.5">{{ p.description || 'Enforced across all certificate requests' }}</div>
          </div>
          <span class="badge" :class="p.severity === 'BLOCK' ? 'badge-critical' : 'badge-warning'">
            {{ p.severity }}
          </span>
        </div>

        <div class="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono space-y-1">
          <div><span class="text-slate-400">Rule Type:</span> <span class="text-indigo-300">{{ p.rule_type }}</span></div>
          <div><span class="text-slate-400">Scope:</span> <span class="text-slate-200">{{ p.domain_pattern || '*' }}</span></div>
          <div><span class="text-slate-400">Config:</span> <span class="text-slate-300">{{ p.rule_config }}</span></div>
        </div>

        <div class="flex items-center justify-between pt-2 border-t border-slate-800/80">
          <button 
            @click="togglePolicy(p)" 
            class="text-xs font-medium px-3 py-1.5 rounded-lg border transition-colors flex items-center gap-1.5"
            :class="p.is_enabled ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-slate-800 text-slate-400 border-slate-700'"
          >
            <span class="w-2 h-2 rounded-full" :class="p.is_enabled ? 'bg-emerald-400' : 'bg-slate-500'"></span>
            {{ p.is_enabled ? 'Active Policy' : 'Disabled' }}
          </button>

          <button @click="deletePolicy(p.id)" class="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors">
            <Trash2 class="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>

    <!-- Create Policy Modal -->
    <div v-if="showModal" class="modal-backdrop">
      <div class="modal-content">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
          <h3 class="text-lg font-bold text-white">Create Security Policy Rule</h3>
          <button @click="showModal = false" class="text-slate-400 hover:text-white">
            <X class="w-5 h-5" />
          </button>
        </div>

        <form @submit.prevent="submitPolicy" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Policy Name</label>
            <input v-model="newPolicy.name" class="input-field" placeholder="e.g. Enforce Minimum RSA 2048" required />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Description</label>
            <input v-model="newPolicy.description" class="input-field" placeholder="Rejects any certificate request with keys below 2048 bits" />
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">Rule Type</label>
              <select v-model="newPolicy.rule_type" class="input-field">
                <option value="key_size">Minimum Key Size</option>
                <option value="max_lifetime">Maximum Lifetime</option>
                <option value="ca_restriction">CA Restriction</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1.5">Severity</label>
              <select v-model="newPolicy.severity" class="input-field">
                <option value="BLOCK">BLOCK (Reject Issuance)</option>
                <option value="WARNING">WARNING (Log Alert)</option>
              </select>
            </div>
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1.5">Rule Config (JSON)</label>
            <input v-model="newPolicy.rule_config" class="input-field font-mono text-xs" required />
          </div>

          <div class="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
            <button type="button" @click="showModal = false" class="btn-secondary">Cancel</button>
            <button type="submit" class="btn-primary">Save Policy</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
