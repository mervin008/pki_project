<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import { Sliders, Plus, RotateCw, CircleX, Trash2 } from 'lucide-vue-next'
import { parseDetails, type ListResponse, type Policy } from '@/lib/types'

const api = useApi()

const policies = useAsyncData<ListResponse<Policy>>((s) =>
  api.get<ListResponse<Policy>>('/api/v1/policies', s),
)
const policyList = computed(() => policies.data.value?.data ?? [])

/**
 * Only these three rule types are evaluated by the engine
 * (core/engine/policy/engine.go). The schema's CHECK constraint also permits
 * key_type, naming, and approval_required, but nothing implements them — a
 * policy using one would silently never fire, which is worse than not being
 * able to create it.
 */
const RULE_TYPES = [
  { value: 'key_size', label: 'Minimum key size', hint: 'Applies to RSA keys' },
  { value: 'max_lifetime', label: 'Maximum lifetime', hint: 'Caps requested validity' },
  { value: 'ca_restriction', label: 'Allowed CA providers', hint: 'Restricts which gateways may issue' },
] as const

const SEVERITIES = [
  { value: 'INFO', label: 'Info', hint: 'Recorded on the request, allowed' },
  { value: 'WARNING', label: 'Warning', hint: 'Returned with the certificate, allowed' },
  { value: 'BLOCK', label: 'Block', hint: 'Refuses the request outright' },
] as const

function ruleLabel(type: string) {
  return RULE_TYPES.find((r) => r.value === type)?.label ?? type
}

function severityBadgeClass(severity: string) {
  switch (severity) {
    case 'BLOCK': return 'sev-critical'
    case 'WARNING': return 'sev-warning'
    default: return 'sev-unknown'
  }
}

/** Renders the JSON rule_config as a readable sentence. */
function describeRule(policy: Policy): string {
  const cfg = parseDetails<Record<string, unknown>>(policy.rule_config)
  if (!cfg) return policy.rule_config || '—'
  switch (policy.rule_type) {
    case 'key_size':
      return `RSA keys must be at least ${cfg.min_key_size} bits`
    case 'max_lifetime':
      return `Validity must not exceed ${cfg.max_days} days`
    case 'ca_restriction':
      return `May only be issued by: ${(cfg.allowed_providers as string[])?.join(', ')}`
    default:
      return policy.rule_config
  }
}

// ── Create ────────────────────────────────────────────────
const showCreate = ref(false)
const saving = ref(false)
const createError = ref<string | null>(null)

const blankForm = () => ({
  name: '',
  description: '',
  rule_type: 'key_size' as (typeof RULE_TYPES)[number]['value'],
  severity: 'WARNING' as (typeof SEVERITIES)[number]['value'],
  domain_pattern: '*',
  is_enabled: true,
  min_key_size: '2048',
  max_days: '90',
  allowed_providers: 'acme',
})
const form = ref(blankForm())

/** Builds the JSON `rule_config` the engine expects for the chosen rule type. */
function buildRuleConfig(): string {
  switch (form.value.rule_type) {
    case 'key_size':
      return JSON.stringify({ min_key_size: Number(form.value.min_key_size) })
    case 'max_lifetime':
      return JSON.stringify({ max_days: Number(form.value.max_days) })
    case 'ca_restriction':
      return JSON.stringify({
        allowed_providers: form.value.allowed_providers
          .split(',').map((p) => p.trim()).filter(Boolean),
      })
  }
}

async function createPolicy() {
  saving.value = true
  createError.value = null
  try {
    await api.post('/api/v1/policies', {
      name: form.value.name,
      description: form.value.description || undefined,
      rule_type: form.value.rule_type,
      rule_config: buildRuleConfig(),
      domain_pattern: form.value.domain_pattern || undefined,
      severity: form.value.severity,
      is_enabled: form.value.is_enabled,
    })
    showCreate.value = false
    form.value = blankForm()
    await policies.refresh()
  } catch (err) {
    createError.value = err instanceof Error ? err.message : String(err)
  } finally {
    saving.value = false
  }
}

// ── Enable / disable / delete ─────────────────────────────
const busyId = ref<string | null>(null)
const actionError = ref<string | null>(null)

// The enable switch was previously bound with :checked and no handler, so it
// looked interactive and changed nothing.
async function toggleEnabled(policy: Policy) {
  busyId.value = policy.id
  actionError.value = null
  try {
    await api.put(`/api/v1/policies/${policy.id}`, {
      ...policy,
      is_enabled: !policy.is_enabled,
    })
    await policies.refresh()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busyId.value = null
  }
}

async function removePolicy(policy: Policy) {
  if (!confirm(`Delete the policy "${policy.name}"?`)) return
  busyId.value = policy.id
  actionError.value = null
  try {
    await api.delete(`/api/v1/policies/${policy.id}`)
    await policies.refresh()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busyId.value = null
  }
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <p class="text-sm text-[color:var(--text-muted)]">
        Rules evaluated when a certificate is requested
      </p>
      <div class="flex items-center gap-2">
        <button class="btn-console gap-1.5" :disabled="policies.loading.value" @click="policies.refresh()">
          <RotateCw class="w-3.5 h-3.5" :class="policies.loading.value && 'animate-spin'" />
          Refresh
        </button>
        <button class="btn-console btn-signal gap-2" @click="showCreate = true">
          <Plus class="w-4 h-4" /> Create policy
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="notice" data-tone="critical">
      <CircleX class="w-5 h-5 shrink-0" />
      <span class="text-sm break-words">{{ actionError }}</span>
    </div>

    <div role="alert" class="notice" data-tone="signal">
      <Sliders class="w-4 h-4 shrink-0" />
      <span class="text-xs">
        Policies are evaluated on issuance only, not on renewal. Only
        <span class="font-mono">BLOCK</span> refuses a request; other severities are returned
        alongside the certificate.
      </span>
    </div>

    <DataState
      :loading="policies.loading.value"
      :error="policies.error.value"
      :loaded="policies.loaded.value"
      @retry="policies.refresh()"
    >
      <div v-if="policyList.length" class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div
          v-for="policy in policyList" :key="policy.id"
          class="panel border"
          :class="!policy.is_enabled && 'opacity-60'"
        >
          <div class="panel-body p-4 gap-2">
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <div class="font-bold text-sm truncate">{{ policy.name }}</div>
                <div class="text-[11px] text-[color:var(--text-muted)]">{{ ruleLabel(policy.rule_type) }}</div>
              </div>
              <span class="tag shrink-0" :class="severityBadgeClass(policy.severity)">
                {{ policy.severity }}
              </span>
            </div>

            <p v-if="policy.description" class="text-xs text-[color:var(--text-secondary)]">{{ policy.description }}</p>
            <p class="text-xs font-mono px-2 py-1.5 break-words">
              {{ describeRule(policy) }}
            </p>
            <p class="text-[11px] text-[color:var(--text-muted)]">
              Applies to <span class="font-mono">{{ policy.domain_pattern || '*' }}</span>
            </p>

            <div class="flex items-center justify-between mt-1">
              <label class="label cursor-pointer justify-start gap-2 py-0">
                <input
                  type="checkbox" class="toggle-console toggle-primary"
                  :checked="policy.is_enabled" :disabled="busyId === policy.id"
                  @change="toggleEnabled(policy)"
                />
                <span class="label-micro">
                  {{ policy.is_enabled ? 'Enabled' : 'Disabled' }}
                </span>
              </label>
              <button
                class="btn-console sev-critical" :disabled="busyId === policy.id"
                @click="removePolicy(policy)"
              >
                <Trash2 class="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="p-3">
        <div class="empty-console">
          <strong>No policies are defined.</strong>
          Every request is accepted: any key size, any lifetime, any certificate
          authority. Nothing is being enforced here, which is not the same as
          nothing being wrong.
        </div>
      </div>
    </DataState>

    <!-- Create modal -->
    <div
      v-if="showCreate"
      class="dialog-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="create-policy-title"
      @click.self="showCreate = false"
      @keydown.esc="showCreate = false"
    >
      <div class="dialog-panel !max-w-md">
        <header class="panel-head">
          <span id="create-policy-title" class="label-rail">Create policy</span>
        </header>
        <form @submit.prevent="createPolicy">
          <div class="dialog-body flex flex-col gap-3">
            <div v-if="createError" role="alert" class="notice" data-tone="critical">
              <CircleX class="w-4 h-4 notice-icon" />
              <span class="break-words">{{ createError }}</span>
            </div>

          <div class="field">
            <label class="label-micro" for="p-name">Name</label>
            <input
              id="p-name" v-model="form.name" type="text" required
              placeholder="Minimum RSA 2048" class="input-console"
            />
          </div>

          <div class="field">
            <label class="label-micro" for="p-desc">Description</label>
            <input
              id="p-desc" v-model="form.description" type="text"
              class="input-console"
            />
          </div>

          <div class="field">
            <label class="label-micro" for="p-type">Rule</label>
            <select id="p-type" v-model="form.rule_type" class="select-console">
              <option v-for="r in RULE_TYPES" :key="r.value" :value="r.value">{{ r.label }}</option>
            </select>
            <p class="text-[11px] text-[color:var(--text-muted)] mt-1">
              {{ RULE_TYPES.find((r) => r.value === form.rule_type)?.hint }}
            </p>
          </div>

          <div v-if="form.rule_type === 'key_size'" class="field">
            <label class="label-micro" for="p-keysize">Minimum RSA key size (bits)</label>
            <select id="p-keysize" v-model="form.min_key_size" class="select-console">
              <option value="2048">2048</option>
              <option value="3072">3072</option>
              <option value="4096">4096</option>
            </select>
          </div>

          <div v-else-if="form.rule_type === 'max_lifetime'" class="field">
            <label class="label-micro" for="p-maxdays">Maximum validity (days)</label>
            <input
              id="p-maxdays" v-model="form.max_days" type="number" min="1" max="398"
              class="input-console"
            />
            <p class="text-[11px] text-[color:var(--text-muted)] mt-1">
              Public TLS maximum is 200 days from March 2026, 100 from 2027, 47 from 2029.
            </p>
          </div>

          <div v-else class="field">
            <label class="label-micro" for="p-providers">Allowed providers</label>
              <span class="field-help">Comma separated</span>
            <input
              id="p-providers" v-model="form.allowed_providers" type="text"
              placeholder="acme, vault" class="input-console"
            />
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div class="field">
              <label class="label-micro" for="p-sev">Severity</label>
              <select id="p-sev" v-model="form.severity" class="select-console">
                <option v-for="s in SEVERITIES" :key="s.value" :value="s.value">{{ s.label }}</option>
              </select>
            </div>
            <div class="field">
              <label class="label-micro" for="p-domain">Domain pattern</label>
              <input
                id="p-domain" v-model="form.domain_pattern" type="text"
                placeholder="*.prod.example.com" class="input-console"
              />
            </div>
          </div>
          <p class="text-[11px] text-[color:var(--text-muted)] -mt-1">
            {{ SEVERITIES.find((s) => s.value === form.severity)?.hint }}
          </p>

            <label class="flex items-center gap-2 cursor-pointer">
              <input v-model="form.is_enabled" type="checkbox" class="check-console" />
              <span class="label-micro">Enabled</span>
            </label>
          </div>

          <div class="dialog-foot">
            <button type="button" class="btn-console" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-console btn-signal" :disabled="saving">
              <span v-if="saving" class="spinner-console"></span>
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
