<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import {
  Plus, Search, RotateCw, Eye, CircleX, ShieldCheck,
} from 'lucide-vue-next'
import {
  certSeverity, compareSeverity, severityBadge, severityText, statusLabel,
} from '@/lib/severity'
import { formatDate, formatDaysShort, truncate } from '@/lib/format'
import type { CaAccount, Certificate, ListResponse } from '@/lib/types'

const api = useApi()

const certs = useAsyncData<ListResponse<Certificate>>((s) =>
  api.get<ListResponse<Certificate>>('/api/v1/certificates', s),
)
// Needed for the request form: ca_account_id is required by the API.
const accounts = useAsyncData<ListResponse<CaAccount>>((s) =>
  api.get<ListResponse<CaAccount>>('/api/v1/ca-accounts', s),
)

const certificates = computed(() => certs.data.value?.data ?? [])
const caAccounts = computed(() => accounts.data.value?.data ?? [])

const searchQuery = ref('')
const filterStatus = ref<'all' | 'ok' | 'warning' | 'critical'>('all')

// Filters group by severity rather than by exact status: an operator scanning
// for trouble wants "everything critical", not to remember that REVOKED and
// RENEWAL_FAILED both belong in that bucket.
const filtered = computed(() => {
  const q = searchQuery.value.trim().toLowerCase()
  return certificates.value
    .filter((c) => {
      const matchesSearch =
        !q ||
        c.common_name.toLowerCase().includes(q) ||
        c.sans?.some((san) => san.toLowerCase().includes(q)) ||
        (c.serial_number ?? '').toLowerCase().includes(q)
      const matchesStatus =
        filterStatus.value === 'all' || certSeverity(c.status) === filterStatus.value
      return matchesSearch && matchesStatus
    })
    .sort((a, b) => {
      const bySeverity = compareSeverity(certSeverity(a.status), certSeverity(b.status))
      return bySeverity !== 0 ? bySeverity : a.days_remaining - b.days_remaining
    })
})

const counts = computed(() => {
  const all = certificates.value
  return {
    all: all.length,
    ok: all.filter((c) => certSeverity(c.status) === 'ok').length,
    warning: all.filter((c) => certSeverity(c.status) === 'warning').length,
    critical: all.filter((c) => certSeverity(c.status) === 'critical').length,
  }
})

// ── Request ───────────────────────────────────────────────
const showRequest = ref(false)
const requesting = ref(false)
const requestError = ref<string | null>(null)

const blankRequest = () => ({
  common_name: '',
  sans: '',
  ca_account_id: '',
  key_type: 'ECDSA',
  key_size: '256',
  validity_days: '90',
  environment: '',
  team: '',
  auto_renew: true,
})
const reqForm = ref(blankRequest())

// RSA and ECDSA have entirely different meaningful key sizes; offering 2048 for
// an EC key produces a request the gateway will reject.
const keySizeOptions = computed(() =>
  reqForm.value.key_type === 'RSA' ? ['2048', '3072', '4096'] : ['256', '384', '521'],
)

function onKeyTypeChange() {
  reqForm.value.key_size = reqForm.value.key_type === 'RSA' ? '2048' : '256'
}

async function requestCert() {
  requesting.value = true
  requestError.value = null
  try {
    await api.post('/api/v1/certificates', {
      common_name: reqForm.value.common_name,
      sans: reqForm.value.sans.split(',').map((d) => d.trim()).filter(Boolean),
      ca_account_id: reqForm.value.ca_account_id,
      key_type: reqForm.value.key_type,
      key_size: Number(reqForm.value.key_size),
      validity_days: Number(reqForm.value.validity_days),
      environment: reqForm.value.environment || undefined,
      team: reqForm.value.team || undefined,
      auto_renew: reqForm.value.auto_renew,
    })
    showRequest.value = false
    reqForm.value = blankRequest()
    await certs.refresh()
  } catch (err) {
    requestError.value = err instanceof Error ? err.message : String(err)
  } finally {
    requesting.value = false
  }
}

// ── Renew ─────────────────────────────────────────────────
const renewingId = ref<string | null>(null)
const actionError = ref<string | null>(null)

async function renewCert(cert: Certificate) {
  renewingId.value = cert.id
  actionError.value = null
  try {
    await api.post(`/api/v1/certificates/${cert.id}/renew`)
    await certs.refresh()
  } catch (err) {
    actionError.value = `Renewing ${cert.common_name} failed: ${
      err instanceof Error ? err.message : String(err)
    }`
  } finally {
    renewingId.value = null
  }
}

const selected = ref<Certificate | null>(null)
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <p class="text-sm text-base-content/60">Managed certificates, most urgent first</p>
      <div class="flex items-center gap-2">
        <button class="btn btn-ghost btn-sm gap-1.5" :disabled="certs.loading.value" @click="certs.refresh()">
          <RotateCw class="w-3.5 h-3.5" :class="certs.loading.value && 'animate-spin'" />
          Refresh
        </button>
        <button class="btn btn-primary btn-sm gap-2" @click="showRequest = true">
          <Plus class="w-4 h-4" /> Request certificate
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="alert alert-error">
      <CircleX class="w-5 h-5 shrink-0" />
      <span class="text-sm break-words">{{ actionError }}</span>
    </div>

    <DataState
      :loading="certs.loading.value"
      :error="certs.error.value"
      :loaded="certs.loaded.value"
      @retry="certs.refresh()"
    >
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
        <button
          v-for="tile in [
            { key: 'all', label: 'All certificates', value: counts.all, tone: '' },
            { key: 'ok', label: 'Healthy', value: counts.ok, tone: 'text-success' },
            { key: 'warning', label: 'Expiring', value: counts.warning, tone: 'text-warning' },
            { key: 'critical', label: 'Needs attention', value: counts.critical, tone: 'text-error' },
          ]"
          :key="tile.key"
          class="stat bg-base-100 rounded-xl border p-4 text-left transition-colors"
          :class="filterStatus === tile.key ? 'border-primary' : 'border-base-300 hover:border-base-content/20'"
          @click="filterStatus = tile.key as typeof filterStatus"
        >
          <div class="stat-title text-xs">{{ tile.label }}</div>
          <div class="stat-value text-xl tabular-nums" :class="tile.value > 0 ? tile.tone : ''">
            {{ tile.value }}
          </div>
        </button>
      </div>

      <label class="input input-bordered input-sm flex items-center gap-2">
        <Search class="w-4 h-4 opacity-50" />
        <input
          v-model="searchQuery" type="search" class="grow"
          placeholder="Search common name, SAN, or serial"
        />
      </label>

      <div class="card bg-base-100 border border-base-300">
        <div class="overflow-x-auto">
          <table class="table table-sm">
            <thead>
              <tr>
                <th class="text-xs">Common name</th>
                <th class="text-xs">Issuer</th>
                <th class="text-xs">Key</th>
                <th class="text-xs">Expires</th>
                <th class="text-xs text-right">Remaining</th>
                <th class="text-xs">Status</th>
                <th class="text-xs text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="cert in filtered" :key="cert.id" class="hover">
                <td class="text-xs font-medium">
                  {{ cert.common_name }}
                  <span v-if="cert.sans?.length > 1" class="opacity-50">
                    +{{ cert.sans.length - 1 }}
                  </span>
                </td>
                <td class="text-xs opacity-70">{{ truncate(cert.issuer_dn, 32) }}</td>
                <td class="text-xs font-mono">
                  {{ cert.key_type }}<template v-if="cert.key_size">-{{ cert.key_size }}</template>
                </td>
                <td class="text-xs font-mono">{{ formatDate(cert.not_after) }}</td>
                <td
                  class="text-xs font-mono tabular-nums text-right"
                  :class="severityText(certSeverity(cert.status))"
                >
                  {{ formatDaysShort(cert.days_remaining) }}
                </td>
                <td>
                  <span class="badge badge-sm" :class="severityBadge(certSeverity(cert.status))">
                    {{ statusLabel(cert.status) }}
                  </span>
                </td>
                <td class="text-right whitespace-nowrap">
                  <button class="btn btn-ghost btn-xs" title="Details" @click="selected = cert">
                    <Eye class="w-3.5 h-3.5" />
                  </button>
                  <button
                    class="btn btn-ghost btn-xs" title="Renew now"
                    :disabled="renewingId === cert.id" @click="renewCert(cert)"
                  >
                    <RotateCw class="w-3.5 h-3.5" :class="renewingId === cert.id && 'animate-spin'" />
                  </button>
                </td>
              </tr>
              <tr v-if="!filtered.length">
                <td colspan="7" class="text-center py-10">
                  <ShieldCheck class="w-8 h-8 opacity-30 mx-auto mb-2" />
                  <p class="text-xs opacity-60">
                    {{ certificates.length
                      ? 'No certificates match this filter.'
                      : 'No certificates yet. Request one to get started.' }}
                  </p>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </DataState>

    <!-- Request modal -->
    <dialog class="modal" :class="{ 'modal-open': showRequest }">
      <div class="modal-box max-w-lg">
        <h3 class="text-base font-bold mb-4">Request certificate</h3>

        <div v-if="requestError" role="alert" class="alert alert-error mb-3">
          <CircleX class="w-4 h-4 shrink-0" />
          <span class="text-xs break-words">{{ requestError }}</span>
        </div>

        <form class="space-y-3" @submit.prevent="requestCert">
          <div class="form-control">
            <label class="label" for="cn"><span class="label-text text-xs">Common name</span></label>
            <input
              id="cn" v-model="reqForm.common_name" type="text" required
              placeholder="app.example.com" class="input input-bordered input-sm"
            />
          </div>

          <div class="form-control">
            <label class="label" for="sans">
              <span class="label-text text-xs">Additional names</span>
              <span class="label-text-alt text-[10px] opacity-60">Comma separated</span>
            </label>
            <input
              id="sans" v-model="reqForm.sans" type="text"
              placeholder="www.example.com, api.example.com"
              class="input input-bordered input-sm"
            />
          </div>

          <div class="form-control">
            <label class="label" for="ca-account">
              <span class="label-text text-xs">Issue from</span>
            </label>
            <select
              id="ca-account" v-model="reqForm.ca_account_id" required
              class="select select-bordered select-sm"
            >
              <option value="" disabled>Select a CA account</option>
              <option v-for="acc in caAccounts" :key="acc.id" :value="acc.id">
                {{ acc.name }} ({{ acc.provider_type }})
              </option>
            </select>
            <p v-if="accounts.loaded.value && !caAccounts.length" class="text-[11px] text-warning mt-1">
              No CA accounts configured — add one on the Gateways page first.
            </p>
          </div>

          <div class="grid grid-cols-3 gap-3">
            <div class="form-control">
              <label class="label" for="kt"><span class="label-text text-xs">Key type</span></label>
              <select
                id="kt" v-model="reqForm.key_type" class="select select-bordered select-sm"
                @change="onKeyTypeChange"
              >
                <option value="ECDSA">ECDSA</option>
                <option value="RSA">RSA</option>
              </select>
            </div>
            <div class="form-control">
              <label class="label" for="ks"><span class="label-text text-xs">Key size</span></label>
              <select id="ks" v-model="reqForm.key_size" class="select select-bordered select-sm">
                <option v-for="size in keySizeOptions" :key="size" :value="size">{{ size }}</option>
              </select>
            </div>
            <div class="form-control">
              <label class="label" for="vd"><span class="label-text text-xs">Validity (days)</span></label>
              <input
                id="vd" v-model="reqForm.validity_days" type="number" min="1" max="398"
                class="input input-bordered input-sm"
              />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <input
              v-model="reqForm.environment" type="text" placeholder="Environment"
              class="input input-bordered input-sm"
            />
            <input
              v-model="reqForm.team" type="text" placeholder="Owning team"
              class="input input-bordered input-sm"
            />
          </div>

          <label class="label cursor-pointer justify-start gap-3">
            <input v-model="reqForm.auto_renew" type="checkbox" class="checkbox checkbox-sm" />
            <span class="label-text text-xs">Renew automatically before expiry</span>
          </label>

          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" @click="showRequest = false">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary btn-sm" :disabled="requesting">
              <span v-if="requesting" class="loading loading-spinner loading-xs"></span>
              Request
            </button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showRequest = false">
        <button>close</button>
      </form>
    </dialog>

    <!-- Detail modal -->
    <dialog class="modal" :class="{ 'modal-open': !!selected }">
      <div v-if="selected" class="modal-box max-w-lg">
        <h3 class="text-base font-bold mb-1">{{ selected.common_name }}</h3>
        <span class="badge badge-sm mb-4" :class="severityBadge(certSeverity(selected.status))">
          {{ statusLabel(selected.status) }}
        </span>

        <dl class="grid grid-cols-2 gap-3 text-xs">
          <div class="col-span-2">
            <dt class="opacity-60 mb-0.5">Subject alternative names</dt>
            <dd class="font-mono break-all">{{ selected.sans?.join(', ') || '—' }}</dd>
          </div>
          <div><dt class="opacity-60 mb-0.5">Serial</dt>
            <dd class="font-mono break-all">{{ selected.serial_number || '—' }}</dd></div>
          <div><dt class="opacity-60 mb-0.5">Key</dt>
            <dd class="font-mono">{{ selected.key_type }}-{{ selected.key_size }}</dd></div>
          <div><dt class="opacity-60 mb-0.5">Issued</dt>
            <dd class="font-mono">{{ formatDate(selected.not_before) }}</dd></div>
          <div><dt class="opacity-60 mb-0.5">Expires</dt>
            <dd class="font-mono">{{ formatDate(selected.not_after) }}</dd></div>
          <div><dt class="opacity-60 mb-0.5">Auto renew</dt>
            <dd>{{ selected.auto_renew ? `Yes, ${selected.renewal_lead_days} days ahead` : 'No' }}</dd></div>
          <div><dt class="opacity-60 mb-0.5">Renewals</dt>
            <dd class="tabular-nums">{{ selected.renewal_count }}</dd></div>
          <div class="col-span-2">
            <dt class="opacity-60 mb-0.5">Issuer</dt>
            <dd class="font-mono break-all">{{ selected.issuer_dn || '—' }}</dd>
          </div>
          <div v-if="selected.renewal_error" class="col-span-2">
            <dt class="opacity-60 mb-0.5 text-error">Last renewal error</dt>
            <dd class="text-error break-words">{{ selected.renewal_error }}</dd>
          </div>
        </dl>

        <div class="modal-action">
          <button class="btn btn-ghost btn-sm" @click="selected = null">Close</button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="selected = null">
        <button>close</button>
      </form>
    </dialog>
  </div>
</template>
