<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import SevChip from '@/components/ui/SevChip.vue'
import {
  Plus, Search, RotateCw, Eye, CircleX, ShieldCheck,
} from 'lucide-vue-next'
import {
  certStateLabel, certUrgency, compareSeverity, sevBg, sevClass,
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
        filterStatus.value === 'all' || certUrgency(c) === filterStatus.value
      return matchesSearch && matchesStatus
    })
    .sort((a, b) => {
      const bySeverity = compareSeverity(certUrgency(a), certUrgency(b))
      return bySeverity !== 0 ? bySeverity : a.days_remaining - b.days_remaining
    })
})

const counts = computed(() => {
  const all = certificates.value
  return {
    all: all.length,
    ok: all.filter((c) => certUrgency(c) === 'ok').length,
    warning: all.filter((c) => certUrgency(c) === 'warning').length,
    critical: all.filter((c) => certUrgency(c) === 'critical').length,
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
  <div class="flex flex-col gap-3 min-w-0">
    <div class="page-head">
      <div class="min-w-0">
        <h1 class="label-rail">Certificate inventory</h1>
        <p class="page-sub prose-ui">Managed certificates, most urgent first.</p>
      </div>
      <div class="flex items-center gap-2 shrink-0">
        <button
          class="btn-console"
          :disabled="certs.loading.value"
          @click="certs.refresh()"
        >
          <RotateCw class="w-3 h-3" :class="certs.loading.value && 'animate-spin'" />
          Refresh
        </button>
        <button class="btn-console" data-variant="signal" @click="showRequest = true">
          <Plus class="w-3 h-3" /> Request
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="action-error">
      <CircleX class="w-3.5 h-3.5 shrink-0 sev-critical" />
      <span>{{ actionError }}</span>
    </div>

    <DataState
      :loading="certs.loading.value"
      :error="certs.error.value"
      :loaded="certs.loaded.value"
      @retry="certs.refresh()"
    >
      <!-- Counts and filter are the same control. Four separate stat tiles that
           also happen to filter is two mental models for one object. -->
      <div class="filter-bar">
        <button
          v-for="tile in [
            { key: 'all', label: 'All', value: counts.all, tone: '' },
            { key: 'critical', label: 'Needs attention', value: counts.critical, tone: 'sev-critical' },
            { key: 'warning', label: 'Expiring', value: counts.warning, tone: 'sev-warning' },
            { key: 'ok', label: 'Healthy', value: counts.ok, tone: 'sev-ok' },
          ]"
          :key="tile.key"
          type="button"
          class="filter-chip"
          :data-active="filterStatus === tile.key || undefined"
          @click="filterStatus = tile.key as typeof filterStatus"
        >
          {{ tile.label }}
          <span
            class="filter-count"
            :class="filterStatus === tile.key || tile.value === 0 ? '' : tile.tone"
          >{{ tile.value }}</span>
        </button>

        <label class="filter-search">
          <Search class="w-3 h-3 shrink-0" style="color: var(--text-muted)" />
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Common name, SAN, or serial"
          />
        </label>
      </div>

      <!-- Table beside detail rather than a modal over it. A modal makes you
           forget the list to read one row; the split keeps the ordering — the
           thing this page is for — on screen while you inspect. -->
      <div class="split" :data-open="selected ? true : undefined">
        <PanelBox
          label="Certificates"
          :note="`${filtered.length} shown`"
          flush
        >
          <div class="table-scroll">
            <table class="tbl">
              <thead>
                <tr>
                  <th class="rail"></th>
                  <th>Common name</th>
                  <th>Issuer</th>
                  <th>Key</th>
                  <th>Expires</th>
                  <th class="num">Left</th>
                  <th>Status</th>
                  <th class="num">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="cert in filtered"
                  :key="cert.id"
                  :data-selected="selected?.id === cert.id || undefined"
                  class="cursor-pointer"
                  @click="selected = cert"
                >
                  <td class="rail" :class="sevBg(certUrgency(cert))"></td>
                  <td class="cell-primary max-w-[16rem] truncate">
                    {{ cert.common_name }}
                    <span v-if="cert.sans?.length > 1" style="color: var(--text-muted)">
                      +{{ cert.sans.length - 1 }}
                    </span>
                  </td>
                  <td class="max-w-[14rem] truncate">{{ truncate(cert.issuer_dn, 30) }}</td>
                  <td>
                    {{ cert.key_type
                    }}<template v-if="cert.key_size">-{{ cert.key_size }}</template>
                  </td>
                  <td>{{ formatDate(cert.not_after) }}</td>
                  <td class="num" :class="sevClass(certUrgency(cert))">
                    {{ formatDaysShort(cert.days_remaining) }}
                  </td>
                  <td>
                    <SevChip
                      :severity="certUrgency(cert)"
                      :label="certStateLabel(cert)"
                    />
                  </td>
                  <td class="num">
                    <button
                      class="row-action"
                      title="Renew now"
                      :disabled="renewingId === cert.id"
                      @click.stop="renewCert(cert)"
                    >
                      <RotateCw
                        class="w-3.5 h-3.5"
                        :class="renewingId === cert.id && 'animate-spin'"
                      />
                    </button>
                  </td>
                </tr>
                <tr v-if="!filtered.length">
                  <td colspan="8">
                    <div class="empty-state">
                      <ShieldCheck class="w-6 h-6" style="color: var(--text-muted)" />
                      <p class="prose-ui">
                        {{
                          certificates.length
                            ? 'No certificates match this filter.'
                            : 'No certificates yet. Request one to get started.'
                        }}
                      </p>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </PanelBox>

        <!-- Detail -->
        <PanelBox v-if="selected" label="Detail">
          <template #actions>
            <button class="btn-console" @click="selected = null">Close</button>
          </template>

          <div class="flex flex-col gap-3 min-w-0">
            <div class="flex items-center gap-2 flex-wrap min-w-0">
              <span class="detail-title">{{ selected.common_name }}</span>
              <SevChip
                :severity="certUrgency(selected)"
                :label="certStateLabel(selected)"
              />
            </div>

            <dl class="detail-list">
              <div class="detail-wide">
                <dt class="label-micro">Subject alternative names</dt>
                <dd>{{ selected.sans?.join(', ') || '—' }}</dd>
              </div>
              <div class="detail-wide">
                <dt class="label-micro">Serial</dt>
                <dd class="break-all">{{ selected.serial_number || '—' }}</dd>
              </div>
              <div>
                <dt class="label-micro">Key</dt>
                <dd>{{ selected.key_type }}-{{ selected.key_size }}</dd>
              </div>
              <div>
                <dt class="label-micro">Renewals</dt>
                <dd>{{ selected.renewal_count }}</dd>
              </div>
              <div>
                <dt class="label-micro">Issued</dt>
                <dd>{{ formatDate(selected.not_before) }}</dd>
              </div>
              <div>
                <dt class="label-micro">Expires</dt>
                <dd>{{ formatDate(selected.not_after) }}</dd>
              </div>
              <div class="detail-wide">
                <dt class="label-micro">Auto renew</dt>
                <dd>
                  {{
                    selected.auto_renew
                      ? `Yes, ${selected.renewal_lead_days} days ahead`
                      : 'No'
                  }}
                </dd>
              </div>
              <div class="detail-wide">
                <dt class="label-micro">Issuer</dt>
                <dd class="break-all">{{ selected.issuer_dn || '—' }}</dd>
              </div>
              <div v-if="selected.renewal_error" class="detail-wide">
                <dt class="label-micro sev-critical">Last renewal error</dt>
                <dd class="sev-critical break-words">{{ selected.renewal_error }}</dd>
              </div>
            </dl>
          </div>
        </PanelBox>
      </div>
    </DataState>

    <!-- Request. A modal is right here: it is a create action with its own
         validity, not a thing to compare against the list behind it. -->
    <div v-if="showRequest" class="modal-scrim" @click.self="showRequest = false">
      <PanelBox label="Request certificate" class="modal-panel">
        <div v-if="requestError" role="alert" class="action-error mb-3">
          <CircleX class="w-3.5 h-3.5 shrink-0 sev-critical" />
          <span>{{ requestError }}</span>
        </div>

        <form class="flex flex-col gap-2.5" @submit.prevent="requestCert">
          <div class="field">
            <label class="label-micro" for="cn">Common name</label>
            <input
              id="cn"
              v-model="reqForm.common_name"
              type="text"
              required
              placeholder="app.example.com"
              class="input-console"
            />
          </div>

          <div class="field">
            <label class="label-micro" for="sans">Additional names — comma separated</label>
            <input
              id="sans"
              v-model="reqForm.sans"
              type="text"
              placeholder="www.example.com, api.example.com"
              class="input-console"
            />
          </div>

          <div class="field">
            <label class="label-micro" for="ca-account">Issue from</label>
            <select id="ca-account" v-model="reqForm.ca_account_id" required class="input-console">
              <option value="" disabled>Select a CA account</option>
              <option v-for="acc in caAccounts" :key="acc.id" :value="acc.id">
                {{ acc.name }} ({{ acc.provider_type }})
              </option>
            </select>
            <p v-if="accounts.loaded.value && !caAccounts.length" class="label-micro sev-warning">
              No CA accounts configured — add one on the Gateways page first.
            </p>
          </div>

          <div class="grid grid-cols-3 gap-2">
            <div class="field">
              <label class="label-micro" for="kt">Key type</label>
              <select
                id="kt"
                v-model="reqForm.key_type"
                class="input-console"
                @change="onKeyTypeChange"
              >
                <option value="ECDSA">ECDSA</option>
                <option value="RSA">RSA</option>
              </select>
            </div>
            <div class="field">
              <label class="label-micro" for="ks">Key size</label>
              <select id="ks" v-model="reqForm.key_size" class="input-console">
                <option v-for="size in keySizeOptions" :key="size" :value="size">{{ size }}</option>
              </select>
            </div>
            <div class="field">
              <label class="label-micro" for="vd">Validity (days)</label>
              <input
                id="vd"
                v-model="reqForm.validity_days"
                type="number"
                min="1"
                max="398"
                class="input-console"
              />
            </div>
          </div>

          <div class="grid grid-cols-2 gap-2">
            <div class="field">
              <label class="label-micro" for="env">Environment</label>
              <input
                id="env"
                v-model="reqForm.environment"
                type="text"
                placeholder="production"
                class="input-console"
              />
            </div>
            <div class="field">
              <label class="label-micro" for="team">Owning team</label>
              <input
                id="team"
                v-model="reqForm.team"
                type="text"
                placeholder="Platform Engineering"
                class="input-console"
              />
            </div>
          </div>

          <label class="flex items-center gap-2 cursor-pointer" style="font-size: var(--fs-small)">
            <input v-model="reqForm.auto_renew" type="checkbox" />
            Renew automatically before expiry
          </label>

          <div class="flex justify-end gap-2 pt-1">
            <button type="button" class="btn-console" @click="showRequest = false">Cancel</button>
            <button type="submit" class="btn-console" data-variant="signal" :disabled="requesting">
              {{ requesting ? 'Requesting…' : 'Request' }}
            </button>
          </div>
        </form>
      </PanelBox>
    </div>
  </div>
</template>

<style scoped>
.page-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid var(--line);
}

.page-sub {
  font-size: var(--fs-small);
  color: var(--text-muted);
  margin-top: 0.25rem;
}

.action-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.625rem;
  font-size: var(--fs-small);
  background: var(--sev-critical-wash);
  border: 1px solid var(--sev-critical);
  border-left-width: 3px;
  word-break: break-word;
}

.filter-bar {
  display: flex;
  align-items: stretch;
  gap: 1px;
  flex-wrap: wrap;
  background: var(--line);
  border: 1px solid var(--line);
}

.filter-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.3rem 0.625rem;
  font-size: var(--fs-micro);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-weight: 600;
  color: var(--text-muted);
  background: var(--ink-panel);
  border: 0;
  cursor: pointer;
}

.filter-chip:hover {
  color: var(--text-primary);
  background: var(--ink-hover);
}

.filter-chip[data-active] {
  color: var(--text-primary);
  background: var(--ink-raised);
  box-shadow: inset 0 -2px 0 0 var(--signal);
}

.filter-count {
  font-weight: 700;
  font-size: var(--fs-label);
}

.filter-search {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin-left: auto;
  padding: 0 0.5rem;
  background: var(--ink-panel);
}

.filter-search input {
  background: none;
  border: 0;
  outline: none;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--fs-small);
  width: 14rem;
}

.filter-search input::placeholder {
  color: var(--text-muted);
}

.split {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 0.75rem;
  min-width: 0;
}

@media (min-width: 1280px) {
  .split[data-open] {
    grid-template-columns: minmax(0, 1fr) 22rem;
  }
}

.table-scroll {
  overflow-x: auto;
  max-height: calc(100vh - 15rem);
  overflow-y: auto;
}

.row-action {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  color: var(--text-muted);
  background: none;
  border: 0;
  cursor: pointer;
}

.row-action:hover:not(:disabled) {
  color: var(--text-primary);
}

.row-action:disabled {
  opacity: 0.4;
}

.detail-title {
  font-size: var(--fs-body);
  font-weight: 600;
  color: var(--text-primary);
  word-break: break-all;
}

.detail-list {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.625rem 0.75rem;
  font-size: var(--fs-small);
}

.detail-wide {
  grid-column: 1 / -1;
}

.detail-list dd {
  color: var(--text-secondary);
  margin-top: 0.15rem;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 2.5rem 1rem;
  text-align: center;
  font-size: var(--fs-small);
  color: var(--text-muted);
}

.modal-scrim {
  position: fixed;
  inset: 0;
  z-index: 80;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 3rem 1rem;
  background: rgb(0 0 0 / 0.65);
  overflow-y: auto;
}

.modal-panel {
  width: 100%;
  max-width: 30rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  min-width: 0;
}
</style>
