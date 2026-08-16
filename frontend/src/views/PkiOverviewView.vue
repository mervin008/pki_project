<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import {
  ShieldCheck, Plus, ChevronDown, ChevronRight, Lock, Server, Stamp,
  RotateCw, CircleCheck, CircleX,
} from 'lucide-vue-next'
import {
  caSeverity, compareSeverity, severityBadge, severityBorder, severityText, statusLabel,
} from '@/lib/severity'
import { formatDate, formatDateTime, formatDays, truncate } from '@/lib/format'
import type { CaAuthority, ListResponse } from '@/lib/types'

const api = useApi()

const cas = useAsyncData<ListResponse<CaAuthority>>((s) =>
  api.get<ListResponse<CaAuthority>>('/api/v1/pki/authorities', s),
)

const authorities = computed(() => cas.data.value?.data ?? [])

// Most urgent first — an expiring issuing CA takes down everything it signed,
// so it must never be below the fold.
const byUrgency = computed(() =>
  [...authorities.value].sort((a, b) => {
    const bySeverity = compareSeverity(caSeverity(a.status), caSeverity(b.status))
    return bySeverity !== 0 ? bySeverity : a.days_remaining - b.days_remaining
  }),
)

const countByType = (type: string) =>
  computed(() => authorities.value.filter((ca) => ca.ca_type === type).length)
const rootCount = countByType('ROOT')
const intermediateCount = countByType('INTERMEDIATE')
const issuingCount = countByType('ISSUING')

const expandedCa = ref<string | null>(null)
function toggleExpand(id: string) {
  expandedCa.value = expandedCa.value === id ? null : id
}

function typeIcon(type: string) {
  switch (type) {
    case 'ROOT': return Lock
    case 'INTERMEDIATE': return Server
    case 'ISSUING': return Stamp
    default: return ShieldCheck
  }
}

// ── Import ────────────────────────────────────────────────
// CertPilot manages CAs; it does not generate them. The API registers an
// existing authority from its certificate, so this is an import form.
//
// The previous form collected common name, organization, key size and validity
// years as though CertPilot would mint the CA — and never sent the
// `certificate_pem` the endpoint requires, so every submission was rejected.
const showImport = ref(false)
const importing = ref(false)
const importError = ref<string | null>(null)

const blankForm = () => ({
  name: '',
  certificate_pem: '',
  parent_ca_id: '',
  crl_distribution_url: '',
  ocsp_responder_url: '',
  notes: '',
})
const form = ref(blankForm())

const parentOptions = computed(() =>
  authorities.value.filter((ca) => ca.ca_type === 'ROOT' || ca.ca_type === 'INTERMEDIATE'),
)

async function importCA() {
  importing.value = true
  importError.value = null
  try {
    await api.post('/api/v1/pki/authorities', {
      name: form.value.name,
      certificate_pem: form.value.certificate_pem,
      parent_ca_id: form.value.parent_ca_id || null,
      crl_distribution_url: form.value.crl_distribution_url || undefined,
      ocsp_responder_url: form.value.ocsp_responder_url || undefined,
      notes: form.value.notes || undefined,
    })
    showImport.value = false
    form.value = blankForm()
    await cas.refresh()
  } catch (err) {
    // Surfaced in the modal rather than an alert() the operator cannot copy.
    importError.value = err instanceof Error ? err.message : String(err)
  } finally {
    importing.value = false
  }
}

// ── On-demand health check ────────────────────────────────
const checking = ref<string | null>(null)
const checkError = ref<string | null>(null)

async function checkNow(ca: CaAuthority) {
  checking.value = ca.id
  checkError.value = null
  try {
    await api.post(`/api/v1/pki/authorities/${ca.id}/check`)
    await cas.refresh()
  } catch (err) {
    checkError.value = err instanceof Error ? err.message : String(err)
  } finally {
    checking.value = null
  }
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <p class="text-sm text-base-content/60">
        Certificate authorities under management, most urgent first
      </p>
      <div class="flex items-center gap-2">
        <button class="btn btn-ghost btn-sm gap-1.5" :disabled="cas.loading.value" @click="cas.refresh()">
          <RotateCw class="w-3.5 h-3.5" :class="cas.loading.value && 'animate-spin'" />
          Refresh
        </button>
        <button class="btn btn-primary btn-sm gap-2" @click="showImport = true">
          <Plus class="w-4 h-4" /> Import CA
        </button>
      </div>
    </div>

    <div v-if="checkError" role="alert" class="alert alert-error">
      <CircleX class="w-5 h-5 shrink-0" />
      <span class="text-sm">{{ checkError }}</span>
    </div>

    <DataState
      :loading="cas.loading.value"
      :error="cas.error.value"
      :loaded="cas.loaded.value"
      @retry="cas.refresh()"
    >
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-title text-xs">Total CAs</div>
          <div class="stat-value text-xl tabular-nums">{{ authorities.length }}</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-title text-xs">Root</div>
          <div class="stat-value text-xl tabular-nums">{{ rootCount }}</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-title text-xs">Intermediate</div>
          <div class="stat-value text-xl tabular-nums">{{ intermediateCount }}</div>
        </div>
        <div class="stat bg-base-100 rounded-xl border border-base-300 p-4">
          <div class="stat-title text-xs">Issuing</div>
          <div class="stat-value text-xl tabular-nums">{{ issuingCount }}</div>
        </div>
      </div>

      <div v-if="byUrgency.length" class="space-y-3">
        <div
          v-for="ca in byUrgency"
          :key="ca.id"
          class="card bg-base-100 border border-base-300 border-l-4"
          :class="severityBorder(caSeverity(ca.status))"
        >
          <div class="card-body p-4">
            <div
              class="flex items-center justify-between gap-3 cursor-pointer"
              role="button"
              tabindex="0"
              @click="toggleExpand(ca.id)"
              @keydown.enter="toggleExpand(ca.id)"
              @keydown.space.prevent="toggleExpand(ca.id)"
            >
              <div class="flex items-center gap-3 min-w-0">
                <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <component :is="typeIcon(ca.ca_type)" class="w-4 h-4 text-primary" />
                </div>
                <div class="min-w-0">
                  <div class="font-bold text-sm truncate">{{ ca.name }}</div>
                  <div class="text-[11px] text-base-content/60 truncate">
                    {{ statusLabel(ca.ca_type) }} · {{ ca.key_type }}<template v-if="ca.key_size">-{{ ca.key_size }}</template>
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-3 shrink-0">
                <span
                  class="text-xs font-mono tabular-nums"
                  :class="severityText(caSeverity(ca.status))"
                >
                  {{ formatDays(ca.days_remaining) }}
                </span>
                <span class="badge badge-sm" :class="severityBadge(caSeverity(ca.status))">
                  {{ statusLabel(ca.status) }}
                </span>
                <ChevronDown v-if="expandedCa === ca.id" class="w-4 h-4 opacity-50" />
                <ChevronRight v-else class="w-4 h-4 opacity-50" />
              </div>
            </div>

            <div v-if="expandedCa === ca.id" class="mt-4 pt-4 border-t border-base-300 space-y-4">
              <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div>
                  <div class="text-base-content/60 mb-1">Expires</div>
                  <div class="font-mono">{{ formatDate(ca.not_after) }}</div>
                </div>
                <div>
                  <div class="text-base-content/60 mb-1">Certificates issued</div>
                  <div class="font-bold tabular-nums">{{ ca.certificates_issued_count }}</div>
                </div>
                <div>
                  <div class="text-base-content/60 mb-1">CRL</div>
                  <div v-if="ca.crl_distribution_url" class="flex items-center gap-1">
                    <CircleCheck v-if="ca.is_crl_fresh" class="w-3.5 h-3.5 text-success" />
                    <CircleX v-else class="w-3.5 h-3.5 text-error" />
                    <span>{{ ca.is_crl_fresh ? 'Fresh' : 'Stale' }}</span>
                  </div>
                  <div v-else class="opacity-60">Not published</div>
                </div>
                <div>
                  <div class="text-base-content/60 mb-1">Last checked</div>
                  <div class="font-mono">{{ formatDateTime(ca.crl_last_checked) }}</div>
                </div>
                <div class="col-span-2">
                  <div class="text-base-content/60 mb-1">Subject</div>
                  <div class="font-mono break-all">{{ truncate(ca.subject_dn, 72) }}</div>
                </div>
                <div class="col-span-2">
                  <div class="text-base-content/60 mb-1">Issuer</div>
                  <div class="font-mono break-all">{{ truncate(ca.issuer_dn, 72) }}</div>
                </div>
                <div class="col-span-2 md:col-span-4">
                  <div class="text-base-content/60 mb-1">SHA-256 fingerprint</div>
                  <div class="font-mono text-[10px] break-all">{{ ca.fingerprint_sha256 }}</div>
                </div>
              </div>

              <div class="flex items-center gap-2">
                <button
                  class="btn btn-outline btn-xs gap-1.5"
                  :disabled="checking === ca.id"
                  @click.stop="checkNow(ca)"
                >
                  <RotateCw class="w-3 h-3" :class="checking === ca.id && 'animate-spin'" />
                  Check now
                </button>
                <span v-if="ca.last_alert_sent_at" class="text-[11px] opacity-60">
                  Last alert at the {{ ca.last_alert_threshold }}-day threshold,
                  {{ formatDateTime(ca.last_alert_sent_at) }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="card bg-base-100 border border-base-300">
        <div class="card-body items-center text-center py-12">
          <ShieldCheck class="w-10 h-10 opacity-30" />
          <h3 class="font-bold text-sm">No certificate authorities yet</h3>
          <p class="text-xs opacity-60 max-w-sm">
            Import a CA certificate to start monitoring its expiry, CRL freshness, and the
            certificates it issues.
          </p>
          <button class="btn btn-primary btn-sm gap-2 mt-2" @click="showImport = true">
            <Plus class="w-4 h-4" /> Import CA
          </button>
        </div>
      </div>
    </DataState>

    <!-- Import modal -->
    <dialog class="modal" :class="{ 'modal-open': showImport }">
      <div class="modal-box max-w-lg">
        <h3 class="text-base font-bold mb-1">Import certificate authority</h3>
        <p class="text-xs opacity-60 mb-4">
          CertPilot monitors existing CAs rather than generating them. Paste the authority's
          certificate; subject, validity, key details and revocation URLs are read from it.
        </p>

        <div v-if="importError" role="alert" class="alert alert-error mb-3">
          <CircleX class="w-4 h-4 shrink-0" />
          <span class="text-xs break-words">{{ importError }}</span>
        </div>

        <form class="space-y-3" @submit.prevent="importCA">
          <div class="form-control">
            <label class="label" for="ca-name"><span class="label-text text-xs">Name</span></label>
            <input
              id="ca-name" v-model="form.name" type="text" required
              placeholder="e.g. Corporate Issuing CA"
              class="input input-bordered input-sm"
            />
          </div>

          <div class="form-control">
            <label class="label" for="ca-pem">
              <span class="label-text text-xs">Certificate (PEM)</span>
            </label>
            <textarea
              id="ca-pem" v-model="form.certificate_pem" required rows="6"
              placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"
              class="textarea textarea-bordered textarea-sm font-mono text-[11px]"
            ></textarea>
          </div>

          <div class="form-control">
            <label class="label" for="ca-parent">
              <span class="label-text text-xs">Parent CA</span>
              <span class="label-text-alt text-[10px] opacity-60">Leave empty for a root</span>
            </label>
            <select id="ca-parent" v-model="form.parent_ca_id" class="select select-bordered select-sm">
              <option value="">None — this is a root</option>
              <option v-for="p in parentOptions" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>

          <details class="collapse collapse-arrow border border-base-300 rounded-lg">
            <summary class="collapse-title text-xs font-medium py-2 min-h-0">
              Revocation endpoints and notes
            </summary>
            <div class="collapse-content space-y-3">
              <p class="text-[11px] opacity-60">
                Read from the certificate when left empty.
              </p>
              <input
                v-model="form.crl_distribution_url" type="url" placeholder="CRL distribution URL"
                class="input input-bordered input-sm w-full"
              />
              <input
                v-model="form.ocsp_responder_url" type="url" placeholder="OCSP responder URL"
                class="input input-bordered input-sm w-full"
              />
              <textarea
                v-model="form.notes" rows="2" placeholder="Notes"
                class="textarea textarea-bordered textarea-sm w-full"
              ></textarea>
            </div>
          </details>

          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" @click="showImport = false">
              Cancel
            </button>
            <button type="submit" class="btn btn-primary btn-sm" :disabled="importing">
              <span v-if="importing" class="loading loading-spinner loading-xs"></span>
              Import
            </button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showImport = false">
        <button>close</button>
      </form>
    </dialog>
  </div>
</template>
