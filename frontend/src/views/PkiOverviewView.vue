<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useCasStore } from '@/stores/cas'
import DataState from '@/components/common/DataState.vue'
import PanelBox from '@/components/ui/PanelBox.vue'
import Readout from '@/components/ui/Readout.vue'
import SevChip from '@/components/ui/SevChip.vue'
import {
  ShieldCheck, Plus, ChevronDown, ChevronRight, Lock, Server, Stamp,
  RotateCw, CircleCheck, CircleX,
} from 'lucide-vue-next'
import { caSeverity, sevClass, statusLabel } from '@/lib/severity'
import { formatDate, formatDateTime, formatDays, truncate } from '@/lib/format'
import type { CaAuthority } from '@/lib/types'

const api = useApi()

// Shared with the dashboard and kept current by the event stream, so a CA that
// goes critical while this page is open reorders itself without a reload — and
// the two pages cannot show different states of the same estate.
const cas = useCasStore()

const authorities = computed(() => cas.authorities)
// Most urgent first — an expiring issuing CA takes down everything it signed,
// so it must never be below the fold.
const byUrgency = computed(() => cas.byUrgency)

const rootCount = computed(() => cas.countByType.ROOT ?? 0)
const intermediateCount = computed(() => cas.countByType.INTERMEDIATE ?? 0)
const issuingCount = computed(() => cas.countByType.ISSUING ?? 0)

// Re-validate on entry. The store usually already holds live data, so this only
// matters when the stream never came up.
onMounted(() => {
  if (!cas.loaded) void cas.refresh()
})

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
    // Surfaced in the dialog rather than an alert() the operator cannot copy.
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
  <div class="flex flex-col gap-3">
    <div class="toolbar justify-between">
      <p class="prose-ui text-[length:var(--fs-small)] text-[color:var(--text-muted)]">
        Certificate authorities under management, most urgent first
      </p>
      <div class="toolbar">
        <button class="btn-console" :disabled="cas.loading" @click="cas.refresh()">
          <RotateCw class="w-3 h-3" :class="cas.loading && 'animate-spin'" />
          Refresh
        </button>
        <button class="btn-console" data-variant="signal" @click="showImport = true">
          <Plus class="w-3 h-3" /> Import CA
        </button>
      </div>
    </div>

    <div v-if="checkError" role="alert" class="notice" data-tone="critical">
      <CircleX class="w-4 h-4 notice-icon" />
      <span>{{ checkError }}</span>
    </div>

    <DataState
      :loading="cas.loading"
      :error="cas.error"
      :loaded="cas.loaded"
      @retry="cas.refresh()"
    >
      <div class="flex flex-col gap-3">
        <PanelBox label="Hierarchy">
          <div class="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-3">
            <Readout :value="authorities.length" label="Total CAs" />
            <Readout :value="rootCount" label="Root" />
            <Readout :value="intermediateCount" label="Intermediate" />
            <Readout :value="issuingCount" label="Issuing" />
          </div>
        </PanelBox>

        <PanelBox
          v-if="byUrgency.length"
          label="Authorities"
          :note="`${byUrgency.length} MONITORED`"
          flush
        >
          <div class="overflow-x-auto">
            <table class="tbl">
              <thead>
                <tr>
                  <th class="rail"></th>
                  <th>Authority</th>
                  <th>Type</th>
                  <th>Key</th>
                  <th class="num">Remaining</th>
                  <th class="num">Issued</th>
                  <th>State</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <template v-for="ca in byUrgency" :key="ca.id">
                  <tr
                    data-clickable="true"
                    :data-selected="expandedCa === ca.id"
                    role="button"
                    tabindex="0"
                    :aria-expanded="expandedCa === ca.id"
                    @click="toggleExpand(ca.id)"
                    @keydown.enter="toggleExpand(ca.id)"
                    @keydown.space.prevent="toggleExpand(ca.id)"
                  >
                    <td class="rail" :class="`sev-bg-${caSeverity(ca.status)}`"></td>
                    <td class="cell-primary">
                      <span class="flex items-center gap-2 min-w-0">
                        <component
                          :is="typeIcon(ca.ca_type)"
                          class="w-3.5 h-3.5 shrink-0 text-[color:var(--text-muted)]"
                        />
                        <span class="truncate">{{ ca.name }}</span>
                      </span>
                    </td>
                    <td>{{ statusLabel(ca.ca_type) }}</td>
                    <td>
                      {{ ca.key_type }}<template v-if="ca.key_size">-{{ ca.key_size }}</template>
                    </td>
                    <td class="num" :class="sevClass(caSeverity(ca.status))">
                      {{ formatDays(ca.days_remaining) }}
                    </td>
                    <td class="num">{{ ca.certificates_issued_count }}</td>
                    <td>
                      <SevChip
                        :severity="caSeverity(ca.status)"
                        :label="statusLabel(ca.status)"
                      />
                    </td>
                    <td class="num">
                      <ChevronDown
                        v-if="expandedCa === ca.id"
                        class="w-3.5 h-3.5 inline text-[color:var(--text-muted)]"
                      />
                      <ChevronRight
                        v-else
                        class="w-3.5 h-3.5 inline text-[color:var(--text-muted)]"
                      />
                    </td>
                  </tr>

                  <tr v-if="expandedCa === ca.id" :key="`${ca.id}-detail`">
                    <td class="rail" :class="`sev-bg-${caSeverity(ca.status)}`"></td>
                    <td colspan="7" class="!whitespace-normal !py-3">
                      <div class="flex flex-col gap-3">
                        <dl class="kv md:grid-cols-[auto_1fr_auto_1fr] md:gap-x-5">
                          <dt>Expires</dt>
                          <dd>{{ formatDate(ca.not_after) }}</dd>

                          <dt>Certificates issued</dt>
                          <dd>{{ ca.certificates_issued_count }}</dd>

                          <dt>CRL</dt>
                          <dd>
                            <span v-if="ca.crl_distribution_url" class="flex items-center gap-1.5">
                              <CircleCheck
                                v-if="ca.is_crl_fresh"
                                class="w-3.5 h-3.5 sev-ok"
                              />
                              <CircleX v-else class="w-3.5 h-3.5 sev-critical" />
                              <span :class="ca.is_crl_fresh ? 'sev-ok' : 'sev-critical'">
                                {{ ca.is_crl_fresh ? 'Fresh' : 'Stale' }}
                              </span>
                            </span>
                            <span v-else class="text-[color:var(--text-muted)]">Not published</span>
                          </dd>

                          <dt>Last checked</dt>
                          <dd>{{ formatDateTime(ca.crl_last_checked) }}</dd>

                          <dt>Subject</dt>
                          <dd>{{ truncate(ca.subject_dn, 96) }}</dd>

                          <dt>Issuer</dt>
                          <dd>{{ truncate(ca.issuer_dn, 96) }}</dd>

                          <dt>SHA-256</dt>
                          <dd class="text-[length:var(--fs-micro)]">{{ ca.fingerprint_sha256 }}</dd>
                        </dl>

                        <div class="toolbar">
                          <button
                            class="btn-console"
                            :disabled="checking === ca.id"
                            @click.stop="checkNow(ca)"
                          >
                            <span v-if="checking === ca.id" class="spinner-console"></span>
                            <RotateCw v-else class="w-3 h-3" />
                            Check now
                          </button>
                          <span
                            v-if="ca.last_alert_sent_at"
                            class="field-help"
                          >
                            Last alert at the {{ ca.last_alert_threshold }}-day threshold,
                            {{ formatDateTime(ca.last_alert_sent_at) }}
                          </span>
                        </div>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
        </PanelBox>

        <!--
          Says why it is empty, not that all is well. "No certificate authorities
          yet" on a monitoring product must never be mistakeable for a clean
          bill of health: the screen is blank because nothing was imported.
        -->
        <PanelBox v-else label="Authorities">
          <div class="empty-console">
            <strong>No certificate authorities are being monitored.</strong>
            This page is empty because nothing has been imported yet, not because
            the estate is healthy. Import a CA certificate to start tracking its
            expiry, CRL freshness, and the certificates it issues.
            <div class="mt-3">
              <button class="btn-console" data-variant="signal" @click="showImport = true">
                <Plus class="w-3 h-3" /> Import CA
              </button>
            </div>
          </div>
        </PanelBox>
      </div>
    </DataState>

    <!-- Import dialog -->
    <div
      v-if="showImport"
      class="dialog-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-ca-title"
      @click.self="showImport = false"
      @keydown.esc="showImport = false"
    >
      <div class="dialog-panel">
        <header class="panel-head">
          <span id="import-ca-title" class="label-rail">Import certificate authority</span>
        </header>

        <form @submit.prevent="importCA">
          <div class="dialog-body flex flex-col gap-3">
            <p class="field-help">
              CertPilot monitors existing CAs rather than generating them. Paste the
              authority's certificate; subject, validity, key details and revocation
              URLs are read from it.
            </p>

            <div v-if="importError" role="alert" class="notice" data-tone="critical">
              <CircleX class="w-4 h-4 notice-icon" />
              <span class="break-words">{{ importError }}</span>
            </div>

            <div class="field">
              <label class="label-micro" for="ca-name">Name</label>
              <input
                id="ca-name" v-model="form.name" type="text" required
                placeholder="e.g. Corporate Issuing CA"
                class="input-console"
              />
            </div>

            <div class="field">
              <label class="label-micro" for="ca-pem">Certificate (PEM)</label>
              <textarea
                id="ca-pem" v-model="form.certificate_pem" required rows="7" data-pem
                placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"
                class="textarea-console"
              ></textarea>
            </div>

            <div class="field">
              <label class="label-micro" for="ca-parent">Parent CA</label>
              <select id="ca-parent" v-model="form.parent_ca_id" class="select-console">
                <option value="">None — this is a root</option>
                <option v-for="p in parentOptions" :key="p.id" :value="p.id">{{ p.name }}</option>
              </select>
              <span class="field-help">Leave as "none" for a root authority.</span>
            </div>

            <details class="border border-[color:var(--line)]">
              <summary
                class="label-micro cursor-pointer select-none px-2.5 py-2 bg-[color:var(--ink-rail)]"
              >
                Revocation endpoints and notes
              </summary>
              <div class="flex flex-col gap-3 p-2.5">
                <p class="field-help">Read from the certificate when left empty.</p>
                <div class="field">
                  <label class="label-micro" for="ca-crl">CRL distribution URL</label>
                  <input
                    id="ca-crl" v-model="form.crl_distribution_url" type="url"
                    class="input-console"
                  />
                </div>
                <div class="field">
                  <label class="label-micro" for="ca-ocsp">OCSP responder URL</label>
                  <input
                    id="ca-ocsp" v-model="form.ocsp_responder_url" type="url"
                    class="input-console"
                  />
                </div>
                <div class="field">
                  <label class="label-micro" for="ca-notes">Notes</label>
                  <textarea
                    id="ca-notes" v-model="form.notes" rows="2"
                    class="textarea-console !min-h-0"
                  ></textarea>
                </div>
              </div>
            </details>
          </div>

          <div class="dialog-foot">
            <button type="button" class="btn-console" @click="showImport = false">
              Cancel
            </button>
            <button
              type="submit"
              class="btn-console"
              data-variant="signal"
              :disabled="importing"
            >
              <span v-if="importing" class="spinner-console"></span>
              Import
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>
