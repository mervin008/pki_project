<script setup lang="ts">
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import DataState from '@/components/common/DataState.vue'
import {
  Cpu, Plus, CircleCheck, CircleX, RotateCw, Server, Stamp, Trash2,
} from 'lucide-vue-next'
import { formatDateTime } from '@/lib/format'
import type { CaAccount, GatewaySummary, ListResponse } from '@/lib/types'

const api = useApi()

// The correct routes are /gateways and /ca-accounts. This view previously
// called /gateways/accounts for both read and write; neither route has ever
// existed, so both requests 404'd and the page silently showed demo rows.
const gateways = useAsyncData<ListResponse<GatewaySummary>>((s) =>
  api.get<ListResponse<GatewaySummary>>('/api/v1/gateways', s),
)
const accounts = useAsyncData<ListResponse<CaAccount>>((s) =>
  api.get<ListResponse<CaAccount>>('/api/v1/ca-accounts', s),
)

const gatewayList = computed(() => gateways.data.value?.data ?? [])
const accountList = computed(() => accounts.data.value?.data ?? [])

const loading = computed(() => gateways.loading.value || accounts.loading.value)
const loaded = computed(() => gateways.loaded.value && accounts.loaded.value)
const error = computed(() => gateways.error.value ?? accounts.error.value)

function refreshAll() {
  void gateways.refresh()
  void accounts.refresh()
}

function providerIcon(type: string) {
  switch (type) {
    case 'vault': return Server
    case 'selfsigned': return Stamp
    default: return Cpu
  }
}

/** Gateways the core is connected to, for the account form's dropdown. */
const connectedGateways = computed(() => gatewayList.value.filter((g) => g.is_connected))

// ── Add CA account ────────────────────────────────────────
const showAdd = ref(false)
const saving = ref(false)
const addError = ref<string | null>(null)
const addWarnings = ref<string[]>([])

const blankForm = () => ({
  name: '',
  provider_type: 'acme',
  gateway_addr: '',
  server_name: '',
  // Provider-specific settings, sealed by the core before storage.
  directory_url: 'letsencrypt-staging',
  email: '',
  challenge: 'dns-01',
  dns_provider: 'cloudflare',
  api_token: '',
  webhook_url: '',
  webhook_secret: '',
  validity_days: '90',
})
const form = ref(blankForm())

const isAcme = computed(() => form.value.provider_type === 'acme')
const usesDns = computed(() => isAcme.value && form.value.challenge === 'dns-01')

/** Builds the provider-specific `config` blob the gateway will validate. */
function buildConfig(): Record<string, unknown> {
  if (!isAcme.value) {
    return { validity_days: Number(form.value.validity_days) }
  }

  const config: Record<string, unknown> = {
    directory_url: form.value.directory_url,
    email: form.value.email,
    challenge: form.value.challenge,
  }

  if (form.value.challenge === 'dns-01') {
    config.dns_provider = form.value.dns_provider
    config.dns_config =
      form.value.dns_provider === 'cloudflare'
        ? { api_token: form.value.api_token }
        : { url: form.value.webhook_url, signing_secret: form.value.webhook_secret }
  }

  return config
}

async function addAccount() {
  saving.value = true
  addError.value = null
  addWarnings.value = []
  try {
    // The core connects to the gateway and asks it to validate this config
    // before storing anything, so a wrong token is reported here rather than
    // during an unattended renewal months from now.
    const res = await api.post<{ warnings?: string[] }>('/api/v1/ca-accounts', {
      name: form.value.name,
      provider_type: form.value.provider_type,
      gateway_addr: form.value.gateway_addr,
      server_name: form.value.server_name || undefined,
      config: buildConfig(),
    })
    addWarnings.value = res?.warnings ?? []
    if (!addWarnings.value.length) {
      showAdd.value = false
      form.value = blankForm()
    }
    refreshAll()
  } catch (err) {
    addError.value = err instanceof Error ? err.message : String(err)
  } finally {
    saving.value = false
  }
}

// ── Health probe / delete ─────────────────────────────────
const busyId = ref<string | null>(null)
const actionError = ref<string | null>(null)

async function probe(account: CaAccount) {
  busyId.value = account.id
  actionError.value = null
  try {
    await api.post(`/api/v1/ca-accounts/${account.id}/health`)
    await accounts.refresh()
  } catch (err) {
    actionError.value = `Health check for ${account.name} failed: ${
      err instanceof Error ? err.message : String(err)
    }`
  } finally {
    busyId.value = null
  }
}

async function removeAccount(account: CaAccount) {
  if (!confirm(`Remove the CA account "${account.name}"? Certificates it issued are kept.`)) return
  busyId.value = account.id
  actionError.value = null
  try {
    await api.delete(`/api/v1/ca-accounts/${account.id}`)
    await accounts.refresh()
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
      <p class="text-sm text-base-content/60">
        Gateway plugins and the CA accounts that issue through them
      </p>
      <div class="flex items-center gap-2">
        <button class="btn btn-ghost btn-sm gap-1.5" :disabled="loading" @click="refreshAll">
          <RotateCw class="w-3.5 h-3.5" :class="loading && 'animate-spin'" />
          Refresh
        </button>
        <button
          class="btn btn-primary btn-sm gap-2"
          :disabled="!connectedGateways.length"
          :title="connectedGateways.length ? '' : 'Start a gateway process first'"
          @click="showAdd = true"
        >
          <Plus class="w-4 h-4" /> Add CA account
        </button>
      </div>
    </div>

    <div v-if="actionError" role="alert" class="alert alert-error">
      <CircleX class="w-5 h-5 shrink-0" />
      <span class="text-sm break-words">{{ actionError }}</span>
    </div>

    <DataState :loading="loading" :error="error" :loaded="loaded" @retry="refreshAll">
      <!-- Gateway processes -->
      <section class="space-y-3">
        <h2 class="text-sm font-bold">Gateway plugins</h2>
        <div v-if="gatewayList.length" class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div
            v-for="gw in gatewayList" :key="gw.name"
            class="card bg-base-100 border border-base-300"
          >
            <div class="card-body p-4">
              <div class="flex items-start justify-between gap-3">
                <div class="flex items-center gap-3 min-w-0">
                  <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                    <component :is="providerIcon(gw.type)" class="w-4 h-4 text-primary" />
                  </div>
                  <div class="min-w-0">
                    <div class="font-bold text-sm truncate">{{ gw.name }}</div>
                    <div class="text-[11px] font-mono opacity-60 truncate">{{ gw.addr }}</div>
                  </div>
                </div>
                <span
                  class="badge badge-sm gap-1 shrink-0"
                  :class="gw.is_connected ? 'badge-success' : 'badge-error'"
                >
                  <CircleCheck v-if="gw.is_connected" class="w-3 h-3" />
                  <CircleX v-else class="w-3 h-3" />
                  {{ gw.is_connected ? 'Connected' : 'Disconnected' }}
                </span>
              </div>

              <p v-if="gw.capabilities?.description" class="text-[11px] opacity-70 mt-2">
                {{ gw.capabilities.description }}
              </p>

              <div v-if="gw.capabilities" class="flex flex-wrap gap-1 mt-2">
                <span
                  v-for="ch in gw.capabilities.supported_challenges" :key="ch"
                  class="badge badge-ghost badge-xs font-mono"
                >{{ ch }}</span>
                <span
                  v-for="kt in gw.capabilities.supported_key_types" :key="kt"
                  class="badge badge-outline badge-xs font-mono"
                >{{ kt }}</span>
              </div>
            </div>
          </div>
        </div>
        <div v-else class="card bg-base-100 border border-base-300">
          <div class="card-body items-center text-center py-10">
            <Cpu class="w-8 h-8 opacity-30" />
            <p class="text-xs opacity-60 max-w-sm">
              No gateways connected. Start one with
              <code class="font-mono">make run-gateway-acme</code> and make sure it is listed
              under <code class="font-mono">plugins.gateways</code> in your config.
            </p>
          </div>
        </div>
      </section>

      <!-- CA accounts -->
      <section class="space-y-3">
        <h2 class="text-sm font-bold">CA accounts</h2>
        <div v-if="accountList.length" class="card bg-base-100 border border-base-300">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr>
                  <th class="text-xs">Name</th>
                  <th class="text-xs">Provider</th>
                  <th class="text-xs">Gateway</th>
                  <th class="text-xs">Status</th>
                  <th class="text-xs">Last checked</th>
                  <th class="text-xs text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="acc in accountList" :key="acc.id" class="hover">
                  <td class="text-xs font-medium">
                    {{ acc.name }}
                    <span v-if="acc.is_default" class="badge badge-ghost badge-xs ml-1">default</span>
                  </td>
                  <td class="text-xs font-mono">{{ acc.provider_type }}</td>
                  <td class="text-xs font-mono opacity-70">{{ acc.gateway_addr }}</td>
                  <td>
                    <span
                      class="badge badge-sm"
                      :class="{
                        'badge-success': acc.status === 'CONNECTED',
                        'badge-error': acc.status === 'ERROR',
                        'badge-ghost': acc.status === 'DISCONNECTED',
                      }"
                    >{{ acc.status }}</span>
                  </td>
                  <td class="text-xs font-mono opacity-70">{{ formatDateTime(acc.last_health_at) }}</td>
                  <td class="text-right whitespace-nowrap">
                    <button
                      class="btn btn-ghost btn-xs" title="Check now"
                      :disabled="busyId === acc.id" @click="probe(acc)"
                    >
                      <RotateCw class="w-3.5 h-3.5" :class="busyId === acc.id && 'animate-spin'" />
                    </button>
                    <button
                      class="btn btn-ghost btn-xs text-error" title="Remove"
                      :disabled="busyId === acc.id" @click="removeAccount(acc)"
                    >
                      <Trash2 class="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div v-else class="card bg-base-100 border border-base-300">
          <div class="card-body items-center text-center py-10">
            <p class="text-xs opacity-60">
              No CA accounts yet. Add one to start issuing certificates.
            </p>
          </div>
        </div>
      </section>
    </DataState>

    <!-- Add account modal -->
    <dialog class="modal" :class="{ 'modal-open': showAdd }">
      <div class="modal-box max-w-lg">
        <h3 class="text-base font-bold mb-1">Add CA account</h3>
        <p class="text-xs opacity-60 mb-4">
          Credentials are validated by the gateway, then encrypted before storage. They are never
          returned by the API.
        </p>

        <div v-if="addError" role="alert" class="alert alert-error mb-3">
          <CircleX class="w-4 h-4 shrink-0" />
          <span class="text-xs break-words">{{ addError }}</span>
        </div>
        <div v-if="addWarnings.length" role="alert" class="alert alert-warning mb-3">
          <div class="text-xs">
            <p class="font-bold">Saved with warnings</p>
            <ul class="list-disc list-inside">
              <li v-for="w in addWarnings" :key="w">{{ w }}</li>
            </ul>
          </div>
        </div>

        <form class="space-y-3" @submit.prevent="addAccount">
          <div class="grid grid-cols-2 gap-3">
            <div class="form-control">
              <label class="label" for="acc-name"><span class="label-text text-xs">Name</span></label>
              <input
                id="acc-name" v-model="form.name" type="text" required
                placeholder="letsencrypt-prod" class="input input-bordered input-sm"
              />
            </div>
            <div class="form-control">
              <label class="label" for="acc-type"><span class="label-text text-xs">Provider</span></label>
              <select id="acc-type" v-model="form.provider_type" class="select select-bordered select-sm">
                <option value="acme">ACME</option>
                <option value="selfsigned">Self-signed (dev)</option>
              </select>
            </div>
          </div>

          <div class="form-control">
            <label class="label" for="acc-gw"><span class="label-text text-xs">Gateway</span></label>
            <select id="acc-gw" v-model="form.gateway_addr" required class="select select-bordered select-sm">
              <option value="" disabled>Select a connected gateway</option>
              <option v-for="gw in connectedGateways" :key="gw.name" :value="gw.addr">
                {{ gw.name }} — {{ gw.addr }}
              </option>
            </select>
          </div>

          <template v-if="isAcme">
            <div class="grid grid-cols-2 gap-3">
              <div class="form-control">
                <label class="label" for="acc-dir"><span class="label-text text-xs">Directory</span></label>
                <select id="acc-dir" v-model="form.directory_url" class="select select-bordered select-sm">
                  <option value="letsencrypt-staging">Let's Encrypt staging</option>
                  <option value="letsencrypt">Let's Encrypt production</option>
                  <option value="zerossl">ZeroSSL</option>
                  <option value="buypass">BuyPass</option>
                  <option value="google">Google Trust Services</option>
                </select>
              </div>
              <div class="form-control">
                <label class="label" for="acc-ch"><span class="label-text text-xs">Challenge</span></label>
                <select id="acc-ch" v-model="form.challenge" class="select select-bordered select-sm">
                  <option value="dns-01">dns-01 (needed for wildcards)</option>
                  <option value="http-01">http-01</option>
                </select>
              </div>
            </div>

            <div class="form-control">
              <label class="label" for="acc-email"><span class="label-text text-xs">Contact email</span></label>
              <input
                id="acc-email" v-model="form.email" type="email" required
                placeholder="pki@example.com" class="input input-bordered input-sm"
              />
            </div>

            <template v-if="usesDns">
              <div class="form-control">
                <label class="label" for="acc-dns"><span class="label-text text-xs">DNS provider</span></label>
                <select id="acc-dns" v-model="form.dns_provider" class="select select-bordered select-sm">
                  <option value="cloudflare">Cloudflare</option>
                  <option value="webhook">Webhook (any other provider)</option>
                </select>
              </div>

              <input
                v-if="form.dns_provider === 'cloudflare'"
                v-model="form.api_token" type="password" required
                placeholder="Cloudflare API token (Zone:Read, DNS:Edit)"
                class="input input-bordered input-sm w-full"
              />
              <template v-else>
                <input
                  v-model="form.webhook_url" type="url" required
                  placeholder="https://dns-hook.internal/acme"
                  class="input input-bordered input-sm w-full"
                />
                <input
                  v-model="form.webhook_secret" type="password"
                  placeholder="HMAC signing secret (recommended)"
                  class="input input-bordered input-sm w-full"
                />
              </template>
            </template>
          </template>

          <div v-else class="form-control">
            <label class="label" for="acc-validity">
              <span class="label-text text-xs">Validity (days)</span>
            </label>
            <input
              id="acc-validity" v-model="form.validity_days" type="number" min="1"
              class="input input-bordered input-sm"
            />
          </div>

          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" @click="showAdd = false">Cancel</button>
            <button type="submit" class="btn btn-primary btn-sm" :disabled="saving">
              <span v-if="saving" class="loading loading-spinner loading-xs"></span>
              Add account
            </button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showAdd = false">
        <button>close</button>
      </form>
    </dialog>
  </div>
</template>
