<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Bell, CircleCheck, CircleX, Plus, Send, Trash2 } from 'lucide-vue-next'
import { useApi } from '@/composables/useApi'
import { formatDateTime } from '@/lib/format'
import type {
  NotificationChannel,
  NotificationChannelList,
  NotificationTestResult,
} from '@/lib/types'

/**
 * Alert delivery channels.
 *
 * Deliberately plain: this is the minimum needed to configure a channel and
 * prove it delivers, pending the wider UI redesign. The behaviour worth keeping
 * through that redesign is the test button and how its result is shown — an
 * alerting channel nobody has ever sent through is a promise, not a capability,
 * and the destination's own complaint ("invalid_token", "connection refused") is
 * the only useful thing about a failure.
 *
 * Configuration is write-only. The server never returns a Slack webhook URL or
 * an SMTP password, so this form cannot pre-fill them and does not pretend to:
 * editing a channel without re-entering its config keeps what is stored.
 */

const api = useApi()

const channels = ref<NotificationChannel[]>([])
const supportedTypes = ref<string[]>([])
const topics = ref<string[]>([])
const loading = ref(false)
const error = ref<string | null>(null)

/** Per-channel test outcome, keyed by id. */
const results = ref<Record<string, NotificationTestResult>>({})
const testing = ref<string | null>(null)
const busy = ref<string | null>(null)

async function load() {
  loading.value = true
  try {
    const res = await api.get<NotificationChannelList>('/api/v1/notification-channels')
    channels.value = res.data ?? []
    supportedTypes.value = res.supported_types ?? []
    topics.value = res.topics ?? []
    error.value = null
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

// ── Create ────────────────────────────────────────────────

const showForm = ref(false)
const saving = ref(false)
const formError = ref<string | null>(null)

const blank = () => ({
  name: '',
  channel_type: 'slack' as NotificationChannel['channel_type'],
  severity_threshold: 'WARNING' as NotificationChannel['severity_threshold'],
  topics: [] as string[],
  // One config object per type, so switching type does not carry a Slack URL
  // into an SMTP form.
  slack: { webhook_url: '' },
  webhook: { url: '', signing_secret: '' },
  email: { host: '', port: 587, username: '', password: '', from: '', to: '' },
})
const form = ref(blank())

/** The config the server expects for the selected type. */
const configForType = computed<Record<string, unknown>>(() => {
  switch (form.value.channel_type) {
    case 'slack':
      return { webhook_url: form.value.slack.webhook_url }
    case 'webhook':
      return {
        url: form.value.webhook.url,
        // Omitted rather than sent empty: the server rejects a short secret,
        // and "" would read as an attempt to configure one.
        ...(form.value.webhook.signing_secret
          ? { signing_secret: form.value.webhook.signing_secret }
          : {}),
      }
    case 'email':
      return {
        host: form.value.email.host,
        port: Number(form.value.email.port) || 587,
        username: form.value.email.username || undefined,
        password: form.value.email.password || undefined,
        from: form.value.email.from,
        to: form.value.email.to
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      }
    default:
      return {}
  }
})

async function create() {
  saving.value = true
  formError.value = null
  try {
    await api.post('/api/v1/notification-channels', {
      name: form.value.name,
      channel_type: form.value.channel_type,
      severity_threshold: form.value.severity_threshold,
      topics: form.value.topics,
      config: configForType.value,
    })
    showForm.value = false
    form.value = blank()
    await load()
  } catch (err) {
    // Shown in the form. The server's message names the exact field that is
    // wrong, which is the whole point of validating before sealing.
    formError.value = err instanceof Error ? err.message : String(err)
  } finally {
    saving.value = false
  }
}

// ── Act on an existing channel ────────────────────────────

async function sendTest(channel: NotificationChannel) {
  testing.value = channel.id
  try {
    results.value[channel.id] = await api.post<NotificationTestResult>(
      `/api/v1/notification-channels/${channel.id}/test`,
    )
  } catch (err) {
    // A failed test returns 502 with the destination's reason in the body,
    // which useApi turns into the thrown error's message.
    results.value[channel.id] = {
      delivered: false,
      error: err instanceof Error ? err.message : String(err),
    }
  } finally {
    testing.value = null
    void load()
  }
}

async function toggle(channel: NotificationChannel) {
  busy.value = channel.id
  try {
    // No `config` key: omitting it keeps the sealed credentials, which cannot
    // be read back to re-send them.
    await api.put(`/api/v1/notification-channels/${channel.id}`, {
      name: channel.name,
      channel_type: channel.channel_type,
      severity_threshold: channel.severity_threshold,
      topics: channel.topics,
      is_enabled: !channel.is_enabled,
    })
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = null
  }
}

async function remove(channel: NotificationChannel) {
  busy.value = channel.id
  try {
    await api.delete(`/api/v1/notification-channels/${channel.id}`)
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = null
  }
}
</script>

<template>
  <section class="card bg-base-100 border border-base-300">
    <div class="card-body p-5 gap-4">
      <div class="flex items-start justify-between gap-3">
        <div>
          <h2 class="card-title text-sm font-bold flex items-center gap-2">
            <Bell class="w-4 h-4 text-primary" />
            Alert delivery
          </h2>
          <p class="text-xs opacity-60 mt-1">
            Where CA expiry and renewal failures are sent. A channel that has never been tested is
            a promise, not a capability.
          </p>
        </div>
        <button class="btn btn-primary btn-sm gap-1.5" @click="showForm = !showForm">
          <Plus class="w-4 h-4" /> Add
        </button>
      </div>

      <div v-if="error" role="alert" class="alert alert-error py-2">
        <CircleX class="w-4 h-4 shrink-0" />
        <span class="text-xs break-words">{{ error }}</span>
      </div>

      <!-- Create -->
      <form v-if="showForm" class="border border-base-300 rounded-lg p-4 space-y-3" @submit.prevent="create">
        <div v-if="formError" role="alert" class="alert alert-error py-2">
          <CircleX class="w-4 h-4 shrink-0" />
          <span class="text-xs break-words">{{ formError }}</span>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <input
            v-model="form.name" required placeholder="Name, e.g. pki-oncall"
            class="input input-bordered input-sm sm:col-span-2"
          />
          <select v-model="form.channel_type" class="select select-bordered select-sm">
            <option v-for="t in supportedTypes" :key="t" :value="t">{{ t }}</option>
          </select>
        </div>

        <!-- Slack -->
        <input
          v-if="form.channel_type === 'slack'"
          v-model="form.slack.webhook_url" type="url" required
          placeholder="https://hooks.slack.com/services/…"
          class="input input-bordered input-sm w-full font-mono text-xs"
        />

        <!-- Webhook -->
        <template v-else-if="form.channel_type === 'webhook'">
          <input
            v-model="form.webhook.url" type="url" required placeholder="https://receiver.example.com/hook"
            class="input input-bordered input-sm w-full font-mono text-xs"
          />
          <input
            v-model="form.webhook.signing_secret" placeholder="Signing secret (optional, 16+ characters)"
            class="input input-bordered input-sm w-full font-mono text-xs"
          />
          <p class="text-[11px] opacity-60">
            With a secret, each delivery carries an HMAC-SHA256 over
            <code>timestamp.body</code> in <code>X-CertPilot-Signature</code>.
          </p>
        </template>

        <!-- Email -->
        <template v-else-if="form.channel_type === 'email'">
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input v-model="form.email.host" required placeholder="SMTP host" class="input input-bordered input-sm sm:col-span-2" />
            <input v-model.number="form.email.port" type="number" placeholder="587" class="input input-bordered input-sm" />
            <input v-model="form.email.username" placeholder="Username (optional)" class="input input-bordered input-sm" />
            <input v-model="form.email.password" type="password" placeholder="Password (optional)" class="input input-bordered input-sm" />
            <input v-model="form.email.from" required placeholder="From address" class="input input-bordered input-sm" />
            <input v-model="form.email.to" required placeholder="To, comma separated" class="input input-bordered input-sm sm:col-span-3" />
          </div>
        </template>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <label class="form-control">
            <span class="label-text text-xs">Minimum severity</span>
            <select v-model="form.severity_threshold" class="select select-bordered select-sm">
              <option value="INFO">INFO — everything</option>
              <option value="WARNING">WARNING and above</option>
              <option value="CRITICAL">CRITICAL only</option>
            </select>
          </label>
          <label class="form-control">
            <span class="label-text text-xs">Topics — none selected means all</span>
            <select v-model="form.topics" multiple class="select select-bordered select-sm h-24">
              <option v-for="t in topics" :key="t" :value="t">{{ t }}</option>
            </select>
          </label>
        </div>

        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-ghost btn-sm" @click="showForm = false">Cancel</button>
          <button type="submit" class="btn btn-primary btn-sm" :disabled="saving">
            <span v-if="saving" class="loading loading-spinner loading-xs"></span>
            Save
          </button>
        </div>
      </form>

      <!-- List -->
      <div v-if="loading && !channels.length" class="text-xs opacity-60">Loading…</div>

      <div v-else-if="!channels.length" class="text-xs opacity-60 py-4 text-center">
        No channels configured. CA expiry alerts are recorded in the audit log and shown on the
        dashboard, but nobody is being told.
      </div>

      <div v-else class="space-y-2">
        <div
          v-for="channel in channels"
          :key="channel.id"
          class="border border-base-300 rounded-lg p-3"
        >
          <div class="flex items-center justify-between gap-3 flex-wrap">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="font-bold text-sm">{{ channel.name }}</span>
                <span class="badge badge-ghost badge-xs">{{ channel.channel_type }}</span>
                <span
                  class="badge badge-xs"
                  :class="channel.is_enabled ? 'badge-success' : 'badge-ghost'"
                >
                  {{ channel.is_enabled ? 'enabled' : 'disabled' }}
                </span>
              </div>
              <div class="text-[11px] opacity-60 mt-0.5">
                {{ channel.severity_threshold }} and above ·
                {{ channel.topics.length ? channel.topics.join(', ') : 'all topics' }} ·
                <template v-if="channel.last_sent_at">
                  last delivered {{ formatDateTime(channel.last_sent_at) }}
                </template>
                <template v-else>never delivered</template>
              </div>
            </div>

            <div class="flex items-center gap-1.5 shrink-0">
              <button
                class="btn btn-outline btn-xs gap-1.5"
                :disabled="testing === channel.id"
                @click="sendTest(channel)"
              >
                <Send class="w-3 h-3" />
                {{ testing === channel.id ? 'Sending…' : 'Send test' }}
              </button>
              <button class="btn btn-ghost btn-xs" :disabled="busy === channel.id" @click="toggle(channel)">
                {{ channel.is_enabled ? 'Disable' : 'Enable' }}
              </button>
              <button class="btn btn-ghost btn-xs text-error" :disabled="busy === channel.id" @click="remove(channel)">
                <Trash2 class="w-3 h-3" />
              </button>
            </div>
          </div>

          <!-- The destination's own answer, verbatim. "invalid_token" tells an
               operator what to fix; "delivery failed" does not. -->
          <div
            v-if="results[channel.id]"
            class="mt-2 text-xs flex items-start gap-1.5"
            :class="results[channel.id].delivered ? 'text-success' : 'text-error'"
          >
            <CircleCheck v-if="results[channel.id].delivered" class="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <CircleX v-else class="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span class="break-words">
              {{ results[channel.id].delivered
                ? 'Accepted by the destination — confirm it arrived.'
                : results[channel.id].error }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
