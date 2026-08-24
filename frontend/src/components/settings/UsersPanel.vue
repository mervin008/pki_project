<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UserCog, UserPlus, KeyRound, AlertTriangle, Copy, Check } from 'lucide-vue-next'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/auth'
import DataState from '@/components/common/DataState.vue'

/**
 * Accounts, for an administrator.
 *
 * Roles live in CertPilot rather than in the identity provider, which is what
 * makes this screen the place a role actually changes. Before it existed the
 * only way to promote a colleague was a SQL update.
 */

interface User {
  id: string
  email?: string
  display_name?: string
  issuer: string
  subject: string
  role: 'admin' | 'operator' | 'auditor' | 'viewer'
  status: 'ACTIVE' | 'SUSPENDED'
  role_source: 'DEFAULT' | 'BOOTSTRAP' | 'ASSIGNED'
  last_seen_at?: string
  must_change_password?: boolean
}

const api = useApi()
const auth = useAuthStore()

const users = ref<User[]>([])
const loading = ref(true)
const error = ref<string | null>(null)
const loaded = ref(false)

const busy = ref<string | null>(null)
const actionError = ref<string | null>(null)

// A password is shown once. Held here until dismissed, never re-fetchable.
const revealed = ref<{ email: string; password: string } | null>(null)
const copied = ref(false)

const creating = ref(false)
const newEmail = ref('')
const newRole = ref<User['role']>('viewer')

const ROLES: User['role'][] = ['viewer', 'auditor', 'operator', 'admin']

/** Signed-in administrators, so the UI can explain a refusal before it happens. */
const activeAdmins = computed(
  () => users.value.filter((u) => u.role === 'admin' && u.status === 'ACTIVE').length,
)

function isLastAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'ACTIVE' && activeAdmins.value === 1
}

async function load() {
  loading.value = true
  error.value = null
  try {
    const response = await api.get<{ data: User[] }>('/api/v1/users')
    users.value = response.data
    loaded.value = true
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

async function changeRole(user: User, role: User['role']) {
  if (role === user.role) return
  busy.value = user.id
  actionError.value = null
  try {
    await api.patch(`/api/v1/users/${user.id}`, { role })
    await load()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
    // Reloaded so the select snaps back to what the server actually holds,
    // rather than showing a change that did not happen.
    await load()
  } finally {
    busy.value = null
  }
}

async function setStatus(user: User, status: User['status']) {
  busy.value = user.id
  actionError.value = null
  try {
    await api.patch(`/api/v1/users/${user.id}`, { status })
    await load()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = null
  }
}

async function resetPassword(user: User) {
  busy.value = user.id
  actionError.value = null
  try {
    const response = await api.post<{ initial_password: string }>(
      `/api/v1/users/${user.id}/password`,
    )
    revealed.value = { email: user.email ?? user.subject, password: response.initial_password }
    await load()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = null
  }
}

async function createUser() {
  busy.value = 'new'
  actionError.value = null
  try {
    const response = await api.post<{ initial_password?: string }>('/api/v1/users', {
      email: newEmail.value.trim(),
      role: newRole.value,
    })
    if (response.initial_password) {
      revealed.value = { email: newEmail.value.trim(), password: response.initial_password }
    }
    newEmail.value = ''
    newRole.value = 'viewer'
    creating.value = false
    await load()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = null
  }
}

async function copyPassword() {
  if (!revealed.value) return
  await navigator.clipboard.writeText(revealed.value.password)
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}

function lastSeen(user: User): string {
  if (!user.last_seen_at) return 'Never'
  const days = Math.floor((Date.now() - new Date(user.last_seen_at).getTime()) / 86_400_000)
  if (days === 0) return 'Today'
  if (days === 1) return 'Yesterday'
  return `${days}d ago`
}
</script>

<template>
  <section class="panel">
    <header class="panel-head">
      <div class="flex items-center gap-2">
        <UserCog class="w-4 h-4" style="color: var(--signal)" />
        <h2 class="label-rail">Accounts</h2>
      </div>
      <button v-if="!creating" class="btn-console" @click="creating = true">
        <UserPlus class="w-3 h-3" />
        Add account
      </button>
    </header>

    <p class="field-help panel-intro">
      CertPilot decides what an account may do, not your identity provider. A role changes here and
      applies on the account's next request.
    </p>

    <!-- Shown once. Kept until dismissed rather than auto-hidden: a password
         that disappears on a timer is a password somebody has to reset. -->
    <div v-if="revealed" class="reveal">
      <KeyRound class="w-4 h-4 shrink-0" style="color: var(--sev-warning)" />
      <div class="flex-1 min-w-0">
        <p class="label-rail sev-warning">Password for {{ revealed.email }}</p>
        <code class="reveal-value">{{ revealed.password }}</code>
        <p class="field-help">
          Shown once and not recoverable. They will be asked to change it when they sign in.
        </p>
      </div>
      <button class="btn-console" @click="copyPassword">
        <component :is="copied ? Check : Copy" class="w-3 h-3" />
        {{ copied ? 'Copied' : 'Copy' }}
      </button>
      <button class="btn-console" @click="revealed = null">Dismiss</button>
    </div>

    <form v-if="creating" class="create-row" @submit.prevent="createUser">
      <input
        v-model="newEmail"
        type="email"
        required
        placeholder="colleague@example.com"
        class="input-console flex-1"
      />
      <select v-model="newRole" class="input-console">
        <option v-for="role in ROLES" :key="role" :value="role">{{ role }}</option>
      </select>
      <button class="btn-console" type="submit" :disabled="busy === 'new'">
        {{ busy === 'new' ? 'Creating…' : 'Create' }}
      </button>
      <button class="btn-console" type="button" @click="creating = false">Cancel</button>
    </form>

    <div v-if="actionError" role="alert" class="action-error">
      <AlertTriangle class="w-4 h-4 shrink-0 sev-critical" />
      <p class="state-error-detail">{{ actionError }}</p>
    </div>

    <DataState :loading="loading" :error="error" :loaded="loaded" @retry="load">
      <table class="tbl">
        <thead>
          <tr>
            <th>Account</th>
            <th>Role</th>
            <th>Source</th>
            <th>Last seen</th>
            <th>Status</th>
            <th class="text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id" :class="{ suspended: user.status === 'SUSPENDED' }">
            <td>
              <div class="who">{{ user.email || user.subject }}</div>
              <div class="label-micro">
                {{ user.issuer === 'certpilot-local' ? 'Local account' : user.issuer }}
                <span v-if="user.id === auth.me?.user_id"> · you</span>
              </div>
            </td>
            <td>
              <select
                class="input-console role-select"
                :value="user.role"
                :disabled="busy === user.id || isLastAdmin(user)"
                :title="isLastAdmin(user) ? 'The only administrator cannot be demoted' : ''"
                @change="changeRole(user, ($event.target as HTMLSelectElement).value as User['role'])"
              >
                <option v-for="role in ROLES" :key="role" :value="role">{{ role }}</option>
              </select>
            </td>
            <td><span class="label-micro">{{ user.role_source }}</span></td>
            <td class="tabular">{{ lastSeen(user) }}</td>
            <td>
              <span :class="user.status === 'ACTIVE' ? 'sev-ok' : 'sev-critical'">
                {{ user.status }}
              </span>
            </td>
            <td class="text-right">
              <button class="btn-console" :disabled="busy === user.id" @click="resetPassword(user)">
                Reset password
              </button>
              <button
                v-if="user.status === 'ACTIVE'"
                class="btn-console"
                :disabled="busy === user.id || isLastAdmin(user)"
                :title="isLastAdmin(user) ? 'The only administrator cannot be suspended' : ''"
                @click="setStatus(user, 'SUSPENDED')"
              >
                Suspend
              </button>
              <button v-else class="btn-console" :disabled="busy === user.id" @click="setStatus(user, 'ACTIVE')">
                Reinstate
              </button>
            </td>
          </tr>
        </tbody>
      </table>

      <p v-if="!users.length" class="field-help">
        No accounts yet. That should not be possible — you are signed in.
      </p>
    </DataState>
  </section>
</template>

<style scoped>
.panel {
  background: var(--ink-panel);
  border: 1px solid var(--line);
  padding: 0.875rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.panel-intro { margin-top: -0.25rem; }

.create-row {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.reveal {
  display: flex;
  align-items: flex-start;
  gap: 0.625rem;
  padding: 0.75rem;
  border: 1px solid var(--sev-warning);
  background: var(--sev-warning-wash);
}

.reveal-value {
  display: block;
  margin: 0.25rem 0;
  font-family: var(--font-mono);
  font-size: var(--fs-body);
  letter-spacing: 0.04em;
  color: var(--text-primary);
  user-select: all;
}

.action-error {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.5rem 0.625rem;
  border: 1px solid var(--sev-critical);
  background: var(--sev-critical-wash);
}

.who {
  font-family: var(--font-mono);
  font-size: var(--fs-small);
  color: var(--text-primary);
}

.role-select { min-width: 7rem; }
.tabular { font-variant-numeric: tabular-nums; }

/* Suspended accounts stay in the list, marked. Filtering them out is how
   somebody's access is believed to be gone while the row still exists. */
.suspended { opacity: 0.62; }
</style>
