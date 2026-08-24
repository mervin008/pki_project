<script setup lang="ts">
import { ref } from 'vue'
import { KeyRound, AlertTriangle } from 'lucide-vue-next'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/auth'

/**
 * Insists on a new password when the current one was not chosen by its owner.
 *
 * Shown for a generated credential — the one printed at first start, or the one
 * an administrator produced when creating the account. Somebody other than the
 * account holder currently knows it, and it has almost certainly been through a
 * terminal, a chat message, or both.
 *
 * Modal rather than a banner, and not dismissable. A prompt that can be
 * postponed is a prompt that is postponed, and the credential it is about is
 * one two people know.
 */

const api = useApi()
const auth = useAuthStore()

const current = ref('')
const next = ref('')
const confirm = ref('')
const busy = ref(false)
const error = ref<string | null>(null)

async function submit() {
  error.value = null

  // Checked here as well as by the API, because this is the one the person can
  // act on without a round trip.
  if (next.value !== confirm.value) {
    error.value = 'The two new passwords do not match.'
    return
  }

  busy.value = true
  try {
    await api.post('/api/v1/auth/password', {
      current_password: current.value,
      new_password: next.value,
    })
    // Re-read rather than assumed: the API is the authority on whether this is
    // now satisfied.
    await auth.loadMe()
  } catch (err) {
    error.value = err instanceof Error ? err.message : String(err)
    current.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="prompt-backdrop">
    <div class="prompt" role="dialog" aria-modal="true" aria-labelledby="pw-title">
      <div class="flex items-center gap-2">
        <KeyRound class="w-4 h-4" style="color: var(--sev-warning)" />
        <h2 id="pw-title" class="label-rail sev-warning">Choose your own password</h2>
      </div>

      <p class="field-help">
        The password you signed in with was generated for you, so somebody else has seen it. Choose
        one now. Every other session on this account will be signed out.
      </p>

      <form class="prompt-form" @submit.prevent="submit">
        <label class="prompt-field">
          <span class="label-micro">Current password</span>
          <input
            v-model="current"
            type="password"
            autocomplete="current-password"
            required
            :disabled="busy"
            class="input-console"
          />
        </label>

        <label class="prompt-field">
          <span class="label-micro">New password</span>
          <input
            v-model="next"
            type="password"
            autocomplete="new-password"
            required
            minlength="12"
            :disabled="busy"
            class="input-console"
          />
          <span class="field-help">At least 12 characters. Length is the rule; there are no
            character classes to satisfy.</span>
        </label>

        <label class="prompt-field">
          <span class="label-micro">Confirm new password</span>
          <input
            v-model="confirm"
            type="password"
            autocomplete="new-password"
            required
            :disabled="busy"
            class="input-console"
          />
        </label>

        <div v-if="error" role="alert" class="prompt-error">
          <AlertTriangle class="w-4 h-4 shrink-0 sev-critical" />
          <p class="state-error-detail">{{ error }}</p>
        </div>

        <button class="prompt-submit" type="submit" :disabled="busy">
          {{ busy ? 'Changing…' : 'Change password' }}
        </button>
      </form>
    </div>
  </div>
</template>

<style scoped>
.prompt-backdrop {
  position: fixed;
  inset: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  background: rgb(0 0 0 / 0.72);
}

.prompt {
  width: 100%;
  max-width: 26rem;
  background: var(--ink-panel);
  border: 1px solid var(--line-strong);
  border-top: 2px solid var(--sev-warning);
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
}

.prompt-form {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.prompt-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.prompt-error {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.5rem 0.625rem;
  border: 1px solid var(--sev-critical);
  background: var(--sev-critical-wash);
}

.prompt-submit {
  padding: 0.5rem 1rem;
  background: var(--signal);
  color: var(--ink-page);
  border: none;
  border-radius: 2px;
  font-size: var(--fs-small);
  font-weight: 600;
  cursor: pointer;
}

.prompt-submit:disabled { opacity: 0.6; cursor: default; }
</style>
