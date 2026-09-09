<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ShieldCheck, AlertTriangle, LogIn } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()

const busy = ref(false)
const failure = ref<string | null>(null)

const email = ref('')
const password = ref('')
const router = useRouter()

/** Where the guard wanted the user to go before it sent them here. */
const returnTo = computed(() => (route.query.next as string) || '/')

// A rejected session says so. Landing on a bare login screen after being
// silently signed out reads as the application having lost the page, rather
// than as a session that ended.
const reason = computed(() => {
  switch (route.query.reason) {
    case 'expired':
      return 'Your session ended. Sign in again to continue.'
    case 'signed-out':
      return 'You have been signed out.'
    default:
      return null
  }
})

onMounted(async () => {
  if (!auth.config) await auth.init()
})

async function signInWithPassword() {
  busy.value = true
  failure.value = null
  try {
    const problem = await auth.signInWithPassword(email.value, password.value)
    if (problem) {
      failure.value = problem
      // Cleared on failure so a wrong value is not silently re-submitted, and
      // so a shared screen does not keep it.
      password.value = ''
      return
    }
    await router.replace(returnTo.value)
  } catch (err) {
    failure.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = false
  }
}

async function signIn() {
  busy.value = true
  failure.value = null
  try {
    await auth.signIn(returnTo.value)
  } catch (err) {
    failure.value = err instanceof Error ? err.message : String(err)
    busy.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <div class="login-panel">
      <div class="login-mark">
        <ShieldCheck class="w-5 h-5" style="color: var(--signal)" />
        <span class="login-wordmark">CertPilot</span>
      </div>

      <p class="login-strap">Certificate lifecycle and CA health, for the team that gets paged.</p>

      <p v-if="reason" class="login-reason">{{ reason }}</p>

      <!-- Nothing is offered before the core has said how it authenticates. A
           button that cannot work is worse than a moment's wait. -->
      <div v-if="auth.loading" class="login-wait" role="status">
        <span class="login-bar" />
        <span class="label-micro">Asking the API how to sign in</span>
      </div>

      <template v-else>
        <form class="login-form" @submit.prevent="signInWithPassword">
          <label class="login-field">
            <span class="label-micro">Email</span>
            <input
              v-model="email"
              type="email"
              autocomplete="username"
              required
              :disabled="busy"
              class="login-input"
            />
          </label>

          <label class="login-field">
            <span class="label-micro">Password</span>
            <input
              v-model="password"
              type="password"
              autocomplete="current-password"
              required
              :disabled="busy"
              class="login-input"
            />
          </label>

          <button class="login-button" type="submit" :disabled="busy">
            <LogIn class="w-4 h-4" />
            {{ busy ? 'Signing in…' : 'Sign in' }}
          </button>
        </form>

        <!-- Offered alongside a password, never instead of it: an identity
             provider outage must not lock a team out of its own CA hierarchy. -->
        <template v-if="auth.mode === 'oidc'">
          <div class="login-divider"><span>or</span></div>
          <button class="login-button login-button--alt" :disabled="busy" @click="signIn">
            Single sign-on
          </button>
          <p class="field-help">
            You will be sent to your organisation's identity provider and returned here.
          </p>
        </template>
      </template>

      <div
        v-if="failure || auth.error"
        role="alert"
        aria-live="assertive"
        class="login-notice login-notice--error"
      >
        <AlertTriangle class="w-4 h-4 shrink-0 sev-critical" />
        <div>
          <p class="label-rail sev-critical">Sign-in could not start</p>
          <p class="field-help">{{ failure || auth.error }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100dvh;
  background: var(--ink-page);
  padding: var(--sp-loose);
}

.login-panel {
  width: 100%;
  max-width: 24rem;
  background: var(--ink-panel);
  border: 1px solid var(--line);
  padding: 1.75rem;
  display: flex;
  flex-direction: column;
  gap: var(--sp-base);
}

.login-mark {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.login-wordmark {
  font-size: var(--fs-body);
  font-weight: 600;
  letter-spacing: 0.02em;
  color: var(--text-primary);
}

.login-strap {
  font-size: var(--fs-small);
  color: var(--text-secondary);
  line-height: 1.5;
}

.login-reason {
  font-size: var(--fs-small);
  color: var(--text-primary);
  border-left: 2px solid var(--signal);
  padding-left: 0.625rem;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: var(--sp-snug);
}

.login-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.login-input {
  width: 100%;
  padding: 0.5rem 0.625rem;
  background: var(--ink-raised);
  border: 1px solid var(--line-strong);
  border-radius: 2px;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--fs-small);
}

.login-input:focus {
  outline: none;
  border-color: var(--signal);
}

.login-divider {
  display: flex;
  align-items: center;
  gap: 0.625rem;
  color: var(--text-muted);
  font-size: var(--fs-micro);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.login-divider::before,
.login-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--line);
}

.login-button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.625rem 1rem;
  background: var(--signal);
  color: var(--ink-page);
  border: 1px solid var(--signal);
  border-radius: 2px;
  font-size: var(--fs-small);
  font-weight: 600;
  cursor: pointer;
  transition: filter var(--dur-fast) var(--ease-out),
    transform var(--dur-fast) var(--ease-out),
    background var(--dur-fast) var(--ease-out);
}

.login-button:hover:not(:disabled) {
  filter: brightness(1.1);
}

/* Acknowledges the press. Without it the only feedback that a click landed is
   the label changing, which arrives a network round trip later — long enough
   that people submit twice. */
.login-button:active:not(:disabled) {
  transform: translateY(1px);
}

/*
 * The secondary action, and it must not look like the primary one.
 *
 * This modifier used to be declared *above* `.login-button`. Both selectors are
 * one class, so source order decided it and the base rule won: single sign-on
 * rendered as a second filled blue button identical to the password submit,
 * with no visual hierarchy between the two at all.
 */
.login-button--alt {
  background: transparent;
  color: var(--text-primary);
  border: 1px solid var(--line-strong);
}

.login-button--alt:hover:not(:disabled) {
  background: var(--ink-hover);
  filter: none;
}

@media (prefers-reduced-motion: reduce) {
  .login-button { transition: none; }
  .login-button:active:not(:disabled) { transform: none; }
}

.login-button:disabled {
  opacity: 0.6;
  cursor: default;
}

.login-notice {
  display: flex;
  gap: var(--sp-snug);
  padding: 0.75rem;
  border: 1px solid var(--line);
  border-left-width: 3px;
  background: var(--ink-raised);
}

.login-notice--error {
  border-left-color: var(--sev-critical);
  background: var(--sev-critical-wash);
}

.login-wait {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  align-items: center;
  padding: 1rem 0;
}

.login-bar {
  position: relative;
  width: 100%;
  height: 2px;
  background: var(--line);
  overflow: hidden;
}

.login-bar::after {
  content: '';
  position: absolute;
  inset: 0;
  width: 40%;
  background: var(--signal);
  animation: login-sweep 1.1s ease-in-out infinite;
}

@keyframes login-sweep {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(250%); }
}

@media (prefers-reduced-motion: reduce) {
  .login-bar::after { animation: none; width: 100%; opacity: 0.4; }
}
</style>
