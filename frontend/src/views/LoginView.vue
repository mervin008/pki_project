<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ShieldCheck, AlertTriangle, LogIn } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const route = useRoute()

const busy = ref(false)
const failure = ref<string | null>(null)

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
      <div v-if="auth.loading" class="login-wait">
        <span class="login-bar" />
        <span class="label-micro">Asking the API how to sign in</span>
      </div>

      <template v-else-if="auth.mode === 'oidc'">
        <button class="login-button" :disabled="busy" @click="signIn">
          <LogIn class="w-4 h-4" />
          {{ busy ? 'Redirecting…' : 'Sign in with single sign-on' }}
        </button>
        <p class="field-help">
          You will be sent to your organisation's identity provider and returned here.
        </p>
      </template>

      <!-- Explaining what is missing, rather than offering a button that fails
           at the provider with an error nobody here can interpret. -->
      <div v-else-if="auth.mode === 'unconfigured'" class="login-notice">
        <AlertTriangle class="w-4 h-4 shrink-0 sev-warning" />
        <div>
          <p class="label-rail sev-warning">Single sign-on is not configured</p>
          <p class="field-help">
            This instance verifies tokens but cannot start a sign-in. Set
            <code>auth.issuer</code> and <code>auth.client_id</code> in the core's configuration.
          </p>
        </div>
      </div>

      <div v-else-if="auth.mode === 'anonymous'" class="login-notice">
        <AlertTriangle class="w-4 h-4 shrink-0 sev-warning" />
        <div>
          <p class="label-rail sev-warning">Anonymous access is enabled</p>
          <p class="field-help">
            Every request is treated as admin. This is a development convenience and the core
            refuses it unless it is bound to a loopback address.
          </p>
          <RouterLink to="/" class="login-continue">Continue without signing in</RouterLink>
        </div>
      </div>

      <div v-if="failure || auth.error" role="alert" class="login-notice login-notice--error">
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
  min-height: 100vh;
  background: var(--ink-page);
  padding: 1.5rem;
}

.login-panel {
  width: 100%;
  max-width: 24rem;
  background: var(--ink-panel);
  border: 1px solid var(--line);
  padding: 1.75rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
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

.login-button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.625rem 1rem;
  background: var(--signal);
  color: var(--ink-page);
  border: none;
  border-radius: 2px;
  font-size: var(--fs-small);
  font-weight: 600;
  cursor: pointer;
}

.login-button:hover:not(:disabled) {
  filter: brightness(1.1);
}

.login-button:disabled {
  opacity: 0.6;
  cursor: default;
}

.login-notice {
  display: flex;
  gap: 0.625rem;
  padding: 0.75rem;
  border: 1px solid var(--sev-warning);
  background: var(--sev-warning-wash);
}

.login-notice--error {
  border-color: var(--sev-critical);
  background: var(--sev-critical-wash);
}

.login-continue {
  display: inline-block;
  margin-top: 0.5rem;
  font-size: var(--fs-small);
  color: var(--signal);
  text-decoration: underline;
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
