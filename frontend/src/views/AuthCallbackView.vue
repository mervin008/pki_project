<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { AlertTriangle } from 'lucide-vue-next'
import { completeSignIn } from '@/lib/oidc'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const auth = useAuthStore()
const failure = ref<string | null>(null)

onMounted(async () => {
  try {
    const returnTo = await completeSignIn(window.location.search)

    // The role is loaded before navigating, so the first screen is drawn with
    // the permissions the API will actually enforce rather than with viewer
    // defaults that visibly change a moment later.
    await auth.init()

    // replace, not push: the callback URL carries a spent authorization code,
    // and leaving it in history means the back button lands on a page that can
    // only fail.
    await router.replace(returnTo)
  } catch (err) {
    failure.value = err instanceof Error ? err.message : String(err)
  }
})
</script>

<template>
  <div class="callback-page">
    <div v-if="!failure" class="callback-wait">
      <span class="callback-bar" />
      <span class="label-micro">Completing sign-in</span>
    </div>

    <div v-else role="alert" class="callback-error">
      <AlertTriangle class="w-4 h-4 shrink-0 sev-critical" />
      <div>
        <p class="label-rail sev-critical">Sign-in did not complete</p>
        <p class="callback-detail">{{ failure }}</p>
        <RouterLink to="/login" class="callback-retry">Back to sign in</RouterLink>
      </div>
    </div>
  </div>
</template>

<style scoped>
.callback-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--ink-page);
  padding: 1.5rem;
}

.callback-wait {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  align-items: center;
  width: 14rem;
}

.callback-bar {
  position: relative;
  width: 100%;
  height: 2px;
  background: var(--line);
  overflow: hidden;
}

.callback-bar::after {
  content: '';
  position: absolute;
  inset: 0;
  width: 40%;
  background: var(--signal);
  animation: callback-sweep 1.1s ease-in-out infinite;
}

@keyframes callback-sweep {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(250%); }
}

@media (prefers-reduced-motion: reduce) {
  .callback-bar::after { animation: none; width: 100%; opacity: 0.4; }
}

.callback-error {
  display: flex;
  gap: 0.625rem;
  max-width: 30rem;
  padding: 0.875rem;
  border: 1px solid var(--sev-critical);
  background: var(--sev-critical-wash);
}

.callback-detail {
  font-size: var(--fs-small);
  color: var(--text-secondary);
  line-height: 1.5;
}

.callback-retry {
  display: inline-block;
  margin-top: 0.5rem;
  font-size: var(--fs-small);
  color: var(--signal);
  text-decoration: underline;
}
</style>
