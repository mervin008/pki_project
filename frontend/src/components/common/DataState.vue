<script setup lang="ts">
import { AlertTriangle, RotateCw } from 'lucide-vue-next'

/**
 * Wraps a panel's loading, error, and first-load states.
 *
 * Views once appended `.catch(() => ({ data: [] }))` to every request, so a
 * backend outage rendered as an empty list — indistinguishable from a healthy
 * system with nothing in it. On a monitoring dashboard that is the worst
 * possible failure, because it reports "no problems" precisely when the tool
 * has stopped being able to see problems.
 *
 * An error is shown even when stale data is still on screen, so the reader can
 * tell current from last-known-good.
 */
const props = withDefaults(
  defineProps<{
    loading: boolean
    error: string | null
    /** True once at least one load has succeeded. */
    loaded?: boolean
    retryLabel?: string
  }>(),
  { loaded: false, retryLabel: 'Retry' },
)

defineEmits<{ retry: [] }>()

/** Only blank the screen before the first successful load. */
const showSpinner = () => props.loading && !props.loaded
</script>

<template>
  <div class="flex flex-col gap-3 min-w-0">
    <!-- A failure is reported whether or not stale data remains visible below. -->
    <div v-if="error" role="alert" class="state-error">
      <AlertTriangle class="w-4 h-4 shrink-0 sev-critical" />
      <div class="flex-1 min-w-0">
        <p class="label-rail sev-critical">Could not load the latest data</p>
        <p class="state-error-detail">{{ error }}</p>
        <p v-if="loaded" class="label-micro mt-1">
          Showing the last values received — they may be out of date
        </p>
      </div>
      <button class="btn-console" @click="$emit('retry')">
        <RotateCw class="w-3 h-3" />
        {{ retryLabel }}
      </button>
    </div>

    <!-- A bar sweeping the width, not a centred spinner: it reads as an
         instrument acquiring a signal rather than as a page loading. -->
    <div v-if="showSpinner()" class="state-loading">
      <span class="state-loading-bar" />
      <span class="label-micro">Acquiring</span>
    </div>

    <!-- Content stays mounted through a refresh so the view does not flash. -->
    <div v-else-if="loaded || !error" class="flex flex-col gap-3 min-w-0">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.state-error {
  display: flex;
  align-items: flex-start;
  gap: 0.625rem;
  padding: 0.625rem 0.75rem;
  background: var(--sev-critical-wash);
  border: 1px solid var(--sev-critical);
  border-left-width: 3px;
}

.state-error-detail {
  font-size: var(--fs-small);
  color: var(--text-secondary);
  word-break: break-word;
}

.state-loading {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 2.5rem 0;
  align-items: center;
}

.state-loading-bar {
  position: relative;
  width: 12rem;
  height: 2px;
  background: var(--line);
  overflow: hidden;
}

.state-loading-bar::after {
  content: '';
  position: absolute;
  inset: 0;
  width: 40%;
  background: var(--signal);
  animation: sweep 1.1s ease-in-out infinite;
}

@keyframes sweep {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(250%); }
}

@media (prefers-reduced-motion: reduce) {
  .state-loading-bar::after {
    animation: none;
    width: 100%;
    opacity: 0.4;
  }
}
</style>
