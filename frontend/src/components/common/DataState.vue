<script setup lang="ts">
import { AlertTriangle, RotateCw } from 'lucide-vue-next'

/**
 * Wraps a panel's loading, error, and first-load states.
 *
 * Views previously appended `.catch(() => ({ data: [] }))` to every request, so
 * a backend outage rendered as an empty list — indistinguishable from a healthy
 * system with nothing in it. On a monitoring dashboard that is the worst
 * possible failure, because it reports "no problems" precisely when the tool
 * has stopped being able to see problems.
 *
 * An error is shown even when stale data is still on screen, so the reader can
 * tell the difference between current and last-known-good.
 */
const props = withDefaults(
  defineProps<{
    loading: boolean
    error: string | null
    /** True once at least one load has succeeded. */
    loaded?: boolean
    /** Label for the retry button. */
    retryLabel?: string
  }>(),
  { loaded: false, retryLabel: 'Retry' },
)

defineEmits<{ retry: [] }>()

/** Only blank the screen before the first successful load. */
const showSpinner = () => props.loading && !props.loaded
</script>

<template>
  <div class="space-y-4">
    <!-- A failure is reported whether or not stale data remains visible below. -->
    <div v-if="error" role="alert" class="alert alert-error">
      <AlertTriangle class="w-5 h-5 shrink-0" />
      <div class="flex-1 min-w-0">
        <h3 class="font-bold text-sm">Could not load the latest data</h3>
        <p class="text-xs opacity-90 break-words">{{ error }}</p>
        <p v-if="loaded" class="text-xs opacity-75 mt-0.5">
          Showing the last values received — they may be out of date.
        </p>
      </div>
      <button class="btn btn-sm" @click="$emit('retry')">
        <RotateCw class="w-3.5 h-3.5" />
        {{ retryLabel }}
      </button>
    </div>

    <div v-if="showSpinner()" class="flex items-center justify-center h-64">
      <span class="loading loading-spinner loading-lg text-primary"></span>
    </div>

    <!-- Content stays mounted through a refresh so the view does not flash. -->
    <div v-else-if="loaded || !error" class="space-y-6">
      <slot />
    </div>
  </div>
</template>
