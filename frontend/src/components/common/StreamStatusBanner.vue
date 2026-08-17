<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import { AlertTriangle, RotateCw } from 'lucide-vue-next'
import { useEventStream } from '@/composables/useEventStream'
import { useAlertsStore } from '@/stores/alerts'
import { formatTime } from '@/lib/format'

/**
 * The degraded-state band, across the top of every page.
 *
 * The chip in the toolbar is enough for someone sitting at the machine. This is
 * for the screen on the wall that nobody is standing in front of: when the feed
 * stops, the page must announce it in a way that cannot be mistaken for normal
 * operation from across a room.
 *
 * It appears only when something is wrong, so it costs nothing when the system
 * is healthy — which is also why it must be impossible to miss when it does
 * appear.
 */

const stream = useEventStream()
const alerts = useAlertsStore()

const now = ref(Date.now())
const ticker = window.setInterval(() => {
  now.value = Date.now()
}, 1000)
onUnmounted(() => window.clearInterval(ticker))

const stale = computed(() => stream.status.value === 'stale')
const reconnecting = computed(() => stream.status.value === 'reconnecting')
const visible = computed(() => stale.value || reconnecting.value || alerts.incomplete)

const staleAge = computed(() => {
  const last = stream.lastEventAt.value ?? stream.lastContactAt.value
  if (!last) return null
  const seconds = Math.max(0, Math.round((now.value - last.getTime()) / 1000))
  if (seconds < 90) return `${seconds} seconds ago`
  const minutes = Math.round(seconds / 60)
  if (minutes < 90) return `${minutes} minutes ago`
  return `${Math.round(minutes / 60)} hours ago`
})
</script>

<template>
  <div v-if="visible" class="space-y-2">
    <!-- Stale: the numbers below are last-known-good and may be wrong. -->
    <div v-if="stale" role="alert" class="alert alert-error rounded-none border-x-0 border-t-0">
      <AlertTriangle class="w-5 h-5 shrink-0" />
      <div class="flex-1 min-w-0">
        <h2 class="font-bold text-sm">This dashboard is not receiving updates</h2>
        <p class="text-xs opacity-90">
          <template v-if="stream.lastEventAt.value">
            The figures below were last confirmed at
            {{ formatTime(stream.lastEventAt.value) }}<template v-if="staleAge">
              — {{ staleAge }}</template
            >. Treat them as out of date.
          </template>
          <template v-else> No data has been received since this page was opened. </template>
          <template v-if="stream.lastError.value"> ({{ stream.lastError.value }})</template>
        </p>
      </div>
      <button class="btn btn-sm" @click="stream.reconnectNow()">
        <RotateCw class="w-3.5 h-3.5" />
        Reconnect
      </button>
    </div>

    <!-- Reconnecting: degraded, but not yet proven stale. -->
    <div
      v-else-if="reconnecting"
      role="status"
      class="alert alert-warning rounded-none border-x-0 border-t-0 py-2"
    >
      <RotateCw class="w-4 h-4 shrink-0 animate-spin" />
      <span class="text-xs">
        Reconnecting to the live feed<template v-if="stream.attempt.value > 1">
          (attempt {{ stream.attempt.value }})</template
        >.
        <template v-if="stream.lastEventAt.value">
          Last update {{ formatTime(stream.lastEventAt.value) }}.
        </template>
      </span>
    </div>

    <!-- We were told, by the server, that we missed events. -->
    <div
      v-if="alerts.incomplete"
      role="status"
      class="alert alert-warning rounded-none border-x-0 border-t-0 py-2"
    >
      <AlertTriangle class="w-4 h-4 shrink-0" />
      <span class="text-xs">
        This browser fell behind and
        {{ alerts.droppedCount > 0 ? `${alerts.droppedCount} events were` : 'some events were' }}
        dropped. The alert list is incomplete; the figures have been resynchronised.
      </span>
      <button class="btn btn-ghost btn-xs" @click="alerts.clear()">Dismiss</button>
    </div>
  </div>
</template>
