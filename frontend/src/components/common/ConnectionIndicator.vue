<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import { useEventStream } from '@/composables/useEventStream'
import { formatTime } from '@/lib/format'

/**
 * Live-connection state, always on screen.
 *
 * This is the smallest piece of the dashboard and one of the most important:
 * every other panel is only as trustworthy as this indicator says it is. It
 * never shows a neutral or reassuring state while the feed is down.
 */

const stream = useEventStream()

// A ticking clock so "no updates for 2m" keeps counting up rather than freezing
// at whatever it said when the connection dropped — a stale staleness display
// would be its own small lie.
const now = ref(Date.now())
const ticker = window.setInterval(() => {
  now.value = Date.now()
}, 1000)
onUnmounted(() => window.clearInterval(ticker))

const silenceFor = computed(() => {
  const last = stream.lastContactAt.value
  if (!last) return null
  return Math.max(0, Math.round((now.value - last.getTime()) / 1000))
})

const label = computed(() => {
  switch (stream.status.value) {
    case 'live':
      return 'Live'
    case 'connecting':
      return 'Connecting…'
    case 'reconnecting':
      return stream.attempt.value > 1
        ? `Reconnecting · attempt ${stream.attempt.value}`
        : 'Reconnecting…'
    case 'stale':
      return silenceFor.value !== null ? `No updates ${humanAge(silenceFor.value)}` : 'No updates'
  }
})

const tone = computed(() => {
  switch (stream.status.value) {
    case 'live':
      return { dot: 'bg-success', text: 'text-base-content/70', ring: 'border-base-300' }
    case 'connecting':
      return { dot: 'bg-base-content/40', text: 'text-base-content/60', ring: 'border-base-300' }
    case 'reconnecting':
      return { dot: 'bg-warning', text: 'text-warning', ring: 'border-warning/40' }
    case 'stale':
      return { dot: 'bg-error', text: 'text-error', ring: 'border-error/60' }
  }
})

const detail = computed(() => {
  const parts: string[] = []
  if (stream.lastEventAt.value) parts.push(`Last update ${formatTime(stream.lastEventAt.value)}`)
  if (stream.lastError.value) parts.push(stream.lastError.value)
  return parts.join(' — ') || 'Waiting for the first update'
})

function humanAge(seconds: number): string {
  if (seconds < 90) return `for ${seconds}s`
  const minutes = Math.round(seconds / 60)
  if (minutes < 90) return `for ${minutes}m`
  return `for ${Math.round(minutes / 60)}h`
}
</script>

<template>
  <button
    type="button"
    class="flex items-center gap-2 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors hover:bg-base-200"
    :class="[tone.ring, tone.text]"
    :title="detail"
    :aria-label="`Live connection: ${label}. ${detail}`"
    @click="stream.reconnectNow()"
  >
    <span class="relative flex h-2 w-2 shrink-0">
      <!-- Only a healthy stream animates. A frozen dot on a frozen dashboard is
           precisely the impression to avoid. -->
      <span
        v-if="stream.status.value === 'live'"
        class="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60"
        :class="tone.dot"
      ></span>
      <span class="relative inline-flex h-2 w-2 rounded-full" :class="tone.dot"></span>
    </span>
    <span class="whitespace-nowrap">{{ label }}</span>
  </button>
</template>
