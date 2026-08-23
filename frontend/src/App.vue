<script setup lang="ts">
import { computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import { useCasStore } from '@/stores/cas'
import { useAlertsStore } from '@/stores/alerts'
import { useEventStream } from '@/composables/useEventStream'
import CommandRail from '@/components/layout/CommandRail.vue'
import StreamStatusBanner from '@/components/common/StreamStatusBanner.vue'

const authStore = useAuthStore()
const themeStore = useThemeStore()
const casStore = useCasStore()
// Instantiated here, not lazily in a view: both stores register handlers on the
// event stream, and a store created only when its page is first opened would
// have missed everything that happened before then.
useAlertsStore()
const stream = useEventStream()

function applyDataTheme() {
  document.documentElement.setAttribute('data-theme', themeStore.currentTheme)
}

onMounted(() => {
  authStore.init()
  applyDataTheme()
  // One connection for the whole app. The snapshot it delivers on connect is
  // what populates the stores, so the initial REST fetch is a fallback for the
  // case where the stream cannot be established at all.
  stream.connect()
  void casStore.refresh()
})

onUnmounted(() => stream.disconnect())

watch(() => themeStore.currentTheme, applyDataTheme)

// When the feed is stale every figure on the page is last-known-good. Draining
// the colour out of the content says so at a glance and from a distance, which
// a small chip in the toolbar cannot do. The banner explains it; this makes it
// impossible to read the screen as normal.
const surfaceIsStale = computed(() => stream.status.value === 'stale')

// Wall mode renders bare: no sidebar, no toolbar, no banner. It supplies its own
// far louder degraded state, sized to be read from across a room — the ordinary
// chrome would only shrink the thing the screen exists to show.
const route = useRoute()
const showChrome = computed(() => route.meta.chrome !== false)
</script>

<template>
  <router-view v-if="!showChrome" />

  <div v-else class="flex flex-col h-screen">
    <CommandRail />
    <StreamStatusBanner />
    <main
      class="flex-1 min-h-0 overflow-y-auto p-3 transition-all"
      :class="{ 'surface-stale': surfaceIsStale }"
    >
      <router-view />
    </main>
  </div>
</template>
