<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { Bell, ChevronDown, RefreshCw, Search, User } from 'lucide-vue-next'
import ConnectionIndicator from '@/components/common/ConnectionIndicator.vue'
import { useAlertsStore } from '@/stores/alerts'
import { useAuthStore } from '@/stores/auth'
import { useCasStore } from '@/stores/cas'
import { describeEvent, eventSeverity } from '@/lib/events'
import { formatRelative } from '@/lib/format'
import { severityText } from '@/lib/severity'

const route = useRoute()
const alerts = useAlertsStore()
const auth = useAuthStore()
const cas = useCasStore()

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/pki': 'Certificate Authorities',
  '/certificates': 'Certificate Inventory',
  '/gateways': 'Gateways',
  '/discovery': 'TLS Discovery',
  '/policies': 'Policies',
  '/settings': 'Settings',
}

const pageTitle = computed(() => pageTitles[route.path] ?? 'CertPilot')

// The badge previously read a hardcoded 3. On a tool whose job is to tell a PKI
// team how many things need their attention, an invented number is not a
// placeholder — it is the product being wrong.
const badgeClass = computed(() =>
  alerts.peakSeverity === 'critical' ? 'badge-error' : 'badge-warning',
)

const recent = computed(() => alerts.actionable.slice(0, 8))

const roleLabel = computed(() => auth.role.charAt(0).toUpperCase() + auth.role.slice(1))
</script>

<template>
  <div class="navbar bg-base-100 border-b border-base-300 px-6 min-h-[56px] gap-4">
    <!-- Left: Page Title -->
    <div class="flex-1 min-w-0">
      <h1 class="text-base font-bold tracking-tight truncate">{{ pageTitle }}</h1>
    </div>

    <!-- Center: Search -->
    <div class="flex-none hidden lg:flex">
      <label class="input input-sm input-bordered flex items-center gap-2 w-56 bg-base-200/50">
        <Search class="w-3.5 h-3.5 opacity-50" />
        <input type="text" class="grow" placeholder="Search certificates, CAs…" />
        <kbd class="kbd kbd-xs">⌘K</kbd>
      </label>
    </div>

    <!-- Right: Actions -->
    <div class="flex-none flex items-center gap-2">
      <ConnectionIndicator />

      <button
        class="btn btn-ghost btn-sm btn-circle"
        title="Refresh now"
        :disabled="cas.loading"
        @click="cas.refresh()"
      >
        <RefreshCw class="w-4 h-4" :class="cas.loading && 'animate-spin'" />
      </button>

      <div class="dropdown dropdown-end">
        <div tabindex="0" role="button" class="indicator" @click="alerts.acknowledge()">
          <span
            v-if="alerts.unacknowledgedCount > 0"
            class="indicator-item badge badge-xs"
            :class="badgeClass"
          >
            {{ alerts.unacknowledgedCount }}
          </span>
          <span class="btn btn-ghost btn-sm btn-circle">
            <Bell class="w-4 h-4" />
          </span>
        </div>
        <div
          tabindex="0"
          class="dropdown-content bg-base-100 rounded-box z-50 w-80 p-3 shadow-lg border border-base-300"
        >
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-xs font-bold">Live alerts</h3>
            <button v-if="alerts.feed.length" class="btn btn-ghost btn-xs" @click="alerts.clear()">
              Clear
            </button>
          </div>
          <ul v-if="recent.length" class="space-y-2 max-h-80 overflow-y-auto">
            <li v-for="event in recent" :key="event.id" class="text-xs flex items-start gap-2">
              <span
                class="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0"
                :class="eventSeverity(event) === 'critical' ? 'bg-error' : 'bg-warning'"
              ></span>
              <span class="flex-1 min-w-0">
                <span class="block break-words">{{ describeEvent(event) }}</span>
                <span class="opacity-50 font-mono text-[10px]">
                  {{ formatRelative(event.timestamp) }}
                </span>
              </span>
            </li>
          </ul>
          <!-- "Nothing yet" is a claim about this session only, and says so. A
               feed that started when the tab opened must not be read as a
               statement that the estate is healthy. -->
          <p v-else class="text-xs opacity-60 py-3 text-center">
            Nothing has needed attention since this page was opened.
          </p>
        </div>
      </div>

      <div class="dropdown dropdown-end">
        <div tabindex="0" role="button" class="btn btn-ghost btn-sm gap-1">
          <div class="avatar placeholder">
            <div class="bg-neutral text-neutral-content w-6 rounded-full">
              <User class="w-3 h-3" />
            </div>
          </div>
          <span class="text-xs font-medium hidden md:inline">{{ roleLabel }}</span>
          <ChevronDown class="w-3 h-3 opacity-50" />
        </div>
        <ul
          tabindex="0"
          class="dropdown-content menu bg-base-100 rounded-box z-50 w-52 p-2 shadow-lg border border-base-300"
        >
          <li class="menu-title text-[10px]">
            {{ auth.user?.email ?? 'Anonymous (development)' }}
          </li>
          <li v-if="auth.isAuthEnabled" class="border-t border-base-300 mt-1 pt-1">
            <a class="text-xs text-error" @click="auth.signOut()">Sign out</a>
          </li>
        </ul>
      </div>
    </div>
  </div>
</template>
