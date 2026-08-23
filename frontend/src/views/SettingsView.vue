<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useApi } from '@/composables/useApi'
import { useAsyncData } from '@/composables/useAsyncData'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import DataState from '@/components/common/DataState.vue'
import NotificationChannels from '@/components/settings/NotificationChannels.vue'
import {
  Server, Cpu, ShieldCheck, CircleCheck, CircleX, RotateCw, Palette, UserCog,
} from 'lucide-vue-next'
import { formatDateTime } from '@/lib/format'
import type { GatewaySummary, ListResponse } from '@/lib/types'

/**
 * This page reports live state only.
 *
 * It previously rendered a hardcoded table — "localhost:8443", ":50051",
 * "Supabase (eu-north-1)", "Connection Pool 10 / 20", and a connected
 * "Vault Provider" for a gateway that does not exist in this repository — built
 * from a non-reactive array that read a ref before it was ever populated. On a
 * settings page that is worse than showing nothing, because it invites someone
 * to trust a port number that was never real.
 */

const api = useApi()
const auth = useAuthStore()
const theme = useThemeStore()
const { role, user, isAuthEnabled } = storeToRefs(auth)
const { currentTheme } = storeToRefs(theme)

// The health endpoint is /healthz and is unversioned; this page used to call
// /api/v1/health, which has never existed.
const health = useAsyncData<{ status: string; service: string }>((s) =>
  api.get<{ status: string; service: string }>('/healthz', s),
)

const gateways = useAsyncData<ListResponse<GatewaySummary>>((s) =>
  api.get<ListResponse<GatewaySummary>>('/api/v1/gateways', s),
)

const gatewayList = computed(() => gateways.data.value?.data ?? [])
const loading = computed(() => health.loading.value || gateways.loading.value)
const loaded = computed(() => health.loaded.value && gateways.loaded.value)
const error = computed(() => health.error.value ?? gateways.error.value)

const apiReachable = computed(() => health.data.value?.status === 'ok')

function refreshAll() {
  void health.refresh()
  void gateways.refresh()
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between gap-4 flex-wrap">
      <p class="text-sm text-base-content/60">Live system state and local preferences</p>
      <button class="btn btn-ghost btn-sm gap-1.5" :disabled="loading" @click="refreshAll">
        <RotateCw class="w-3.5 h-3.5" :class="loading && 'animate-spin'" />
        Refresh
      </button>
    </div>

    <DataState :loading="loading" :error="error" :loaded="loaded" @retry="refreshAll">
      <!-- Control plane -->
      <section class="card bg-base-100 border border-base-300">
        <div class="card-body p-5 gap-3">
          <h2 class="card-title text-sm font-bold flex items-center gap-2">
            <Server class="w-4 h-4" /> Control plane
          </h2>
          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div class="flex items-center justify-between gap-3">
              <dt class="opacity-60">Core API</dt>
              <dd class="flex items-center gap-1.5">
                <CircleCheck v-if="apiReachable" class="w-3.5 h-3.5 text-success" />
                <CircleX v-else class="w-3.5 h-3.5 text-error" />
                {{ apiReachable ? 'Reachable' : 'Unreachable' }}
              </dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="opacity-60">Service</dt>
              <dd class="font-mono">{{ health.data.value?.service ?? '—' }}</dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="opacity-60">Last checked</dt>
              <dd class="font-mono">{{ formatDateTime(health.lastLoadedAt.value?.toISOString()) }}</dd>
            </div>
          </dl>
          <p class="text-[11px] opacity-50">
            Database and encryption-key state are not exposed by the API. They are reported in the
            core's startup logs.
          </p>
        </div>
      </section>

      <!-- Gateways -->
      <section class="card bg-base-100 border border-base-300">
        <div class="card-body p-5 gap-3">
          <h2 class="card-title text-sm font-bold flex items-center gap-2">
            <Cpu class="w-4 h-4" /> Gateway plugins
          </h2>
          <ul v-if="gatewayList.length" class="divide-y divide-base-300 text-xs">
            <li
              v-for="gw in gatewayList" :key="gw.name"
              class="flex items-center justify-between gap-3 py-2 first:pt-0 last:pb-0"
            >
              <div class="min-w-0">
                <div class="font-medium truncate">{{ gw.name }}</div>
                <div class="font-mono opacity-60 truncate">{{ gw.addr }} · {{ gw.type }}</div>
              </div>
              <span
                class="badge badge-sm shrink-0"
                :class="gw.is_connected ? 'badge-success' : 'badge-error'"
              >{{ gw.is_connected ? 'Connected' : 'Disconnected' }}</span>
            </li>
          </ul>
          <p v-else class="text-xs opacity-60">
            No gateways connected. Configure them under
            <span class="font-mono">plugins.gateways</span> and start the processes.
          </p>
        </div>
      </section>

      <!-- Access -->
      <section class="card bg-base-100 border border-base-300">
        <div class="card-body p-5 gap-3">
          <h2 class="card-title text-sm font-bold flex items-center gap-2">
            <UserCog class="w-4 h-4" /> Access
          </h2>
          <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div class="flex items-center justify-between gap-3">
              <dt class="opacity-60">Authentication</dt>
              <dd>{{ isAuthEnabled ? 'Identity provider' : 'Anonymous (development)' }}</dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="opacity-60">Signed in as</dt>
              <dd class="font-mono truncate">{{ user?.email ?? '—' }}</dd>
            </div>
            <div class="flex items-center justify-between gap-3">
              <dt class="opacity-60">Role</dt>
              <dd><span class="badge badge-sm badge-ghost">{{ role }}</span></dd>
            </div>
          </dl>
          <div
            v-if="!isAuthEnabled" role="alert"
            class="alert alert-warning py-2"
          >
            <ShieldCheck class="w-4 h-4 shrink-0" />
            <span class="text-xs">
              Anonymous access treats every request as admin. The core refuses this outside
              development mode on a loopback address.
            </span>
          </div>
        </div>
      </section>

      <!-- Alert delivery -->
      <NotificationChannels />

      <!-- Preferences -->
      <section class="card bg-base-100 border border-base-300">
        <div class="card-body p-5 gap-3">
          <h2 class="card-title text-sm font-bold flex items-center gap-2">
            <Palette class="w-4 h-4" /> Appearance
          </h2>
          <div class="flex items-center justify-between gap-3">
            <span class="text-xs opacity-60">Theme</span>
            <div class="join">
              <button
                class="btn btn-xs join-item"
                :class="currentTheme === 'light' ? 'btn-active' : ''"
                @click="theme.setTheme('light')"
              >Light</button>
              <button
                class="btn btn-xs join-item"
                :class="currentTheme === 'dark' ? 'btn-active' : ''"
                @click="theme.setTheme('dark')"
              >Dark</button>
            </div>
          </div>
          <p class="text-[11px] opacity-50">Stored in this browser only.</p>
        </div>
      </section>
    </DataState>
  </div>
</template>
