<script setup lang="ts">
import { useRoute } from 'vue-router'
import { Search, Bell, RefreshCw, ChevronDown, User } from 'lucide-vue-next'

const route = useRoute()

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/pki': 'Certificate Authorities',
  '/certificates': 'Certificate Inventory',
  '/gateways': 'Gateways',
  '/discovery': 'TLS Discovery',
  '/policies': 'Policies',
  '/settings': 'Settings',
}

function getPageTitle() {
  return pageTitles[route.path] || 'CertPilot'
}
</script>

<template>
  <div class="navbar bg-base-100 border-b border-base-300 px-6 min-h-[56px] gap-4">
    <!-- Left: Page Title -->
    <div class="flex-1">
      <h1 class="text-base font-bold tracking-tight">{{ getPageTitle() }}</h1>
    </div>

    <!-- Center: Search -->
    <div class="flex-none hidden sm:flex">
      <label class="input input-sm input-bordered flex items-center gap-2 w-64 bg-base-200/50">
        <Search class="w-3.5 h-3.5 opacity-50" />
        <input type="text" class="grow" placeholder="Search certificates, CAs…" />
        <kbd class="kbd kbd-xs">⌘K</kbd>
      </label>
    </div>

    <!-- Right: Actions -->
    <div class="flex-none flex items-center gap-1">
      <button class="btn btn-ghost btn-sm btn-circle">
        <RefreshCw class="w-4 h-4" />
      </button>
      <div class="indicator">
        <span class="indicator-item badge badge-primary badge-xs">3</span>
        <button class="btn btn-ghost btn-sm btn-circle">
          <Bell class="w-4 h-4" />
        </button>
      </div>
      <div class="dropdown dropdown-end">
        <div tabindex="0" role="button" class="btn btn-ghost btn-sm gap-1 ml-1">
          <div class="avatar placeholder">
            <div class="bg-neutral text-neutral-content w-6 rounded-full">
              <User class="w-3 h-3" />
            </div>
          </div>
          <span class="text-xs font-medium hidden md:inline">Admin</span>
          <ChevronDown class="w-3 h-3 opacity-50" />
        </div>
        <ul tabindex="0" class="dropdown-content menu bg-base-100 rounded-box z-50 w-48 p-2 shadow-lg border border-base-300">
          <li><a class="text-xs">Profile</a></li>
          <li><a class="text-xs">Preferences</a></li>
          <li class="border-t border-base-300 mt-1 pt-1"><a class="text-xs text-error">Sign Out</a></li>
        </ul>
      </div>
    </div>
  </div>
</template>
