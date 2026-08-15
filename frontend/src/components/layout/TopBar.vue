<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { Bell, User, LogOut } from 'lucide-vue-next'

const authStore = useAuthStore()
</script>

<template>
  <header class="h-16 border-b border-slate-800/80 bg-slate-900/40 backdrop-blur-md px-8 flex items-center justify-between sticky top-0 z-30">
    <div class="flex items-center gap-4">
      <div class="text-xs text-slate-400 font-mono flex items-center gap-2">
        <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
        <span>Environment:</span>
        <span class="text-slate-200 uppercase font-semibold">Development / Cloud DB</span>
      </div>
    </div>

    <div class="flex items-center gap-4">
      <!-- Quick Notification Icon -->
      <button class="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors relative">
        <Bell class="w-4 h-4" />
        <span class="absolute top-1.5 right-1.5 w-2 h-2 bg-indigo-500 rounded-full"></span>
      </button>

      <div class="h-4 w-px bg-slate-800"></div>

      <!-- User Role Info -->
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-300 font-semibold text-xs">
          <User class="w-4 h-4" />
        </div>
        <div class="text-left">
          <div class="text-xs font-semibold text-slate-200">{{ authStore.user?.email || 'admin@certpilot.local' }}</div>
          <div class="text-[10px] uppercase font-mono text-indigo-400">{{ authStore.role }}</div>
        </div>
      </div>
    </div>
  </header>
</template>
