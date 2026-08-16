<script setup lang="ts">
import { useRoute } from 'vue-router'
import { useThemeStore } from '@/stores/theme'
import { 
  LayoutDashboard, ShieldCheck, KeyRound, Cpu, 
  Radar, Sliders, Settings, Sun, Moon
} from 'lucide-vue-next'

const route = useRoute()
const themeStore = useThemeStore()

const navItems = [
  { name: 'Dashboard', path: '/', icon: LayoutDashboard },
  { name: 'Certificate Authorities', path: '/pki', icon: ShieldCheck },
  { name: 'Certificates', path: '/certificates', icon: KeyRound },
  { name: 'Gateways', path: '/gateways', icon: Cpu },
  { name: 'TLS Discovery', path: '/discovery', icon: Radar },
  { name: 'Policies', path: '/policies', icon: Sliders },
  { name: 'Settings', path: '/settings', icon: Settings },
]

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}
</script>

<template>
  <aside class="w-60 bg-base-100 border-r border-base-300 flex flex-col justify-between min-h-screen select-none">
    <!-- Brand -->
    <div>
      <div class="px-5 py-4 flex items-center gap-3 border-b border-base-300">
        <div class="w-8 h-8 rounded-lg bg-primary flex items-center justify-center text-primary-content text-xs font-bold font-mono">
          CP
        </div>
        <div>
          <div class="text-sm font-bold tracking-tight">CertPilot</div>
          <div class="text-[10px] text-base-content/60 font-mono">PKI Command Center</div>
        </div>
      </div>

      <!-- Navigation -->
      <ul class="menu menu-sm px-2 py-3 gap-0.5">
        <li v-for="item in navItems" :key="item.path">
          <router-link
            :to="item.path"
            class="flex items-center gap-2.5 rounded-lg text-xs font-semibold"
            :class="isActive(item.path) ? 'active' : ''"
          >
            <component :is="item.icon" class="w-4 h-4" />
            {{ item.name }}
          </router-link>
        </li>
      </ul>
    </div>

    <!-- Footer -->
    <div class="p-3 border-t border-base-300 space-y-2">
      <!-- Theme Toggle -->
      <button 
        @click="themeStore.toggleTheme"
        class="btn btn-ghost btn-sm btn-block justify-start gap-2 font-normal text-xs"
      >
        <Sun v-if="themeStore.currentTheme === 'dark'" class="w-4 h-4 text-warning" />
        <Moon v-else class="w-4 h-4 text-primary" />
        {{ themeStore.currentTheme === 'dark' ? 'Light Mode' : 'Dark Mode' }}
      </button>

      <!-- Status -->
      <div class="px-3 py-1.5 text-[11px] font-mono flex items-center justify-between text-base-content/60">
        <span>Engine</span>
        <span class="badge badge-success badge-xs gap-1">
          <span class="w-1.5 h-1.5 rounded-full bg-success animate-pulse"></span>
          Online
        </span>
      </div>
    </div>
  </aside>
</template>
