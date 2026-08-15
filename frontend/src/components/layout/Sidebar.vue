<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { 
  LayoutDashboard, 
  ShieldCheck, 
  KeyRound, 
  Cpu, 
  Radar, 
  Sliders, 
  Settings,
  Shield
} from 'lucide-vue-next'

const route = useRoute()
const router = useRouter()

const navItems = [
  { name: 'Dashboard', path: '/', icon: LayoutDashboard },
  { name: 'PKI & CAs', path: '/pki', icon: ShieldCheck },
  { name: 'Certificates', path: '/certificates', icon: KeyRound },
  { name: 'Gateways', path: '/gateways', icon: Cpu },
  { name: 'Discovery', path: '/discovery', icon: Radar },
  { name: 'Policies', path: '/policies', icon: Sliders },
  { name: 'Settings', path: '/settings', icon: Settings },
]

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}
</script>

<template>
  <aside class="w-64 bg-slate-900/90 border-r border-slate-800/80 flex flex-col justify-between p-4 min-h-screen">
    <div>
      <!-- Brand -->
      <div class="flex items-center gap-3 px-3 py-4 mb-6">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-500 via-purple-500 to-pink-500 flex items-center justify-center shadow-lg shadow-indigo-500/25">
          <Shield class="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
            CertPilot
            <span class="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">OSS</span>
          </h1>
          <p class="text-xs text-slate-400">PKI & Cert Control Plane</p>
        </div>
      </div>

      <!-- Navigation Links -->
      <nav class="space-y-1">
        <router-link
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all duration-150"
          :class="isActive(item.path) 
            ? 'bg-indigo-600/15 text-indigo-300 border border-indigo-500/30 shadow-sm shadow-indigo-500/10' 
            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'"
        >
          <component :is="item.icon" class="w-4 h-4" :class="isActive(item.path) ? 'text-indigo-400' : 'text-slate-400'" />
          <span>{{ item.name }}</span>
        </router-link>
      </nav>
    </div>

    <!-- Footer System Status -->
    <div class="p-3 rounded-xl bg-slate-950/60 border border-slate-800/60">
      <div class="flex items-center justify-between text-xs mb-1.5">
        <span class="text-slate-400">Core Service</span>
        <span class="flex items-center gap-1 text-emerald-400 font-medium">
          <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          Active
        </span>
      </div>
      <div class="text-[11px] text-slate-400 font-mono">PostgreSQL 17 (Supabase)</div>
    </div>
  </aside>
</template>
