<script setup lang="ts">
import { ref } from 'vue'
import { Settings, Database, Bell, Shield, Key } from 'lucide-vue-next'

const supabaseProject = 'wlhrdxswnzwpiffvbkez'
const supabaseRegion = 'eu-north-1'
const supabaseStatus = 'Connected (Healthy)'
</script>

<template>
  <div class="space-y-8">
    <!-- Header -->
    <div>
      <h2 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
        <Settings class="w-7 h-7 text-indigo-400" />
        System Settings & Integrations
      </h2>
      <p class="text-sm text-slate-400 mt-1">
        Configure database persistence, Supabase Auth OIDC/SSO, and alert notification destinations.
      </p>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <!-- Database & Auth Settings -->
      <div class="glass-panel p-6 space-y-4">
        <div class="flex items-center gap-3 border-b border-slate-800 pb-3">
          <Database class="w-5 h-5 text-emerald-400" />
          <h3 class="font-semibold text-white">Database & Auth Provider</h3>
        </div>

        <div class="space-y-3 text-xs">
          <div class="flex justify-between py-1.5 border-b border-slate-800/60">
            <span class="text-slate-400">Database Engine</span>
            <span class="font-mono text-slate-200">PostgreSQL 17</span>
          </div>
          <div class="flex justify-between py-1.5 border-b border-slate-800/60">
            <span class="text-slate-400">Supabase Project Ref</span>
            <span class="font-mono text-slate-200">{{ supabaseProject }}</span>
          </div>
          <div class="flex justify-between py-1.5 border-b border-slate-800/60">
            <span class="text-slate-400">Region</span>
            <span class="font-mono text-slate-200">{{ supabaseRegion }}</span>
          </div>
          <div class="flex justify-between py-1.5 border-b border-slate-800/60">
            <span class="text-slate-400">Row-Level Security</span>
            <span class="text-emerald-400 font-semibold">Enabled (9 tables)</span>
          </div>
          <div class="flex justify-between py-1.5">
            <span class="text-slate-400">Realtime WebSocket</span>
            <span class="text-emerald-400 font-semibold">Active</span>
          </div>
        </div>
      </div>

      <!-- Notification Channels -->
      <div class="glass-panel p-6 space-y-4">
        <div class="flex items-center gap-3 border-b border-slate-800 pb-3">
          <Bell class="w-5 h-5 text-indigo-400" />
          <h3 class="font-semibold text-white">Alert Dispatch Destinations</h3>
        </div>

        <div class="space-y-3 text-xs text-slate-300">
          <p>
            CertPilot automatically routes CA expiry threshold warnings and renewal failure alerts to your designated channels.
          </p>
          <div class="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-medium text-slate-200">Slack Webhook</span>
              <span class="badge badge-healthy text-[10px]">Ready</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="font-medium text-slate-200">Microsoft Teams</span>
              <span class="badge badge-healthy text-[10px]">Ready</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="font-medium text-slate-200">Generic Webhook</span>
              <span class="badge badge-healthy text-[10px]">Ready</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
