<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useApi } from '@/composables/useApi'
import { Settings as SettingsIcon, Database, Server, Globe, CheckCircle, XCircle } from 'lucide-vue-next'

const api = useApi()
const healthStatus = ref<any>(null)
const loading = ref(true)

async function loadHealth() {
  loading.value = true
  try {
    healthStatus.value = await api.get<any>('/api/v1/health').catch(() => null)
  } finally {
    loading.value = false
  }
}

onMounted(() => loadHealth())

const configSections = [
  {
    title: 'API Server',
    icon: Server,
    items: [
      { label: 'HTTP Endpoint', value: 'localhost:8443', status: 'connected' },
      { label: 'gRPC Gateway Port', value: ':50051', status: 'connected' },
      { label: 'TLS Mode', value: 'Enabled (mTLS)', status: 'connected' },
    ],
  },
  {
    title: 'Database',
    icon: Database,
    items: [
      { label: 'PostgreSQL', value: 'Supabase (eu-north-1)', status: healthStatus.value ? 'connected' : 'unknown' },
      { label: 'Connection Pool', value: '10 / 20', status: 'connected' },
    ],
  },
  {
    title: 'External Integrations',
    icon: Globe,
    items: [
      { label: 'ACME Provider', value: "Let's Encrypt", status: 'connected' },
      { label: 'Vault Provider', value: 'HashiCorp Vault', status: 'connected' },
      { label: 'GCP CAS Provider', value: 'Not Configured', status: 'disconnected' },
    ],
  },
]
</script>

<template>
  <div class="space-y-6">
    <p class="text-sm text-base-content/60">System configuration and infrastructure health</p>

    <div v-if="loading" class="flex justify-center py-12">
      <span class="loading loading-spinner loading-lg text-primary"></span>
    </div>

    <template v-else>
      <!-- Health Status -->
      <div class="card bg-base-100 border border-base-300">
        <div class="card-body p-5">
          <h2 class="card-title text-sm font-bold mb-3">
            <SettingsIcon class="w-4 h-4 text-primary" /> System Health
          </h2>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div class="flex items-center gap-2">
              <CheckCircle class="w-4 h-4 text-success" />
              <div>
                <div class="font-medium">API Server</div>
                <div class="text-base-content/60">Running</div>
              </div>
            </div>
            <div class="flex items-center gap-2">
              <CheckCircle class="w-4 h-4 text-success" />
              <div>
                <div class="font-medium">Database</div>
                <div class="text-base-content/60">{{ healthStatus ? 'Connected' : 'Checking…' }}</div>
              </div>
            </div>
            <div class="flex items-center gap-2">
              <CheckCircle class="w-4 h-4 text-success" />
              <div>
                <div class="font-medium">gRPC Gateway</div>
                <div class="text-base-content/60">Listening</div>
              </div>
            </div>
            <div class="flex items-center gap-2">
              <XCircle class="w-4 h-4 text-base-content/30" />
              <div>
                <div class="font-medium">Background Jobs</div>
                <div class="text-base-content/60">Idle</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Configuration Cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div v-for="section in configSections" :key="section.title" class="card bg-base-100 border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-2 mb-3">
              <component :is="section.icon" class="w-4 h-4 text-primary" />
              <h3 class="font-bold text-sm">{{ section.title }}</h3>
            </div>
            <div class="space-y-2.5">
              <div v-for="item in section.items" :key="item.label" class="flex items-center justify-between text-xs">
                <span class="text-base-content/70">{{ item.label }}</span>
                <div class="flex items-center gap-1.5">
                  <span class="font-mono text-[11px]">{{ item.value }}</span>
                  <span class="w-2 h-2 rounded-full" :class="item.status === 'connected' ? 'bg-success' : item.status === 'disconnected' ? 'bg-error' : 'bg-base-content/30'"></span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
