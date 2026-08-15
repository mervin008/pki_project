<script setup lang="ts">
import { onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import Sidebar from '@/components/layout/Sidebar.vue'
import TopBar from '@/components/layout/TopBar.vue'

const authStore = useAuthStore()

onMounted(() => {
  authStore.init()
})
</script>

<template>
  <div class="flex min-h-screen bg-slate-950 text-slate-100">
    <Sidebar />
    <div class="flex-1 flex flex-col min-w-0">
      <TopBar />
      <main class="flex-1 p-8 overflow-y-auto max-w-7xl w-full mx-auto">
        <router-view />
      </main>
    </div>
  </div>
</template>

<style>
/* Layout styles */
</style>
