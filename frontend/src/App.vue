<script setup lang="ts">
import { onMounted, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useThemeStore } from '@/stores/theme'
import Sidebar from '@/components/layout/Sidebar.vue'
import TopBar from '@/components/layout/TopBar.vue'

const authStore = useAuthStore()
const themeStore = useThemeStore()

function applyDataTheme() {
  document.documentElement.setAttribute('data-theme', themeStore.currentTheme)
}

onMounted(() => {
  authStore.init()
  applyDataTheme()
})

watch(() => themeStore.currentTheme, applyDataTheme)
</script>

<template>
  <div class="flex min-h-screen bg-base-200">
    <Sidebar />
    <div class="flex-1 flex flex-col min-w-0">
      <TopBar />
      <main class="flex-1 p-6 overflow-y-auto">
        <router-view />
      </main>
    </div>
  </div>
</template>
