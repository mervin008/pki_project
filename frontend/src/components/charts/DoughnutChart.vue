<script setup lang="ts">
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js'
import { Doughnut } from 'vue-chartjs'
import { computed } from 'vue'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps<{
  labels: string[]
  data: number[]
  colors: string[]
  centerText?: string
  centerSub?: string
}>()

const chartData = computed(() => ({
  labels: props.labels,
  datasets: [
    {
      data: props.data,
      backgroundColor: props.colors,
      borderWidth: 0,
      hoverOffset: 6,
    },
  ],
}))

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  cutout: '68%',
  plugins: {
    legend: {
      display: true,
      position: 'bottom' as const,
      labels: {
        padding: 16,
        usePointStyle: true,
        pointStyleWidth: 8,
        font: { size: 11, family: 'Inter' },
      },
    },
    tooltip: {
      backgroundColor: 'rgba(15,23,42,0.9)',
      titleFont: { family: 'Inter', size: 12 },
      bodyFont: { family: 'JetBrains Mono', size: 11 },
      padding: 10,
      cornerRadius: 8,
    },
  },
}))
</script>

<template>
  <div class="relative w-full h-full min-h-[220px]">
    <Doughnut :data="chartData" :options="chartOptions" />
    <!-- Center Text Overlay -->
    <div v-if="centerText" class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none" style="margin-bottom: 32px">
      <span class="text-2xl font-bold">{{ centerText }}</span>
      <span v-if="centerSub" class="text-xs opacity-60">{{ centerSub }}</span>
    </div>
  </div>
</template>
