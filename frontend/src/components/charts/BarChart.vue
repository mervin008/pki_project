<script setup lang="ts">
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from 'chart.js'
import { Bar } from 'vue-chartjs'
import { computed } from 'vue'

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend)

const props = defineProps<{
  labels: string[]
  datasets: { label: string; data: number[]; backgroundColor: string }[]
}>()

const chartData = computed(() => ({
  labels: props.labels,
  datasets: props.datasets.map(ds => ({
    ...ds,
    borderRadius: 6,
    borderSkipped: false as const,
    maxBarThickness: 40,
  })),
}))

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    x: {
      grid: { display: false },
      ticks: { font: { size: 10, family: 'Inter' } },
    },
    y: {
      beginAtZero: true,
      grid: { color: 'rgba(148,163,184,0.12)' },
      ticks: { font: { size: 10, family: 'JetBrains Mono' }, stepSize: 1 },
    },
  },
  plugins: {
    legend: {
      display: props.datasets.length > 1,
      position: 'bottom' as const,
      labels: { padding: 14, usePointStyle: true, pointStyleWidth: 8, font: { size: 11, family: 'Inter' } },
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
  <div class="w-full h-full min-h-[220px]">
    <Bar :data="chartData" :options="chartOptions" />
  </div>
</template>
