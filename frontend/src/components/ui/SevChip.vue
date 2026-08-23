<script setup lang="ts">
import { computed } from 'vue'
import { sevClass, sevLabel, type Severity } from '@/lib/severity'

/**
 * A severity as a squared block with a heavy leading bar.
 *
 * Deliberately not a pill. Rounded pills read as decoration and every admin
 * template is full of them; a squared block with a rule down its left edge
 * reads as a state something reported.
 */
const props = defineProps<{ severity: Severity; label?: string }>()

const text = computed(() => props.label ?? sevLabel(props.severity))
</script>

<template>
  <span class="chip" :class="sevClass(severity)">{{ text }}</span>
</template>
