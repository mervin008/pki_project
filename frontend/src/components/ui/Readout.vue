<script setup lang="ts">
import { computed } from 'vue'
import { sevClass, type Severity } from '@/lib/severity'

/**
 * A single large number with a tracked label beneath it.
 *
 * The number comes first and the label second, at a tenth of the size. On a
 * console the figure is what is being read; the word is only there to say what
 * it counts, and sizing the two similarly — as stat tiles usually do — makes
 * neither legible at distance.
 */
const props = withDefaults(
  defineProps<{
    value: number | string
    label: string
    /** Colours the figure. Omit entirely for counts that are not a problem. */
    severity?: Severity
    /** Small trailing unit, set in the muted colour: "days", "certs". */
    unit?: string
    large?: boolean
  }>(),
  { large: false },
)

const tone = computed(() => (props.severity ? sevClass(props.severity) : ''))
</script>

<template>
  <div class="flex flex-col gap-1 min-w-0">
    <div class="flex items-baseline gap-1.5 min-w-0">
      <span :class="[large ? 'readout-lg' : 'readout', tone]">{{ value }}</span>
      <span v-if="unit" class="label-micro shrink-0">{{ unit }}</span>
    </div>
    <span class="label-micro truncate">{{ label }}</span>
  </div>
</template>
