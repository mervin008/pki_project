<script setup lang="ts">
/**
 * The only container in the interface.
 *
 * Not a card: no shadow, no radius, no floating. A bordered region with a
 * labelled header rail, the way an instrument groups a readout. Cards imply
 * independent objects of equal importance, which is exactly the wrong reading
 * for a screen where one row matters and four hundred do not.
 */
withDefaults(
  defineProps<{
    /** Tracked uppercase label in the header rail. */
    label?: string
    /** Right-aligned count or status, e.g. "3 NEED ATTENTION". */
    note?: string
    /** Severity for the note, when it is reporting a problem. */
    noteSeverity?: 'critical' | 'warning' | 'ok' | 'unknown'
    /** Drop the body padding — for tables, which supply their own. */
    flush?: boolean
  }>(),
  { flush: false },
)
</script>

<template>
  <section class="panel">
    <header v-if="label || note || $slots.actions" class="panel-head">
      <span v-if="label" class="label-rail">{{ label }}</span>
      <span class="flex-1"></span>
      <slot name="actions" />
      <span
        v-if="note"
        class="label-micro"
        :class="noteSeverity && noteSeverity !== 'unknown' ? `sev-${noteSeverity}` : ''"
      >
        {{ note }}
      </span>
    </header>
    <div :class="flush ? 'panel-body-flush' : 'panel-body'">
      <slot />
    </div>
  </section>
</template>
