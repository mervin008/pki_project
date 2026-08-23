<script setup lang="ts">
import { computed, ref } from 'vue'
import { sevBg, sevClass, type Severity } from '@/lib/severity'

/**
 * The expiry horizon.
 *
 * Every object CertPilot manages is dying on a clock, and the ordinary way to
 * show a fleet of them — a grid of equal cards, or a table sorted by name —
 * gives a CA with twenty days left exactly the same visual weight as one with
 * ten years. This puts them all on one time axis instead, so urgency is a
 * position rather than a value you have to read.
 *
 * **The axis is logarithmic**, and that is the whole design. On a linear axis
 * running to ten years, everything expiring inside a quarter — which is
 * everything worth looking at — collapses into the first two percent of the
 * width. Log spacing gives the next thirty days about a third of the screen and
 * compresses the safe years into the tail, which is the correct allocation of
 * attention: the left edge is death, and things drift toward it.
 *
 * Authorities sit above the axis and certificates below, sharing it. A cluster
 * of certificates directly beneath an issuing CA is the picture of the failure
 * this product exists to prevent, and it needs no explanation when you see it.
 */

export interface HorizonItem {
  id: string
  label: string
  days: number
  severity: Severity
  lane: 'authorities' | 'certificates'
  meta?: string
}

const props = withDefaults(
  defineProps<{
    items: HorizonItem[]
    /** Far end of the axis. Ten years covers a root CA's natural life. */
    maxDays?: number
  }>(),
  { maxDays: 3650 },
)

const emit = defineEmits<{ (e: 'select', id: string): void }>()

const hovered = ref<HorizonItem | null>(null)

/** Log position, 0 at the left edge (now) to 1 at maxDays. */
function positionOf(days: number): number {
  const clamped = Math.max(0, Math.min(days, props.maxDays))
  return Math.log1p(clamped) / Math.log1p(props.maxDays)
}

const TICKS: { days: number; label: string }[] = [
  { days: 0, label: 'NOW' },
  { days: 1, label: '24h' },
  { days: 7, label: '7d' },
  { days: 30, label: '30d' },
  { days: 90, label: '90d' },
  { days: 365, label: '1y' },
  { days: 1825, label: '5y' },
  { days: 3650, label: '10y' },
]

const ticks = computed(() =>
  TICKS.filter((t) => t.days <= props.maxDays).map((t) => {
    const x = positionOf(t.days) * 100
    // The last tick sits on the right edge, so a label drawn to the right of
    // its line falls outside the panel and gets clipped. Flip it inward.
    return { ...t, x, align: x > 92 ? ('end' as const) : ('start' as const) }
  }),
)

/** The alert thresholds the CA monitor actually uses, drawn as ground. */
const zones = computed(() => [
  { severity: 'critical' as const, from: 0, to: positionOf(30) * 100 },
  { severity: 'warning' as const, from: positionOf(30) * 100, to: positionOf(180) * 100 },
])

/**
 * Stacks marks that would otherwise sit on top of each other.
 *
 * Certificates issued in a batch all expire within hours of one another, so on
 * a log axis they land on the same pixel. Without stacking, forty certificates
 * and one certificate look identical — and "how many are about to go" is the
 * question being asked. Worst-first, so a critical mark is never the one
 * pushed into a back row.
 */
function pack(items: HorizonItem[]) {
  const placed = items
    .map((item) => ({ item, x: positionOf(item.days) * 100 }))
    .sort((a, b) => a.x - b.x)

  const MIN_GAP = 1.7
  const MAX_ROWS = 5
  const rowEnds: number[] = []

  return placed.map(({ item, x }) => {
    let row = rowEnds.findIndex((end) => x - end >= MIN_GAP)
    if (row === -1) {
      row = rowEnds.length < MAX_ROWS ? rowEnds.length : MAX_ROWS - 1
    }
    rowEnds[row] = x
    return { item, x, row }
  })
}

const authorities = computed(() => pack(props.items.filter((i) => i.lane === 'authorities')))
const certificates = computed(() => pack(props.items.filter((i) => i.lane === 'certificates')))

/**
 * What the readout shows when nothing is hovered: the single most urgent thing
 * on the axis. A monitoring surface should never be idle — with no pointer on
 * it, it still names the worst problem you have.
 */
const mostUrgent = computed(() => {
  const sorted = [...props.items].sort((a, b) => a.days - b.days)
  return sorted[0] ?? null
})

const focus = computed(() => hovered.value ?? mostUrgent.value)
const isEmpty = computed(() => props.items.length === 0)

const ROW_HEIGHT = 14
</script>

<template>
  <div class="horizon substrate">
    <!-- Threshold ground. Barely visible on purpose: it is the scale the marks
         are read against, not a thing to be looked at. -->
    <div class="horizon-zones" aria-hidden="true">
      <div
        v-for="zone in zones"
        :key="zone.severity"
        class="horizon-zone"
        :data-severity="zone.severity"
        :style="{ left: `${zone.from}%`, width: `${zone.to - zone.from}%` }"
      />
    </div>

    <!-- Authorities, above the axis -->
    <div class="horizon-lane" data-side="above">
      <span class="horizon-lane-label">Authorities</span>
      <div class="horizon-plot" data-side="above">
        <button
          v-for="mark in authorities"
          :key="mark.item.id"
          class="horizon-mark"
          :data-severity="mark.item.severity"
          :style="{ left: `${mark.x}%`, '--stem': `${(mark.row + 1) * ROW_HEIGHT}px` }"
          :title="`${mark.item.label} · ${mark.item.days}d`"
          @mouseenter="hovered = mark.item"
          @mouseleave="hovered = null"
          @focus="hovered = mark.item"
          @blur="hovered = null"
          @click="emit('select', mark.item.id)"
        >
          <span class="horizon-stem" />
          <span class="horizon-dot" :class="sevBg(mark.item.severity)" />
        </button>
      </div>
    </div>

    <!-- The axis itself -->
    <div class="horizon-axis">
      <div
        v-for="tick in ticks"
        :key="tick.label"
        class="horizon-tick"
        :style="{ left: `${tick.x}%` }"
        :data-edge="tick.days === 0 ? 'now' : undefined"
        :data-align="tick.align"
      >
        <span class="horizon-tick-label">{{ tick.label }}</span>
      </div>
    </div>

    <!-- Certificates, below -->
    <div class="horizon-lane" data-side="below">
      <div class="horizon-plot" data-side="below">
        <button
          v-for="mark in certificates"
          :key="mark.item.id"
          class="horizon-mark"
          :data-severity="mark.item.severity"
          :style="{ left: `${mark.x}%`, '--stem': `${(mark.row + 1) * ROW_HEIGHT}px` }"
          :title="`${mark.item.label} · ${mark.item.days}d`"
          @mouseenter="hovered = mark.item"
          @mouseleave="hovered = null"
          @focus="hovered = mark.item"
          @blur="hovered = null"
          @click="emit('select', mark.item.id)"
        >
          <span class="horizon-stem" />
          <span class="horizon-dot" :class="sevBg(mark.item.severity)" />
        </button>
      </div>
      <span class="horizon-lane-label">Certificates</span>
    </div>

    <!-- The readout. Fixed height so the layout never jumps as the pointer
         crosses marks. -->
    <div class="horizon-readout">
      <template v-if="focus">
        <span class="horizon-readout-caret" :class="sevClass(focus.severity)">▲</span>
        <span class="horizon-readout-name">{{ focus.label }}</span>
        <span class="horizon-readout-days" :class="sevClass(focus.severity)">
          {{ focus.days < 0 ? 'expired' : `${focus.days}d` }}
        </span>
        <span v-if="focus.meta" class="horizon-readout-meta">{{ focus.meta }}</span>
        <span v-if="!hovered" class="horizon-readout-hint">most urgent</span>
      </template>
      <span v-else-if="isEmpty" class="horizon-readout-hint prose-ui">
        Nothing is being monitored yet. Connect a CA account to populate the horizon.
      </span>
    </div>
  </div>
</template>

<style scoped>
.horizon {
  position: relative;
  padding: 0.5rem 0.75rem 0;
  border: 1px solid var(--line);
  background: var(--ink-panel);
  overflow: hidden;
}

.horizon-zones {
  position: absolute;
  inset: 0;
  pointer-events: none;
}

.horizon-zone {
  position: absolute;
  top: 0;
  bottom: 30px;
}

.horizon-zone[data-severity='critical'] {
  background: linear-gradient(90deg, var(--sev-critical-wash), transparent);
}

.horizon-zone[data-severity='warning'] {
  background: linear-gradient(90deg, var(--sev-warning-wash), transparent);
}

.horizon-lane {
  position: relative;
  display: flex;
  flex-direction: column;
}

.horizon-lane[data-side='below'] {
  flex-direction: column-reverse;
}

.horizon-lane-label {
  font-size: var(--fs-micro);
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--text-muted);
  padding: 0.125rem 0;
}

.horizon-plot {
  position: relative;
  height: 76px;
}

/* A mark is a stem rising from the axis with a dot on the end — the axis is
   "now + this many days", and the stem is what ties the dot to its position on
   it. Free-floating dots lose that link the moment they stack. */
.horizon-mark {
  position: absolute;
  display: flex;
  align-items: center;
  width: 9px;
  margin-left: -4.5px;
  height: var(--stem);
  background: none;
  border: 0;
  padding: 0;
  cursor: pointer;
}

.horizon-plot[data-side='above'] .horizon-mark {
  bottom: 0;
  flex-direction: column-reverse;
}

.horizon-plot[data-side='below'] .horizon-mark {
  top: 0;
  flex-direction: column;
}

.horizon-stem {
  flex: 1;
  width: 1px;
  margin: 0 auto;
  background: var(--line-strong);
}

.horizon-dot {
  width: 6px;
  height: 6px;
  flex: none;
  margin: 0 auto;
  border-radius: 50%;
  transition: transform 0.1s;
}

/* A critical mark is bigger and haloed. Position already encodes urgency, but
   the left of a log axis is also the most crowded part of it, and the one thing
   that must never happen is a critical mark lost in a cluster. */
.horizon-mark[data-severity='critical'] .horizon-dot {
  width: 9px;
  height: 9px;
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--sev-critical) 22%, transparent);
}

.horizon-mark[data-severity='critical'] .horizon-stem {
  background: color-mix(in srgb, var(--sev-critical) 45%, transparent);
}

.horizon-mark[data-severity='warning'] .horizon-stem {
  background: color-mix(in srgb, var(--sev-warning) 38%, transparent);
}

.horizon-mark:hover .horizon-dot,
.horizon-mark:focus-visible .horizon-dot {
  transform: scale(1.6);
}

.horizon-axis {
  position: relative;
  height: 30px;
  border-top: 1px solid var(--line-strong);
}

.horizon-tick {
  position: absolute;
  top: 0;
  height: 100%;
  border-left: 1px solid var(--line);
}

/* "NOW" is the edge everything is falling toward, so it is the one gridline
   drawn at full strength. */
.horizon-tick[data-edge='now'] {
  border-left-color: var(--text-muted);
}

.horizon-tick[data-align='end'] .horizon-tick-label {
  left: auto;
  right: 3px;
}

.horizon-tick-label {
  position: absolute;
  top: 4px;
  left: 3px;
  font-size: var(--fs-micro);
  letter-spacing: 0.1em;
  color: var(--text-muted);
  white-space: nowrap;
}

.horizon-readout {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
  height: 30px;
  padding: 0.25rem 0;
  border-top: 1px solid var(--line);
  font-size: var(--fs-small);
  min-width: 0;
}

.horizon-readout-caret {
  font-size: var(--fs-micro);
}

.horizon-readout-name {
  color: var(--text-primary);
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.horizon-readout-days {
  font-weight: 600;
}

.horizon-readout-meta,
.horizon-readout-hint {
  color: var(--text-muted);
  font-size: var(--fs-micro);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  white-space: nowrap;
}

.horizon-readout-hint {
  margin-left: auto;
}
</style>
