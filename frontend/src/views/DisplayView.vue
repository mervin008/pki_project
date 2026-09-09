<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { AlertTriangle, Maximize, ShieldCheck, WifiOff } from 'lucide-vue-next'
import { useCasStore } from '@/stores/cas'
import { useEventStream } from '@/composables/useEventStream'
import { caSeverity, compareSeverity, sevClass, statusLabel, type Severity } from '@/lib/severity'
import { hasDisplayToken } from '@/lib/displayToken'
import { formatDate } from '@/lib/format'

/**
 * Wall mode — the unattended screen in the PKI team's area.
 *
 * Everything here is sized to be read from across a room by someone who is not
 * looking for a problem, and who will only glance up if the screen changes. That
 * makes the failure modes the important part of the design, not the happy path:
 *
 *  - **A dead feed takes over the screen.** When the stream goes stale this does
 *    not degrade politely — an alarm band covers the top, the figures grey out,
 *    and the last time the data was confirmed is stated in words. A frozen green
 *    wall display is worse than a blank one, because it actively tells the team
 *    everything is fine.
 *  - **Nothing needing attention is ever below the fold.** Only as many rows as
 *    fit are drawn, but if anything urgent did not fit, the count of what was
 *    left off is stated in the footer in warning colour.
 *  - **Empty never reads as healthy.** No CAs under management produces a
 *    message saying so, not a calm green screen.
 *
 * Authentication is the kiosk display token in the launch URL; see
 * lib/displayToken.ts. It grants viewer, GETs only, and is revocable.
 */

const cas = useCasStore()
const stream = useEventStream()

// ── Clock ─────────────────────────────────────────────────
// A visibly ticking clock is itself a liveness signal: a photograph of a frozen
// screen and a photograph of a working one are otherwise identical.
const now = ref(new Date())
const clock = window.setInterval(() => (now.value = new Date()), 1000)
onUnmounted(() => window.clearInterval(clock))

const timeText = computed(() =>
  now.value.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
)
const dateText = computed(() =>
  now.value.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' }),
)

// ── How many rows fit ─────────────────────────────────────
// Wall displays range from a 24" desk monitor to a 65" panel. Rather than
// picking a number that is wrong for both, measure.
const viewportHeight = ref(window.innerHeight)
function measure() {
  viewportHeight.value = window.innerHeight
}
onMounted(() => window.addEventListener('resize', measure))
onUnmounted(() => window.removeEventListener('resize', measure))

const ROW_HEIGHT = 84
const CHROME_HEIGHT = 400
const rowLimit = computed(() =>
  Math.max(3, Math.floor((viewportHeight.value - CHROME_HEIGHT) / ROW_HEIGHT)),
)

const shown = computed(() => cas.byUrgency.slice(0, rowLimit.value))
const hidden = computed(() => cas.byUrgency.slice(rowLimit.value))
const hiddenNeedingAttention = computed(
  () => hidden.value.filter((ca) => caSeverity(ca.status) !== 'ok').length,
)

// ── State ─────────────────────────────────────────────────

const stale = computed(() => stream.status.value === 'stale')
const connecting = computed(
  () => !cas.loaded && (stream.status.value === 'connecting' || cas.loading),
)

/**
 * A screen that cannot authenticate has to say so plainly, or it sits there
 * showing "connecting" forever while nobody realises the token was revoked.
 *
 * Deliberately not conditioned on whether data was ever loaded. Revoking a
 * token while a screen is running is the normal case — that is what revocation
 * is *for* — and the open stream survives it until the connection next drops, so
 * a display can be hours into its last-known-good figures before the rejection
 * appears. Falling back to the generic "not receiving updates" band there would
 * be true but useless: it points at the network, when the fix is administrative.
 *
 * Taking over the screen loses the last-known figures, which is correct. A
 * revoked display cannot be trusted to be showing anything current, and saying
 * why is worth more than the stale numbers it would otherwise keep.
 */
const unauthorised = computed(() => {
  if (stream.status.value === 'live') return false
  const message = `${stream.lastError.value ?? ''} ${cas.error ?? ''}`.toLowerCase()
  return (
    message.includes('sign in') ||
    message.includes('display token') ||
    message.includes('not permitted') ||
    message.includes('unauthorized') ||
    message.includes('unauthorised')
  )
})

const worst = computed<Severity>(() => {
  let peak: Severity = 'ok'
  for (const ca of cas.authorities) {
    if (compareSeverity(caSeverity(ca.status), peak) < 0) peak = caSeverity(ca.status)
  }
  return peak
})

const needingAttention = computed(() => cas.needingAttention)

/** Big tiles. Every one is a real figure from the API; none has a fallback. */
const tiles = computed(() => [
  { label: 'Authorities', value: cas.authorities.length, tone: '' },
  { label: 'Healthy', value: cas.summary.healthy_cas, tone: 'text-success' },
  { label: 'Warning', value: cas.summary.warning_cas, tone: 'text-warning' },
  { label: 'Critical', value: cas.summary.critical_cas, tone: 'text-error' },
  { label: 'Expired', value: cas.summary.expired_cas, tone: 'text-error' },
  { label: 'Unassessed', value: cas.summary.unknown_cas, tone: 'text-[color:var(--text-secondary)]' },
])

const staleSince = computed(() => {
  const last = stream.lastEventAt.value ?? cas.lastUpdatedAt
  if (!last) return null
  return last.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
})

function goFullscreen() {
  void document.documentElement.requestFullscreen?.().catch(() => {
    // Refused without a user gesture, or unsupported. The kiosk browser is
    // normally launched fullscreen anyway; this is a convenience.
  })
}

function remaining(days: number): string {
  if (days === null || days === undefined || Number.isNaN(days)) return '—'
  if (days < 0) return 'EXPIRED'
  return String(days)
}
</script>

<template>
  <div class="h-screen w-screen flex flex-col overflow-hidden select-none">
    <!-- Alarm band. Occupies the top of the screen so a dead feed is the first
         thing seen, ahead of any figure it would otherwise be trusted for.
         Suppressed when the reason is a rejected credential: the panel below
         says the same thing more precisely, and two alarms for one fault make
         the screen harder to read, not more urgent. -->
    <div
      v-if="stale && !unauthorised"
      role="alert"
      class="wall-alarm px-8 py-4 flex items-center gap-5 shrink-0 bg-[color:var(--sev-critical)] text-[color:var(--ink-page)]"
    >
      <WifiOff class="w-10 h-10 shrink-0" />
      <div class="min-w-0">
        <div class="text-3xl font-black tracking-tight">NOT RECEIVING UPDATES</div>
        <div class="text-lg opacity-90">
          <template v-if="staleSince">
            Everything below was last confirmed at {{ staleSince }} and may be wrong.
          </template>
          <template v-else>No data has been received since this screen was opened.</template>
          <template v-if="stream.lastError.value"> — {{ stream.lastError.value }}</template>
        </div>
      </div>
    </div>

    <!-- Header -->
    <header class="px-8 pt-6 pb-4 flex items-end justify-between gap-6 shrink-0">
      <div class="flex items-center gap-4 min-w-0">
        <div
          class="w-12 h-12 flex items-center justify-center font-bold font-mono shrink-0 bg-[color:var(--signal)] text-[color:var(--ink-page)]"
        >
          CP
        </div>
        <div class="min-w-0">
          <div class="text-2xl font-black tracking-tight leading-tight">
            Certificate Authority Health
          </div>
          <div class="text-sm text-[color:var(--text-muted)] font-mono">
            CertPilot ·
            <span :class="stale ? 'text-error font-bold' : 'text-success'">
              {{ stale ? 'FEED DOWN' : statusLabel(stream.status.value) }}
            </span>
          </div>
        </div>
      </div>

      <div class="text-right shrink-0">
        <div class="text-5xl font-black tabular-nums leading-none">{{ timeText }}</div>
        <div class="text-sm text-[color:var(--text-muted)] mt-1">{{ dateText }}</div>
      </div>

      <button
        class="btn-console opacity-20 hover:opacity-100 shrink-0"
        title="Fullscreen"
        @click="goFullscreen"
      >
        <Maximize class="w-4 h-4" />
      </button>
    </header>

    <!-- Body. Greys out wholesale when the feed is stale: every figure in it is
         then last-known-good, and it must not look like a live readout. -->
    <!-- Greyed out while stale, since every figure in it is then last-known-good.
         Not greyed when unauthorised: what it holds then is the explanation, and
         draining the colour out of the one readable thing on the screen would be
         the opposite of the point. -->
    <div
      class="flex-1 min-h-0 px-8 pb-6 flex flex-col gap-5"
      :class="{ 'surface-stale': stale && !unauthorised }"
    >
      <!-- Not authorised -->
      <div v-if="unauthorised" class="flex-1 flex items-center justify-center">
        <div class="text-center max-w-2xl">
          <AlertTriangle class="w-20 h-20 mx-auto sev-critical" />
          <h2 class="text-4xl font-black mt-6">This display is not authorised</h2>
          <p class="text-lg text-[color:var(--text-secondary)] mt-3">
            {{ stream.lastError.value ?? cas.error }}
          </p>
          <p class="text-base text-[color:var(--text-muted)] mt-6">
            <template v-if="hasDisplayToken()">
              The display token this screen is using has been revoked or has expired. An
              administrator can issue a replacement and relaunch this screen at its new URL.
            </template>
            <template v-else>
              Launch this screen at a URL carrying a display token, for example
              <code class="font-mono text-sm">/display?display_token=cpd_…</code>
            </template>
          </p>
        </div>
      </div>

      <!-- First load -->
      <div v-else-if="connecting" class="flex-1 flex items-center justify-center">
        <div class="text-center">
          <span class="spinner-console loading-lg opacity-40"></span>
          <p class="text-xl text-[color:var(--text-muted)] mt-4">Connecting to CertPilot…</p>
        </div>
      </div>

      <template v-else>
        <!-- Totals -->
        <div class="grid grid-cols-6 gap-3 shrink-0">
          <div
            v-for="tile in tiles"
            :key="tile.label"
            class="border px-4 py-3"
          >
            <div class="text-4xl font-black tabular-nums leading-none" :class="tile.tone">
              {{ tile.value }}
            </div>
            <div class="text-xs uppercase tracking-widest text-[color:var(--text-muted)] mt-1.5">
              {{ tile.label }}
            </div>
          </div>
        </div>

        <!-- The list -->
        <div v-if="shown.length" class="flex-1 min-h-0 flex flex-col gap-2">
          <div
            v-for="ca in shown"
            :key="ca.id"
            class="border border-l-8 border-[color:var(--line)] flex items-center gap-6 px-6 py-3"
            :class="sevClass(caSeverity(ca.status))"
            :style="{ borderLeftColor: `var(--sev-${caSeverity(ca.status)})` }"
          >
            <div class="w-28 text-center shrink-0">
              <div
                class="font-black tabular-nums leading-none"
                :class="[
                  sevClass(caSeverity(ca.status)),
                  ca.days_remaining < 0 ? 'text-2xl' : 'text-5xl',
                ]"
              >
                {{ remaining(ca.days_remaining) }}
              </div>
              <div
                v-if="ca.days_remaining >= 0"
                class="text-[11px] uppercase tracking-widest opacity-50 mt-1"
              >
                days
              </div>
            </div>

            <div class="min-w-0 flex-1">
              <div class="text-2xl font-bold truncate leading-tight">{{ ca.name }}</div>
              <div class="text-sm text-[color:var(--text-muted)] font-mono">
                {{ statusLabel(ca.ca_type) }} · expires {{ formatDate(ca.not_after) }}
                <template v-if="ca.crl_distribution_url && !ca.is_crl_fresh">
                  · <span class="sev-warning">CRL stale</span>
                </template>
              </div>
            </div>

            <div
              class="text-xl font-bold uppercase tracking-wide shrink-0"
              :class="sevClass(caSeverity(ca.status))"
            >
              {{ statusLabel(ca.status) }}
            </div>
          </div>
        </div>

        <!-- No CAs at all. Deliberately not a green all-clear. -->
        <div v-else class="flex-1 flex items-center justify-center">
          <div class="text-center">
            <ShieldCheck class="w-20 h-20 mx-auto opacity-20" />
            <h2 class="text-3xl font-bold mt-5">No certificate authorities are being monitored</h2>
            <p class="text-lg text-[color:var(--text-muted)] mt-2">
              This screen is empty because nothing has been imported, not because everything is
              healthy.
            </p>
          </div>
        </div>

        <!-- Footer. Anything urgent that did not fit is called out here, in
             warning colour, rather than silently truncated. -->
        <div
          v-if="hidden.length"
          class="text-center text-base shrink-0"
          :class="hiddenNeedingAttention > 0 ? 'sev-warning font-bold' : 'text-[color:var(--text-muted)]'"
        >
          <template v-if="hiddenNeedingAttention > 0">
            {{ hiddenNeedingAttention }} further
            {{ hiddenNeedingAttention === 1 ? 'authority needs' : 'authorities need' }}
            attention and could not fit on this screen
          </template>
          <template v-else>
            {{ hidden.length }} more {{ hidden.length === 1 ? 'authority' : 'authorities' }}, all
            healthy
          </template>
        </div>

        <div
          v-else-if="worst === 'ok' && cas.authorities.length"
          class="text-center text-base text-[color:var(--text-muted)] shrink-0"
        >
          All {{ cas.authorities.length }} authorities healthy · {{ needingAttention }} needing
          attention
        </div>
      </template>
    </div>
  </div>
</template>
