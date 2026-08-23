import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { useEventStream } from '@/composables/useEventStream'
import { isActionable } from '@/lib/events'
import type { StreamEvent } from '@/lib/types'

/**
 * The live feed of things that happened, newest first.
 *
 * Distinct from the audit log the dashboard already shows. The audit log is the
 * durable record and carries actor identity, which is why a kiosk display token
 * is refused on `/dashboard/activity`. This is the volatile, viewer-safe view of
 * what the core has announced since this tab connected — the thing a wall
 * display can show.
 */

/** How many events to retain. A wall display scrolls; it does not archive. */
const FEED_LIMIT = 200

export const useAlertsStore = defineStore('alerts', () => {
  const stream = useEventStream()

  const feed = ref<StreamEvent[]>([])
  /** When the operator last opened the alert list. */
  const acknowledgedAt = ref<Date | null>(null)
  /**
   * Set when the server tells us we fell behind and lost events.
   *
   * This is shown rather than swallowed. A feed that is missing entries and
   * does not say so is a feed that reports "nothing happened" when what actually
   * happened is that we stopped listening.
   */
  const incomplete = ref(false)
  const droppedCount = ref(0)

  const seen = new Set<number>()

  /** Everything a PKI team would act on — warnings and criticals. */
  const actionable = computed(() => feed.value.filter(isActionable))

  const criticalCount = computed(
    () => feed.value.filter((e) => e.severity === 'CRITICAL').length,
  )

  /** Actionable events that arrived since the operator last looked. */
  const unacknowledged = computed(() => {
    const since = acknowledgedAt.value
    if (!since) return actionable.value
    return actionable.value.filter((e) => new Date(e.timestamp) > since)
  })

  const unacknowledgedCount = computed(() => unacknowledged.value.length)

  /** Worst severity currently unacknowledged, for the badge colour. */
  const peakSeverity = computed<'critical' | 'warning' | null>(() => {
    if (unacknowledged.value.some((e) => e.severity === 'CRITICAL')) return 'critical'
    if (unacknowledged.value.length > 0) return 'warning'
    return null
  })

  function record(event: StreamEvent) {
    // A reconnect replays from history, so the same event can arrive twice.
    // Without this the badge inflates every time the network hiccups.
    if (seen.has(event.id)) return
    seen.add(event.id)

    feed.value.unshift(event)
    if (feed.value.length > FEED_LIMIT) {
      for (const dropped of feed.value.splice(FEED_LIMIT)) seen.delete(dropped.id)
    }
  }

  function markResync(dropped: number) {
    incomplete.value = true
    droppedCount.value += dropped
  }

  function acknowledge() {
    acknowledgedAt.value = new Date()
  }

  /** Clears the feed and the incomplete flag — an explicit operator action. */
  function clear() {
    feed.value = []
    seen.clear()
    incomplete.value = false
    droppedCount.value = 0
    acknowledgedAt.value = new Date()
  }

  stream.onEvent(record)
  stream.onResync(markResync)

  return {
    feed,
    actionable,
    unacknowledged,
    unacknowledgedCount,
    criticalCount,
    peakSeverity,
    incomplete,
    droppedCount,
    acknowledgedAt,
    acknowledge,
    clear,
  }
})
