import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useEventStream } from '@/composables/useEventStream'
import { caSeverity, compareSeverity } from '@/lib/severity'
import type {
  CaAuthority,
  CaExpiryAlertPayload,
  CaHealthPayload,
  DashboardStats,
  ListResponse,
  StreamEvent,
  StreamSnapshot,
} from '@/lib/types'

/**
 * Certificate authorities and dashboard totals, shared across every view.
 *
 * Dashboard and PkiOverview each fetched `/pki/authorities` independently and
 * shared nothing, so the same estate could be sorted one way on one page and
 * another way on the next, and a CA that went critical only updated on whichever
 * page happened to be reloaded. For a monitoring tool that is a correctness
 * problem, not a tidiness one.
 *
 * The store keeps the *full* CaAuthority records — the detail panel needs
 * subject, fingerprint, and revocation URLs, none of which the lean stream
 * snapshot carries — and overlays the live fields from the stream on top.
 */
export const useCasStore = defineStore('cas', () => {
  const api = useApi()
  const stream = useEventStream()

  const authorities = ref<CaAuthority[]>([])
  const stats = ref<DashboardStats | null>(null)

  const loading = ref(false)
  const loaded = ref(false)
  const error = ref<string | null>(null)
  /** When the REST snapshot last succeeded, or a live update last landed. */
  const lastUpdatedAt = ref<Date | null>(null)

  let inFlight: Promise<void> | null = null
  let controller: AbortController | null = null
  let reconcileTimer: number | null = null

  // ── Reads ───────────────────────────────────────────────

  /**
   * Most urgent first. Sorted client-side rather than trusting the server's
   * order, because a live delta can move a CA from healthy to critical without
   * a refetch and the list has to reorder itself when it does.
   */
  const byUrgency = computed(() =>
    [...authorities.value].sort((a, b) => {
      const bySeverity = compareSeverity(caSeverity(a.status), caSeverity(b.status))
      if (bySeverity !== 0) return bySeverity

      // A revoked CA outranks one that is merely close to expiring, even one
      // closer. Days remaining is the wrong comparison for it: it is not 729
      // days away from being a problem, it is a problem now — everything it
      // ever signed stopped being trustworthy the moment its parent revoked
      // it. Sorting it by expiry put it below a CA with 18 days left.
      const aRevoked = a.ocsp_status === 'REVOKED'
      const bRevoked = b.ocsp_status === 'REVOKED'
      if (aRevoked !== bRevoked) return aRevoked ? -1 : 1

      return a.days_remaining - b.days_remaining
    }),
  )

  const needingAttention = computed(
    () => authorities.value.filter((ca) => caSeverity(ca.status) !== 'ok').length,
  )

  const countByType = computed(() => {
    const counts = { ROOT: 0, INTERMEDIATE: 0, ISSUING: 0 } as Record<string, number>
    for (const ca of authorities.value) {
      counts[ca.ca_type] = (counts[ca.ca_type] ?? 0) + 1
    }
    return counts
  })

  /** Totals with a zeroed fallback, so a view never has to null-check. */
  const summary = computed<DashboardStats>(
    () =>
      stats.value ?? {
        total_certificates: 0,
        healthy_certs: 0,
        expiring_soon_certs: 0,
        expired_certs: 0,
        total_cas: 0,
        healthy_cas: 0,
        warning_cas: 0,
        critical_cas: 0,
        expired_cas: 0,
        unknown_cas: 0,
        total_scans: 0,
      },
  )

  function find(id: string | undefined): CaAuthority | undefined {
    if (!id) return undefined
    return authorities.value.find((ca) => ca.id === id)
  }

  // ── Fetching ────────────────────────────────────────────

  /**
   * Reloads authorities and totals together.
   *
   * Concurrent callers share one request: the stream's snapshot and a view's
   * onMounted both want this within the same tick on first paint, and two
   * identical round trips would be pure waste.
   */
  function refresh(): Promise<void> {
    if (inFlight) return inFlight

    controller?.abort()
    controller = new AbortController()
    const signal = controller.signal

    loading.value = true
    inFlight = (async () => {
      try {
        const [list, totals] = await Promise.all([
          api.get<ListResponse<CaAuthority>>('/api/v1/pki/authorities', signal),
          api.get<DashboardStats>('/api/v1/dashboard/stats', signal),
        ])
        if (signal.aborted) return
        authorities.value = list.data ?? []
        stats.value = totals
        error.value = null
        loaded.value = true
        lastUpdatedAt.value = new Date()
      } catch (err) {
        if (signal.aborted) return
        // Keep whatever was last loaded on screen. Blanking the view on a
        // transient failure loses the very information the reader needs.
        error.value = err instanceof Error ? err.message : String(err)
      } finally {
        if (!signal.aborted) loading.value = false
      }
    })()

    return inFlight.finally(() => {
      inFlight = null
    })
  }

  /**
   * Refetches shortly after a delta.
   *
   * Deltas update what they can immediately, which is what makes the screen feel
   * live; the refetch afterwards is what makes it *correct*, since a `ca.health`
   * payload cannot tell us the new certificate totals and an event for a CA we
   * have never seen carries none of its detail. Debounced so a health sweep
   * across the estate produces one reconciliation, not one per CA.
   */
  function scheduleReconcile(delayMs = 1500) {
    if (reconcileTimer !== null) window.clearTimeout(reconcileTimer)
    reconcileTimer = window.setTimeout(() => {
      reconcileTimer = null
      void refresh()
    }, delayMs)
  }

  // ── Live updates ────────────────────────────────────────

  function applySnapshot(snapshot: StreamSnapshot) {
    stats.value = snapshot.stats
    lastUpdatedAt.value = new Date()

    const known = new Map(authorities.value.map((ca) => [ca.id, ca]))
    let membershipChanged = snapshot.cas.length !== authorities.value.length

    for (const live of snapshot.cas) {
      const full = known.get(live.id)
      if (!full) {
        // A CA we hold no detail for. The snapshot deliberately omits the PEM
        // and the DNs, so this needs a real fetch rather than a half-populated
        // row that renders with blank fields.
        membershipChanged = true
        continue
      }
      full.status = live.status
      full.days_remaining = live.days_remaining
      full.not_after = live.not_after
      full.is_crl_fresh = live.is_crl_fresh
      full.certificates_issued_count = live.certificates_issued_count
      full.last_alert_threshold = live.last_alert_threshold
    }

    if (membershipChanged) void refresh()
    else loaded.value = true
  }

  function applyEvent(event: StreamEvent) {
    lastUpdatedAt.value = new Date()

    switch (event.topic) {
      case 'ca.health': {
        const p = event.payload as unknown as CaHealthPayload | undefined
        const ca = find(event.entity_id)
        if (ca && p) {
          ca.status = p.status
          ca.days_remaining = p.days_remaining
          ca.is_crl_fresh = p.is_crl_fresh
          ca.not_after = p.not_after
        }
        scheduleReconcile()
        break
      }

      case 'ca.expiry_alert': {
        const p = event.payload as unknown as CaExpiryAlertPayload | undefined
        const ca = find(event.entity_id)
        if (ca && p) {
          ca.days_remaining = p.days_remaining
          ca.last_alert_threshold = p.threshold
          ca.last_alert_sent_at = event.timestamp
        }
        scheduleReconcile()
        break
      }

      default:
        // Certificate and gateway events change totals this store cannot derive
        // from the CA records it holds. Reconciling is honest; guessing is not.
        if (event.topic.startsWith('cert.')) scheduleReconcile()
    }
  }

  // Registered once, for the life of the app. Pinia stores are singletons, so
  // there is no unmount to unwind here — the composable owns the connection.
  stream.onSnapshot(applySnapshot)
  stream.onEvent(applyEvent)

  return {
    authorities,
    stats,
    loading,
    loaded,
    error,
    lastUpdatedAt,
    byUrgency,
    needingAttention,
    countByType,
    summary,
    find,
    refresh,
  }
})
