import { computed, readonly, ref, type ComputedRef, type Ref } from 'vue'
import { supabase } from '@/lib/supabase'
import { createSseParser } from '@/lib/sse'
import { displayTokenHeaders } from '@/lib/displayToken'
import type { StreamEvent, StreamSnapshot } from '@/lib/types'

/**
 * Client for the core's Server-Sent Events endpoint.
 *
 * The governing rule for this file: **a dashboard that has stopped updating
 * must look broken, not healthy.** A frozen screen showing green manufactures
 * false confidence, which is worse than no screen at all. Everything unusual
 * below follows from that — the watchdog, the separation of "last contact" from
 * "last data", and the refusal to leave `status` at `live` on the strength of a
 * socket that merely has not errored yet.
 *
 * ## Why fetch, and not EventSource
 *
 * `EventSource` cannot set request headers, so it cannot carry the operator's
 * bearer token; it would authenticate only in anonymous development mode or
 * with a kiosk token in the query string. Its reconnect is also fixed-interval
 * and uncontrollable beyond the server's `retry:` directive, so the
 * exponential backoff this needs would mean fighting the built-in behaviour
 * with close()/new anyway.
 *
 * `fetch` with a streaming body gives headers, an AbortController for teardown,
 * and full control of the reconnect schedule, at the cost of ~50 lines of SSE
 * framing. That trade is worth making once, here.
 */

/** Where the client thinks it stands. Ordered worst-last for reasoning. */
export type StreamStatus = 'connecting' | 'reconnecting' | 'stale' | 'live'

const STREAM_URL = '/api/v1/events'

/**
 * How long without a single byte from the server before the surface is declared
 * stale.
 *
 * The server heartbeats every 15s (core/api/events.go), so this is two missed
 * heartbeats plus margin. It has to be short: the whole point is that a wall
 * display goes visibly wrong within seconds of losing its feed, not minutes.
 */
const STALE_AFTER_MS = 35_000

/** How often the watchdog checks data age. */
const WATCHDOG_INTERVAL_MS = 1_000

/** Reconnect delay ceiling. A screen in a corridor has nobody to press retry. */
const MAX_RETRY_MS = 30_000

/** Fallback base delay, replaced by the server's `retry:` directive on connect. */
const DEFAULT_RETRY_MS = 3_000

export interface EventStream {
  /** Connection state, degraded by the staleness watchdog. */
  status: ComputedRef<StreamStatus>
  /** True when nothing has arrived for longer than the stale threshold. */
  isStale: ComputedRef<boolean>
  /**
   * When a `snapshot` or topic event last arrived — what "last updated" means
   * to a reader. Heartbeats do not move it: they prove the link is alive, not
   * that the data is fresh.
   */
  lastEventAt: Readonly<Ref<Date | null>>
  /**
   * When any byte last arrived, heartbeats included. This is what liveness is
   * judged on; conflating it with lastEventAt would mean a quiet PKI looked
   * like a dead connection.
   */
  lastContactAt: Readonly<Ref<Date | null>>
  /** Consecutive failed connection attempts. Zero while connected. */
  attempt: Readonly<Ref<number>>
  /** Why the last attempt failed, for the operator. Null when healthy. */
  lastError: Readonly<Ref<string | null>>
  connect: () => void
  disconnect: () => void
  /** Abandon any backoff and retry immediately. */
  reconnectNow: () => void
  onSnapshot: (fn: (snapshot: StreamSnapshot) => void) => () => void
  onEvent: (fn: (event: StreamEvent) => void) => () => void
  /**
   * The server has told us we fell behind and lost events. A consumer that
   * hears this knows its view is incomplete and must say so; a snapshot follows
   * immediately.
   */
  onResync: (fn: (dropped: number) => void) => () => void
}

function createEventStream(): EventStream {
  // Raw connection state, before the watchdog gets a say.
  const connection = ref<'idle' | 'connecting' | 'open' | 'reconnecting'>('idle')
  const stale = ref(false)
  const attempt = ref(0)
  const lastError = ref<string | null>(null)
  const lastEventAt = ref<Date | null>(null)
  const lastContactAt = ref<Date | null>(null)

  const snapshotHandlers = new Set<(s: StreamSnapshot) => void>()
  const eventHandlers = new Set<(e: StreamEvent) => void>()
  const resyncHandlers = new Set<(dropped: number) => void>()

  let controller: AbortController | null = null
  let watchdog: number | null = null
  let running = false
  let stopping = false
  let lastEventId: string | null = null
  let retryBaseMs = DEFAULT_RETRY_MS
  /** Resolves a pending backoff early, so a retry can be forced. */
  let wake: (() => void) | null = null

  // Stale wins over everything. A connection that is technically open but has
  // delivered nothing for half a minute is not "live", and calling it live is
  // exactly the lie this component exists to prevent.
  const status = computed<StreamStatus>(() => {
    if (stale.value) return 'stale'
    if (connection.value === 'open') return 'live'
    if (connection.value === 'reconnecting') return 'reconnecting'
    return 'connecting'
  })

  // ── SSE framing ─────────────────────────────────────────

  const parser = createSseParser()

  function feed(text: string) {
    for (const frame of parser.push(text)) {
      if (frame.id !== undefined) lastEventId = frame.id
      if (frame.retry !== undefined) retryBaseMs = frame.retry
      if (frame.data === '') continue
      dispatch(frame.event, frame.data)
    }
  }

  function dispatch(name: string, raw: string) {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      // Report rather than swallow: a frame we cannot read means the view is
      // missing something, and silence would hide that.
      lastError.value = `the server sent a ${name} frame that is not valid JSON`
      return
    }

    lastEventAt.value = new Date()

    switch (name) {
      case 'snapshot':
        for (const fn of snapshotHandlers) fn(parsed as StreamSnapshot)
        break
      case 'resync': {
        const detail = parsed as { dropped?: number }
        for (const fn of resyncHandlers) fn(detail.dropped ?? 0)
        break
      }
      case 'error': {
        const detail = parsed as { message?: string }
        lastError.value = detail.message ?? 'the server could not build the event stream'
        break
      }
      default:
        for (const fn of eventHandlers) fn(parsed as StreamEvent)
    }
  }

  // ── Connection ──────────────────────────────────────────

  function markAlive() {
    lastContactAt.value = new Date()
    if (stale.value) {
      stale.value = false
      lastError.value = null
    }
  }

  /**
   * Headers for the stream request.
   *
   * Two ways to authenticate: an operator's bearer token, or the kiosk display
   * token a wall screen is launched with. `displayTokenHeaders` mirrors the
   * server's precedence — a real session always wins, so a display token left in
   * a bookmark cannot mask an operator's identity.
   */
  async function authHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = { Accept: 'text/event-stream' }

    if (supabase) {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (session?.access_token) {
        headers.Authorization = `Bearer ${session.access_token}`
      }
    }

    Object.assign(headers, displayTokenHeaders(headers.Authorization !== undefined))

    // Resume from where we left off. The core replays from its history when it
    // can, and sends a fresh snapshot when the gap is too wide — it never
    // silently skips, which would leave the dashboard confidently wrong.
    if (lastEventId) headers['Last-Event-ID'] = lastEventId

    return headers
  }

  async function readStream(signal: AbortSignal): Promise<void> {
    const response = await fetch(STREAM_URL, {
      headers: await authHeaders(),
      signal,
      cache: 'no-store',
    })

    if (!response.ok) throw new Error(await describeHttpFailure(response))
    if (!response.body) throw new Error('this browser returned no body for the event stream')

    connection.value = 'open'
    attempt.value = 0
    lastError.value = null
    markAlive()

    const reader = response.body.getReader()
    const decoder = new TextDecoder()

    for (;;) {
      const { value, done } = await reader.read()
      if (done) {
        // A clean close is the core shutting down. Treated as a failure so the
        // loop reconnects to the replacement process.
        throw new Error('the server closed the event stream')
      }
      markAlive()
      feed(decoder.decode(value, { stream: true }))
    }
  }

  async function supervise() {
    while (!stopping) {
      controller = new AbortController()
      connection.value = attempt.value === 0 ? 'connecting' : 'reconnecting'
      parser.reset()

      try {
        await readStream(controller.signal)
      } catch (err) {
        if (stopping) break
        // A watchdog-forced abort has already set a truthful message; the
        // AbortError that follows would replace it with jargon.
        if (!stale.value) lastError.value = describeFailure(err)
      }

      if (stopping) break

      connection.value = 'reconnecting'
      attempt.value += 1
      await sleep(backoffMs(attempt.value))
    }

    running = false
    connection.value = 'idle'
  }

  function backoffMs(n: number): number {
    const exponential = Math.min(retryBaseMs * 2 ** (n - 1), MAX_RETRY_MS)
    // Jitter, so a floor of wall displays does not reconnect in lockstep and
    // stampede the core the instant it comes back up.
    return Math.round(exponential * (0.8 + Math.random() * 0.4))
  }

  function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = window.setTimeout(() => {
        wake = null
        resolve()
      }, ms)
      wake = () => {
        window.clearTimeout(timer)
        wake = null
        resolve()
      }
    })
  }

  /**
   * The watchdog.
   *
   * A dropped link does not always surface as a fetch error: a half-open TCP
   * connection can sit there for minutes with the browser none the wiser. Data
   * age is the only signal that cannot be faked by a socket that merely has not
   * noticed yet, so age is what the status is judged on.
   */
  function startWatchdog() {
    if (watchdog !== null) return
    watchdog = window.setInterval(() => {
      if (stopping) return
      const last = lastContactAt.value
      if (!last) return
      if (Date.now() - last.getTime() < STALE_AFTER_MS) return

      if (!stale.value) {
        stale.value = true
        lastError.value = 'no data has arrived from the server for over 30 seconds'
      }
      // Age has proven the connection dead even though fetch has not returned.
      // Drop it so the reconnect loop takes over.
      if (connection.value === 'open') controller?.abort()
    }, WATCHDOG_INTERVAL_MS)
  }

  function onNetworkOnline() {
    if (!running) return
    reconnectNow()
  }

  function onNetworkOffline() {
    if (!running) return
    // The browser knows before any timeout does. Say so immediately rather than
    // showing a confident green for another half minute.
    stale.value = true
    lastError.value = 'this device is offline'
    controller?.abort()
  }

  function connect() {
    if (running) return
    running = true
    stopping = false
    attempt.value = 0
    lastError.value = null
    window.addEventListener('online', onNetworkOnline)
    window.addEventListener('offline', onNetworkOffline)
    startWatchdog()
    void supervise()
  }

  function disconnect() {
    stopping = true
    running = false
    window.removeEventListener('online', onNetworkOnline)
    window.removeEventListener('offline', onNetworkOffline)
    if (watchdog !== null) {
      window.clearInterval(watchdog)
      watchdog = null
    }
    wake?.()
    controller?.abort()
    controller = null
    connection.value = 'idle'
  }

  function reconnectNow() {
    if (!running) {
      connect()
      return
    }
    attempt.value = 0
    lastError.value = null
    if (wake) {
      wake() // Cut a pending backoff short.
    } else {
      controller?.abort() // Drop the current attempt; supervise() retries.
    }
  }

  function register<T extends (...args: never[]) => void>(set: Set<T>, fn: T) {
    set.add(fn)
    return () => {
      set.delete(fn)
    }
  }

  return {
    status,
    isStale: computed(() => stale.value),
    lastEventAt: readonly(lastEventAt) as Readonly<Ref<Date | null>>,
    lastContactAt: readonly(lastContactAt) as Readonly<Ref<Date | null>>,
    attempt: readonly(attempt),
    lastError: readonly(lastError),
    connect,
    disconnect,
    reconnectNow,
    onSnapshot: (fn) => register(snapshotHandlers, fn),
    onEvent: (fn) => register(eventHandlers, fn),
    onResync: (fn) => register(resyncHandlers, fn),
  }
}

/** Turns a failed response into something an operator can act on. */
async function describeHttpFailure(response: Response): Promise<string> {
  const body = await response.text().catch(() => '')
  let detail = ''
  try {
    detail = (JSON.parse(body) as { error?: string }).error ?? ''
  } catch {
    detail = ''
  }

  switch (response.status) {
    case 401:
      return detail || 'the event stream rejected this session; sign in again'
    case 403:
      return detail || 'this session is not permitted to watch the event stream'
    default:
      return detail || `the event stream returned ${response.status} ${response.statusText}`
  }
}

function describeFailure(err: unknown): string {
  if (err instanceof DOMException && err.name === 'AbortError') {
    return 'the connection to the server was dropped'
  }
  if (err instanceof TypeError) {
    // What fetch reports for DNS failures, refused connections, and a core that
    // is not running — the common case during a restart.
    return 'cannot reach the server'
  }
  return err instanceof Error ? err.message : String(err)
}

// One connection per tab, shared by every consumer.
//
// Each view opening its own stream would multiply snapshots and connections by
// the number of panels on screen, and leave them disagreeing about whether the
// link is up.
let shared: EventStream | null = null

export function useEventStream(): EventStream {
  if (!shared) shared = createEventStream()
  return shared
}
