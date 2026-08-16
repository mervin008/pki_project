import { ref, shallowRef, onMounted, onUnmounted, type Ref } from 'vue'

/**
 * Reactive wrapper around an async fetch.
 *
 * Every view previously hand-rolled `const loading = ref(true)` and appended
 * `.catch(() => ({ data: [] }))` to each request. That pattern turns a failed
 * fetch into an empty result, so a backend outage renders as "no certificates,
 * no problems" — the single worst failure mode for a monitoring tool. Here an
 * error is a first-class state that the caller must render.
 *
 * `lastLoadedAt` exists so a view can show how stale its data is. That becomes
 * load-bearing once live updates land: a screen left on a wall has to be able
 * to say "I stopped receiving updates at 14:02" rather than silently showing
 * yesterday's green.
 */
export interface AsyncData<T> {
  data: Ref<T | null>
  error: Ref<string | null>
  loading: Ref<boolean>
  /** When the last successful load completed. Null until the first success. */
  lastLoadedAt: Ref<Date | null>
  /** True once a load has succeeded — distinguishes "empty" from "not yet loaded". */
  loaded: Ref<boolean>
  refresh: () => Promise<void>
}

export interface AsyncDataOptions {
  /** Fetch on mount. Default true. */
  immediate?: boolean
}

export function useAsyncData<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  options: AsyncDataOptions = {},
): AsyncData<T> {
  const { immediate = true } = options

  const data = shallowRef<T | null>(null) as Ref<T | null>
  const error = ref<string | null>(null)
  const loading = ref(false)
  const loaded = ref(false)
  const lastLoadedAt = ref<Date | null>(null)

  let controller: AbortController | null = null
  let disposed = false

  async function refresh() {
    // Cancel any in-flight request so a slow earlier response cannot land after
    // a newer one and roll the view back to stale data.
    controller?.abort()
    controller = new AbortController()
    const signal = controller.signal

    loading.value = true
    try {
      const result = await fetcher(signal)
      if (signal.aborted || disposed) return
      data.value = result
      error.value = null
      loaded.value = true
      lastLoadedAt.value = new Date()
    } catch (err) {
      if (signal.aborted || disposed) return
      // Preserve whatever was last loaded. A transient failure should show a
      // warning over the previous data, not blank the screen.
      error.value = err instanceof Error ? err.message : String(err)
    } finally {
      if (!signal.aborted && !disposed) loading.value = false
    }
  }

  if (immediate) {
    onMounted(refresh)
  }

  onUnmounted(() => {
    disposed = true
    controller?.abort()
  })

  return { data, error, loading, loaded, lastLoadedAt, refresh }
}

/**
 * Runs several fetches together and reports one combined state.
 *
 * A dashboard drawing from four endpoints needs a single "is anything broken"
 * signal; failing partially and silently is how a panel ends up showing stale
 * numbers next to fresh ones with nothing to distinguish them.
 */
export function useAsyncGroup(
  fetchers: Array<() => Promise<unknown>>,
  options: AsyncDataOptions = {},
): Omit<AsyncData<never>, 'data'> {
  const { immediate = true } = options

  const error = ref<string | null>(null)
  const loading = ref(false)
  const loaded = ref(false)
  const lastLoadedAt = ref<Date | null>(null)
  let disposed = false

  async function refresh() {
    loading.value = true
    try {
      const results = await Promise.allSettled(fetchers.map((f) => f()))
      if (disposed) return

      const failures = results.filter(
        (r): r is PromiseRejectedResult => r.status === 'rejected',
      )
      if (failures.length > 0) {
        const first = failures[0].reason
        const message = first instanceof Error ? first.message : String(first)
        error.value =
          failures.length === 1
            ? message
            : `${message} (and ${failures.length - 1} more request${failures.length > 2 ? 's' : ''} failed)`
      } else {
        error.value = null
        lastLoadedAt.value = new Date()
      }
      loaded.value = true
    } finally {
      if (!disposed) loading.value = false
    }
  }

  if (immediate) {
    onMounted(refresh)
  }

  onUnmounted(() => {
    disposed = true
  })

  return { error, loading, loaded, lastLoadedAt, refresh }
}
