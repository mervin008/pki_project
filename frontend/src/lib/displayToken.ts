/**
 * The kiosk credential a wall display authenticates with.
 *
 * A screen in a corridor has no keyboard and nobody to sign in at it, so it is
 * launched at a URL carrying a display token:
 *
 *     https://certpilot.example.com/display?display_token=cpd_…
 *
 * The token is minted by an admin, grants `viewer` and nothing else, is refused
 * on every non-GET route and on the sensitive reads, and is revocable
 * (core/server/middleware/display_token.go). Those guarantees are enforced by
 * the server; this module is only responsible for carrying it correctly.
 *
 * ## Why sessionStorage, and why the URL is rewritten
 *
 * Held in `sessionStorage`, not `localStorage`: a kiosk keeps one tab open for
 * months, so it survives everything that matters, while a colleague who opens a
 * display link once on their laptop does not leave an API credential on disk
 * afterwards.
 *
 * The router strips the parameter from the address bar as soon as it is read.
 * A query string is the weakest place to put a secret — it reaches browser
 * history, `Referer` headers, and any screenshot of the window — and the kiosk
 * is relaunched from its configured URL anyway, so nothing is lost by removing
 * it from the visible one.
 *
 * The token is sent as the `X-Display-Token` header rather than the query
 * parameter the server also accepts. That parameter exists for `EventSource`,
 * which cannot set headers; this frontend streams over `fetch`, so it can use
 * the channel that stays out of access logs.
 */

const STORAGE_KEY = 'certpilot.display_token'

/**
 * The shape the server mints: the `cpd_` prefix followed by base64url entropy
 * (core/server/middleware/display_token.go).
 *
 * The length is a floor rather than the exact 43 characters the server currently
 * produces, so raising the entropy there does not silently lock every screen
 * out here. It is still tight enough to reject what actually goes wrong — a URL
 * truncated by a chat client, or the literal `cpd_…` placeholder copied out of
 * the documentation, both of which pass a prefix-only test.
 */
const TOKEN_PATTERN = /^cpd_[A-Za-z0-9_-]{20,}$/

/** Mirrors the server's key name, so an operator pastes one URL, not two. */
export const DISPLAY_TOKEN_PARAM = 'display_token'

// Held in memory as well, so the app keeps working in a browser where storage
// is unavailable — private modes and some kiosk shells block it — rather than
// dropping the credential on the first read.
let inMemory: string | null = null

/** Records a token seen in the URL. Returns true when one was accepted. */
export function captureDisplayToken(raw: string | null | undefined): boolean {
  const token = (raw ?? '').trim()
  // Checked here so a truncated or mangled URL fails visibly at the point it is
  // pasted, rather than as an anonymous 401 on the stream an hour later. A
  // rejected value also leaves any token already held untouched, so a stray
  // navigation cannot log a working screen out.
  if (!TOKEN_PATTERN.test(token)) return false

  inMemory = token
  try {
    window.sessionStorage.setItem(STORAGE_KEY, token)
  } catch {
    // Storage unavailable. The in-memory copy still serves this tab.
  }
  return true
}

export function displayToken(): string | null {
  if (inMemory) return inMemory
  try {
    inMemory = window.sessionStorage.getItem(STORAGE_KEY)
  } catch {
    inMemory = null
  }
  return inMemory
}

export function hasDisplayToken(): boolean {
  return displayToken() !== null
}

/** Forgets the credential — used when signing in as a real operator. */
export function clearDisplayToken(): void {
  inMemory = null
  try {
    window.sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    // Nothing to clear.
  }
}

/**
 * The header to attach, or nothing.
 *
 * `authenticated` says whether a real session is already carrying this request.
 * The server ignores a display token whenever an `Authorization` header is
 * present, so this mirrors that precedence rather than sending both and relying
 * on the server to pick — an operator signed in on a display URL should be
 * acting as themselves, and appear as themselves in the audit log.
 */
export function displayTokenHeaders(authenticated: boolean): Record<string, string> {
  if (authenticated) return {}
  const token = displayToken()
  return token ? { 'X-Display-Token': token } : {}
}
