/**
 * Checks the kiosk display-token client.
 *
 * Run: node scripts/check-display-token.mjs   (or `make test-frontend`)
 *
 * Same no-dependency approach as the other checks here: Node strips TypeScript
 * types natively from v22.18, so the module is imported directly.
 *
 * Two of these are security properties rather than conveniences:
 *
 *  - **A real session always wins.** The core ignores a display token whenever
 *    an Authorization header is present. If this client sent both, an operator
 *    who opened a display URL could not tell which identity their requests were
 *    being attributed to — and the audit log would be the thing that decided.
 *  - **Only a well-formed token is stored.** A truncated or mangled launch URL
 *    should fail where it is pasted, not an hour later as an anonymous 401 on a
 *    screen nobody is standing in front of.
 *
 * The remaining checks pin the storage choice, which is deliberate and easy to
 * "tidy" into localStorage: session storage means a colleague who opens a
 * display link once does not leave an API credential on their disk.
 */

// Minimal browser surface, installed before the module under test is imported.
const store = new Map()
globalThis.window = {
  sessionStorage: {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, v),
    removeItem: (k) => store.delete(k),
  },
}

const {
  captureDisplayToken,
  clearDisplayToken,
  displayToken,
  displayTokenHeaders,
  hasDisplayToken,
  DISPLAY_TOKEN_PARAM,
} = await import('../src/lib/displayToken.ts')

let failures = 0

function check(name, actual, expected) {
  const a = JSON.stringify(actual)
  const e = JSON.stringify(expected)
  if (a === e) {
    console.log(`  ok   ${name}`)
  } else {
    failures++
    console.log(`  FAIL ${name}\n         want ${e}\n         got  ${a}`)
  }
}

const VALID = 'cpd_' + 'A'.repeat(43)

// The parameter name has to match core/server/middleware/display_token.go, or an
// operator pastes a URL the client silently ignores.
check('the query parameter matches the server', DISPLAY_TOKEN_PARAM, 'display_token')

// Capture and read back.
{
  clearDisplayToken()
  check('nothing is held to begin with', hasDisplayToken(), false)
  check('a well-formed token is accepted', captureDisplayToken(VALID), true)
  check('and read back intact', displayToken(), VALID)
  check('surrounding whitespace is tolerated', captureDisplayToken(`  ${VALID}  `), true)
  check('and stripped', displayToken(), VALID)
}

// Rejection. Each of these is a plausible way a launch URL gets mangled.
{
  for (const [label, value] of [
    ['an empty value', ''],
    ['a null value', null],
    ['an undefined value', undefined],
    ['a token missing its prefix', 'A'.repeat(43)],
    ['a bearer token pasted by mistake', 'eyJhbGciOiJIUzI1NiJ9.abc.def'],
    ['the placeholder from the docs', 'cpd_…'.slice(0, 4) + '…'],
  ]) {
    clearDisplayToken()
    captureDisplayToken(VALID)
    check(`${label} is refused`, captureDisplayToken(value), false)
    // A refused value must also leave the previously good token alone, or a
    // stray navigation would log a working screen out.
    check(`${label} leaves the held token intact`, displayToken(), VALID)
  }
}

// The precedence rule. This is the one that must not drift.
{
  clearDisplayToken()
  captureDisplayToken(VALID)
  check('an unauthenticated request carries the token', displayTokenHeaders(false), {
    'X-Display-Token': VALID,
  })
  check('a signed-in request carries nothing', displayTokenHeaders(true), {})
}

// No token held: neither kind of request may invent one.
{
  clearDisplayToken()
  check('no token, unauthenticated', displayTokenHeaders(false), {})
  check('no token, signed in', displayTokenHeaders(true), {})
  check('and none is reported', hasDisplayToken(), false)
}

// Clearing has to reach storage, not just the in-memory copy, or signing out
// leaves the credential behind for the next navigation to pick up.
{
  clearDisplayToken()
  captureDisplayToken(VALID)
  clearDisplayToken()
  check('clearing empties the backing store', store.size, 0)
  check('and nothing is recovered from it', displayToken(), null)
}

// Storage is chosen, not incidental.
{
  clearDisplayToken()
  captureDisplayToken(VALID)
  check('the token lives in session storage', store.get('certpilot.display_token'), VALID)
  check('and localStorage is never touched', 'localStorage' in globalThis.window, false)
}

// A browser that blocks storage — private modes, some kiosk shells — must not
// drop the credential on the first read.
{
  clearDisplayToken()
  const blocked = {
    getItem() { throw new Error('storage disabled') },
    setItem() { throw new Error('storage disabled') },
    removeItem() { throw new Error('storage disabled') },
  }
  const real = globalThis.window.sessionStorage
  globalThis.window.sessionStorage = blocked
  check('capture survives storage being blocked', captureDisplayToken(VALID), true)
  check('and the token is still usable in this tab', displayToken(), VALID)
  globalThis.window.sessionStorage = real
  clearDisplayToken()
}

console.log(
  failures === 0 ? '\nDisplay token: all checks passed' : `\nDisplay token: ${failures} failure(s)`,
)
process.exit(failures === 0 ? 0 : 1)
