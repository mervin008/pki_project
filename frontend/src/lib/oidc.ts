/**
 * OpenID Connect, authorization code with PKCE.
 *
 * Written rather than pulled in because the flow is small, and because the two
 * places it is easy to get wrong — verifying `state`, and never putting a token
 * where a stale one can outlive a sign-out — are easier to keep right in code
 * that is read than in configuration for a library that is not.
 *
 * There is no client secret. A single-page application cannot keep one, which
 * is the whole reason PKCE exists: the code verifier is generated per attempt,
 * never leaves this origin, and is what proves the code being redeemed belongs
 * to the browser that asked for it.
 *
 * ── This module holds no tokens ─────────────────────────────────────────────
 *
 * It used to. The browser redeemed the authorization code itself, kept the
 * access token in memory, and kept the refresh token in localStorage — because
 * surviving a page reload requires *something* persistent and every storage a
 * page can reach is readable by script on this origin. That was a documented
 * trade-off rather than an oversight, and it is now gone.
 *
 * The code is posted to `POST /api/v1/auth/callback` and the core redeems it.
 * What comes back is the same httpOnly session cookie a local password sign-in
 * gets. So this file builds an authorization URL, checks `state`, and hands the
 * result to the core; it never sees an access token, a refresh token, or an ID
 * token. There is nothing here for a cross-site scripting flaw to steal that it
 * could not already do by calling the API directly.
 *
 * The nonce is generated here and sent to the core alongside the code, because
 * the core is the half that must check it. A browser verifying its own nonce
 * proves nothing.
 */

export interface AuthConfig {
  // 'password' when only local accounts are configured, 'oidc' when single
  // sign-on is offered as well. There is no anonymous mode.
  mode: 'oidc' | 'password'
  password_login?: boolean
  issuer?: string
  client_id?: string
  scopes?: string[]
  audience?: string
}

interface ProviderMetadata {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
}

const PENDING_KEY = 'certpilot.auth_pending'
const RETURN_KEY = 'certpilot.return_to'

/**
 * The key an older build kept a refresh token under.
 *
 * Removed on load rather than merely stopped being written. An upgrade
 * otherwise leaves a live refresh token sitting in localStorage indefinitely,
 * belonging to a flow nothing uses any more — the exact object this change
 * exists to get rid of, preserved by the change that removed it.
 */
const LEGACY_REFRESH_KEY = 'certpilot.refresh_token'

/** Marks that a sign-in has completed in this browser. Carries no credential. */
const SIGNED_IN_KEY = 'certpilot.signed_in'
try {
  localStorage.removeItem(LEGACY_REFRESH_KEY)
} catch {
  // Storage can be unavailable — a private window, or a browser configured to
  // block it. Nothing here depends on the removal succeeding.
}

// ── Small crypto helpers ────────────────────────────────────────────────────

function randomString(bytes = 32): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return base64url(buf)
}

function base64url(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

// ── Discovery ───────────────────────────────────────────────────────────────

let cachedConfig: AuthConfig | null = null
let cachedMetadata: ProviderMetadata | null = null

/**
 * Reads how this instance authenticates, from the core rather than from the
 * build.
 *
 * A frontend carrying its own copy of the issuer can disagree with the API it
 * talks to, and that disagreement presents as a login that appears to succeed
 * followed by 401 on every request — which reads as a broken server rather
 * than a mismatched setting.
 */
export async function loadAuthConfig(): Promise<AuthConfig> {
  if (cachedConfig) return cachedConfig
  const response = await fetch('/api/v1/auth/config')
  if (!response.ok) {
    throw new Error(
      `CertPilot could not be asked how to sign in (HTTP ${response.status}). ` +
        'The API may be unreachable.',
    )
  }
  cachedConfig = (await response.json()) as AuthConfig
  return cachedConfig
}

async function providerMetadata(issuer: string): Promise<ProviderMetadata> {
  if (cachedMetadata) return cachedMetadata
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(
      `The identity provider at ${issuer} did not return its OpenID configuration ` +
        `(HTTP ${response.status}). Check auth.issuer in the core's configuration.`,
    )
  }
  cachedMetadata = (await response.json()) as ProviderMetadata
  return cachedMetadata
}

function redirectUri(): string {
  return `${window.location.origin}/auth/callback`
}

// ── Sign-in ─────────────────────────────────────────────────────────────────

/** Sends the browser to the identity provider. Does not return. */
export async function beginSignIn(returnTo?: string): Promise<void> {
  const config = await loadAuthConfig()
  if (config.mode !== 'oidc' || !config.issuer || !config.client_id) {
    throw new Error('This CertPilot instance is not configured for single sign-on.')
  }

  const metadata = await providerMetadata(config.issuer)
  const verifier = randomString()
  const state = randomString(16)
  const nonce = randomString(16)

  // sessionStorage, not localStorage: this is per-attempt and per-tab, and a
  // verifier surviving in another tab is a verifier that can be replayed.
  sessionStorage.setItem(PENDING_KEY, JSON.stringify({ verifier, state, nonce }))
  if (returnTo) sessionStorage.setItem(RETURN_KEY, returnTo)

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.client_id,
    redirect_uri: redirectUri(),
    scope: (config.scopes ?? ['openid', 'profile', 'email']).join(' '),
    state,
    nonce,
    code_challenge: await challengeFor(verifier),
    code_challenge_method: 'S256',
  })
  if (config.audience) params.set('audience', config.audience)

  window.location.assign(`${metadata.authorization_endpoint}?${params.toString()}`)
}

/**
 * Completes the flow after the provider redirects back.
 *
 * Returns where the user was trying to go, so the caller can put them back
 * there rather than always landing them on the dashboard.
 */
export async function completeSignIn(search: string): Promise<string> {
  const params = new URLSearchParams(search)

  const error = params.get('error')
  if (error) {
    throw new Error(
      `${params.get('error_description') ?? error}. ` +
        'This came from the identity provider, not from CertPilot.',
    )
  }

  const code = params.get('code')
  const returnedState = params.get('state')
  const pendingRaw = sessionStorage.getItem(PENDING_KEY)
  sessionStorage.removeItem(PENDING_KEY)

  if (!code || !pendingRaw) {
    throw new Error('This sign-in did not start here. Begin again from the login page.')
  }

  const pending = JSON.parse(pendingRaw) as { verifier: string; state: string; nonce: string }

  // The check that makes the redirect safe. Without it, an attacker can hand
  // somebody a callback URL carrying their own authorization code and have the
  // victim's browser sign in as the attacker — the session then looks entirely
  // legitimate to the person using it.
  if (returnedState !== pending.state) {
    throw new Error(
      'The sign-in response did not match the request that started it, so it was refused.',
    )
  }

  // The core redeems the code, not this page. What comes back is an httpOnly
  // session cookie — the same one a local password sign-in gets — so nothing
  // token-shaped ever reaches this origin's storage or this module's memory.
  //
  // The nonce goes with it. It was generated here, and the core is the half
  // that checks the ID token carries the same one; a browser verifying its own
  // nonce proves nothing.
  const response = await fetch('/api/v1/auth/callback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({
      code,
      code_verifier: pending.verifier,
      redirect_uri: redirectUri(),
      nonce: pending.nonce,
    }),
  })

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { error?: string }
    throw new Error(
      body.error ??
        `This sign-in could not be completed (HTTP ${response.status}). ` +
          'The most common cause is a redirect URI that is not registered for this client.',
    )
  }

  rememberSignIn()

  const returnTo = sessionStorage.getItem(RETURN_KEY) ?? '/'
  sessionStorage.removeItem(RETURN_KEY)
  return returnTo
}

// ── Keeping the session alive ───────────────────────────────────────────────

/**
 * Whether a previous session might still be usable without interaction.
 *
 * The session cookie is httpOnly, so this page cannot see it. The honest answer
 * is therefore "ask the API", which the auth store does on start-up — and the
 * only thing this can report is whether this browser has ever completed a
 * sign-in here.
 *
 * It exists to keep one message truthful. "Your session ended" shown to a
 * first-time visitor who has simply arrived at the URL is wrong and alarming;
 * the same message after a session really has expired is exactly right.
 */
export function hasResumableSession(): boolean {
  try {
    return localStorage.getItem(SIGNED_IN_KEY) === '1'
  } catch {
    return false
  }
}

/** Records that a sign-in has completed here, for hasResumableSession. */
export function rememberSignIn(): void {
  try {
    localStorage.setItem(SIGNED_IN_KEY, '1')
  } catch {
    // Not worth failing a sign-in over.
  }
}

/**
 * Forgets local sign-in state.
 *
 * There are no tokens left to clear — the session lives in an httpOnly cookie
 * the core sets and clears. This drops only the marker above, so that the next
 * visit is treated as a first one rather than as an expired session.
 */
export function clearTokens(): void {
  try {
    localStorage.removeItem(SIGNED_IN_KEY)
    localStorage.removeItem(LEGACY_REFRESH_KEY)
  } catch {
    // As above.
  }
}

/**
 * Ends the session here, and at the provider when it supports it.
 *
 * Clearing only the local tokens leaves the provider's own session cookie
 * intact, so the next sign-in completes silently and looks to the operator as
 * though signing out did nothing.
 */
export async function signOut(): Promise<void> {
  clearTokens()
  try {
    const config = await loadAuthConfig()
    if (config.mode !== 'oidc' || !config.issuer) return
    const metadata = await providerMetadata(config.issuer)
    if (!metadata.end_session_endpoint) return

    const params = new URLSearchParams({
      client_id: config.client_id!,
      post_logout_redirect_uri: `${window.location.origin}/login`,
    })
    window.location.assign(`${metadata.end_session_endpoint}?${params.toString()}`)
  } catch {
    // Signing out must never fail in a way that leaves somebody signed in.
    window.location.assign('/login')
  }
}
