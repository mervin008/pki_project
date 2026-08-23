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
 * ── Where tokens live, and what that costs ──────────────────────────────────
 *
 * The access token is held in memory only. It dies with the tab, and no script
 * can read it out of storage after the fact.
 *
 * The refresh token is in localStorage, and that is a real trade-off rather
 * than an oversight. Surviving a page reload without sending the operator back
 * to their identity provider requires *something* persistent, and every option
 * available to a page with no backend of its own is readable by script running
 * on this origin. The honest mitigation is that a cross-site scripting flaw
 * here is already fatal — it could simply call the API — so the refresh token
 * raises the duration of a compromise rather than its severity.
 *
 * The durable fix is a backend-for-frontend holding the refresh token in an
 * httpOnly cookie. That is a deployment change, not a code change here, and it
 * is recorded as a known gap rather than pretended away.
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

interface TokenResponse {
  access_token: string
  refresh_token?: string
  expires_in?: number
  token_type?: string
}

const REFRESH_KEY = 'certpilot.refresh_token'
const PENDING_KEY = 'certpilot.auth_pending'
const RETURN_KEY = 'certpilot.return_to'

/** Held in memory deliberately — see the note at the top of this file. */
let accessToken: string | null = null
let accessTokenExpiry = 0
let inFlightRefresh: Promise<string | null> | null = null

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

  const pending = JSON.parse(pendingRaw) as { verifier: string; state: string }

  // The check that makes the redirect safe. Without it, an attacker can hand
  // somebody a callback URL carrying their own authorization code and have the
  // victim's browser sign in as the attacker — the session then looks entirely
  // legitimate to the person using it.
  if (returnedState !== pending.state) {
    throw new Error(
      'The sign-in response did not match the request that started it, so it was refused.',
    )
  }

  const config = await loadAuthConfig()
  const metadata = await providerMetadata(config.issuer!)

  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri(),
      client_id: config.client_id!,
      code_verifier: pending.verifier,
    }),
  })

  if (!response.ok) {
    throw new Error(
      `The identity provider refused to exchange the sign-in code (HTTP ${response.status}). ` +
        'The most common cause is a redirect URI that is not registered for this client.',
    )
  }

  storeTokens((await response.json()) as TokenResponse)

  const returnTo = sessionStorage.getItem(RETURN_KEY) ?? '/'
  sessionStorage.removeItem(RETURN_KEY)
  return returnTo
}

function storeTokens(tokens: TokenResponse): void {
  accessToken = tokens.access_token
  // Refreshed a minute early, so a request is never sent with a token that
  // expires while it is in flight.
  accessTokenExpiry = Date.now() + ((tokens.expires_in ?? 300) - 60) * 1000
  if (tokens.refresh_token) {
    localStorage.setItem(REFRESH_KEY, tokens.refresh_token)
  }
}

// ── Keeping the session alive ───────────────────────────────────────────────

/**
 * Returns a usable access token, refreshing if necessary, or null.
 *
 * Concurrent callers share one refresh. A dashboard opens several requests and
 * an event stream at once, and letting each redeem the same refresh token
 * would — with the rotation every serious provider now does — invalidate the
 * others and sign the user out at the moment the page loads.
 */
export async function currentAccessToken(): Promise<string | null> {
  if (accessToken && Date.now() < accessTokenExpiry) return accessToken
  if (inFlightRefresh) return inFlightRefresh

  inFlightRefresh = refresh().finally(() => {
    inFlightRefresh = null
  })
  return inFlightRefresh
}

async function refresh(): Promise<string | null> {
  const stored = localStorage.getItem(REFRESH_KEY)
  if (!stored) return null

  try {
    const config = await loadAuthConfig()
    if (config.mode !== 'oidc') return null
    const metadata = await providerMetadata(config.issuer!)

    const response = await fetch(metadata.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: stored,
        client_id: config.client_id!,
      }),
    })

    if (!response.ok) {
      // The refresh token is spent, revoked, or expired. Clearing it is what
      // turns this into a clean prompt to sign in again rather than a loop.
      clearTokens()
      return null
    }

    storeTokens((await response.json()) as TokenResponse)
    return accessToken
  } catch {
    // A network failure is not proof the session ended, so the refresh token
    // is kept and the next attempt can succeed.
    return null
  }
}

export function clearTokens(): void {
  accessToken = null
  accessTokenExpiry = 0
  localStorage.removeItem(REFRESH_KEY)
}

/** True when a previous session may still be resumable without interaction. */
export function hasResumableSession(): boolean {
  return Boolean(accessToken || localStorage.getItem(REFRESH_KEY))
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
