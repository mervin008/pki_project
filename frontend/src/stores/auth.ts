import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import {
  loadAuthConfig,
  currentAccessToken,
  hasResumableSession,
  beginSignIn,
  signOut as oidcSignOut,
  clearTokens,
  type AuthConfig,
} from '@/lib/oidc'

/** RBAC roles, matching the backend. */
export type Role = 'admin' | 'operator' | 'auditor' | 'viewer'

const WRITE_ROLES: Role[] = ['admin', 'operator']

/** What GET /api/v1/me returns. */
interface Me {
  subject: string
  email?: string
  display_name?: string
  role: Role
  auth_method: string
  user_id?: string
  role_source?: string
}

export const useAuthStore = defineStore('auth', () => {
  const config = ref<AuthConfig | null>(null)
  const me = ref<Me | null>(null)

  // Least privilege until the API says otherwise. Showing an unauthenticated
  // visitor admin controls invites actions the API will reject, and mirrors the
  // backend rule that an unrecognised role falls back to viewer.
  const role = ref<Role>('viewer')
  const loading = ref(true)
  const error = ref<string | null>(null)

  const mode = computed(() => config.value?.mode ?? 'unconfigured')
  /** True when this instance expects people to sign in at all. */
  const isAuthEnabled = computed(() => mode.value === 'oidc')
  const isAuthenticated = ref(false)

  const canWrite = computed(() => WRITE_ROLES.includes(role.value))
  const isAdmin = computed(() => role.value === 'admin')

  const displayName = computed(
    () => me.value?.display_name || me.value?.email || me.value?.subject || 'Unknown',
  )

  /**
   * Asks the API who the caller is.
   *
   * The role is read from here and never decoded out of the token. The role
   * that governs a request is the one in CertPilot's users table, so a UI that
   * trusted the token's own claim would keep offering controls for a role the
   * API had stopped honouring the moment somebody was demoted.
   */
  async function loadMe(): Promise<boolean> {
    const headers: Record<string, string> = {}
    const token = await currentAccessToken()
    if (token) headers.Authorization = `Bearer ${token}`

    const response = await fetch('/api/v1/me', { headers })
    if (!response.ok) {
      me.value = null
      role.value = 'viewer'
      isAuthenticated.value = false
      return false
    }

    me.value = (await response.json()) as Me
    role.value = me.value.role
    isAuthenticated.value = true
    return true
  }

  async function init(): Promise<void> {
    loading.value = true
    error.value = null
    try {
      config.value = await loadAuthConfig()

      // Anonymous development: the core treats every request as admin, so
      // there is nobody to sign in and no login screen to show.
      if (config.value.mode === 'anonymous') {
        await loadMe()
        return
      }

      // Only attempt to resume when there is something to resume from.
      // Calling /me without a credential would be a guaranteed 401 on every
      // page load, which fills the console and looks like a fault.
      if (hasResumableSession()) {
        await loadMe()
      } else {
        isAuthenticated.value = false
      }
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err)
      isAuthenticated.value = false
    } finally {
      loading.value = false
    }
  }

  async function signIn(returnTo?: string): Promise<void> {
    await beginSignIn(returnTo)
  }

  async function signOut(): Promise<void> {
    me.value = null
    role.value = 'viewer'
    isAuthenticated.value = false
    await oidcSignOut()
  }

  /**
   * Drops local credentials without contacting the provider.
   *
   * Used when the API rejects a token: the session is already over, and
   * redirecting through the provider's logout at that point would lose
   * whatever the operator was looking at for no benefit.
   */
  function forgetSession(): void {
    clearTokens()
    me.value = null
    role.value = 'viewer'
    isAuthenticated.value = false
  }

  return {
    config,
    me,
    role,
    loading,
    error,
    mode,
    isAuthEnabled,
    isAuthenticated,
    canWrite,
    isAdmin,
    displayName,
    init,
    loadMe,
    signIn,
    signOut,
    forgetSession,
  }
})
