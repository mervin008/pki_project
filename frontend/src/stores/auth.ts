import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { supabase, isSupabaseConfigured } from '@/lib/supabase'
import type { User, Session } from '@supabase/supabase-js'

/** RBAC roles, matching the backend. */
export type Role = 'admin' | 'operator' | 'auditor' | 'viewer'

const WRITE_ROLES: Role[] = ['admin', 'operator']

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const session = ref<Session | null>(null)
  // Least privilege by default. Showing an unauthenticated visitor admin
  // controls invites actions the API will reject, and mirrors the backend rule
  // that an unrecognised role falls back to viewer.
  const role = ref<Role>('viewer')
  const loading = ref<boolean>(true)

  // When Supabase is not configured the core is presumably running with
  // anonymous access for local development, where every request is admin.
  const isAuthEnabled = computed(() => isSupabaseConfigured)

  const canWrite = computed(() => WRITE_ROLES.includes(role.value))
  const isAdmin = computed(() => role.value === 'admin')

  function readRole(u: User | null): Role {
    // Read only from app_metadata: user_metadata is writable by the user it
    // belongs to, so a role taken from there could be self-assigned.
    const claimed = u?.app_metadata?.certpilot_role
    switch (claimed) {
      case 'admin':
      case 'operator':
      case 'auditor':
      case 'viewer':
        return claimed
      default:
        return 'viewer'
    }
  }

  async function init() {
    loading.value = true
    try {
      if (!supabase) {
        // Local development against a core with anonymous access enabled.
        role.value = 'admin'
        return
      }

      const { data } = await supabase.auth.getSession()
      session.value = data.session
      user.value = data.session?.user ?? null
      role.value = readRole(user.value)

      supabase.auth.onAuthStateChange((_event, newSession) => {
        session.value = newSession
        user.value = newSession?.user ?? null
        role.value = readRole(user.value)
      })
    } finally {
      loading.value = false
    }
  }

  async function signInWithOAuth(provider: 'google' | 'github' | 'azure' | 'gitlab') {
    if (!supabase) {
      throw new Error('Sign-in is unavailable: Supabase is not configured.')
    }
    return supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: window.location.origin,
      },
    })
  }

  async function signOut() {
    if (supabase) {
      await supabase.auth.signOut()
    }
    user.value = null
    session.value = null
    role.value = 'viewer'
  }

  return {
    user,
    session,
    role,
    loading,
    isAuthEnabled,
    canWrite,
    isAdmin,
    init,
    signInWithOAuth,
    signOut,
  }
})
