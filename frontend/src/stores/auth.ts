import { defineStore } from 'pinia'
import { ref } from 'vue'
import { supabase } from '@/lib/supabase'
import type { User, Session } from '@supabase/supabase-js'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const session = ref<Session | null>(null)
  const role = ref<string>('admin') // Defaults to admin in dev
  const loading = ref<boolean>(true)

  async function init() {
    loading.value = true
    try {
      const { data } = await supabase.auth.getSession()
      session.value = data.session
      user.value = data.session?.user || null
      if (user.value) {
        role.value = (user.value.app_metadata?.certpilot_role as string) || 'admin'
      }

      supabase.auth.onAuthStateChange((_event, newSession) => {
        session.value = newSession
        user.value = newSession?.user || null
        if (user.value) {
          role.value = (user.value.app_metadata?.certpilot_role as string) || 'admin'
        }
      })
    } finally {
      loading.value = false
    }
  }

  async function signInWithOAuth(provider: 'google' | 'github' | 'azure' | 'gitlab') {
    return supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: window.location.origin,
      },
    })
  }

  async function signOut() {
    await supabase.auth.signOut()
    user.value = null
    session.value = null
    role.value = 'viewer'
  }

  return {
    user,
    session,
    role,
    loading,
    init,
    signInWithOAuth,
    signOut,
  }
})
