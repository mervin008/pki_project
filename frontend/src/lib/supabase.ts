import { createClient } from '@supabase/supabase-js'

// Supabase is optional: CertPilot authenticates against any OIDC provider, and
// the core runs against plain PostgreSQL. This client is only constructed when
// a project is configured.
//
// No fallback values. A hardcoded project URL and key in an open-source
// repository points every clone at one person's project, and a missing
// configuration should be a clear error rather than a silent connection
// somewhere unexpected.
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey)

export const supabase = isSupabaseConfigured
  ? createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
      },
      realtime: {
        params: {
          eventsPerSecond: 10,
        },
      },
    })
  : null

/**
 * Returns the Supabase client, throwing if it was never configured.
 *
 * Use this at call sites that genuinely require Supabase, so the failure names
 * the missing environment variables instead of surfacing as a null dereference.
 */
export function requireSupabase() {
  if (!supabase) {
    throw new Error(
      'Supabase is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY, ' +
        'or use the core API with any OIDC provider instead.',
    )
  }
  return supabase
}
