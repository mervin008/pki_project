import { router } from '@/router'
import { useAuthStore } from '@/stores/auth'
import { hasDisplayToken } from '@/lib/displayToken'

/**
 * Handles the API rejecting our credential.
 *
 * Centralised because a dashboard makes many requests at once: an expired
 * session produces a burst of 401s, and each panel deciding independently to
 * redirect would race the others and bounce the operator through the sign-in
 * flow more than once.
 */

let redirecting = false

export function onUnauthorized(): void {
  const current = router.currentRoute.value

  // Keyed on the route, not on whether a display token happens to be present.
  //
  // A wall screen with no token configured yet is exactly the case that must
  // not redirect: it has nobody standing at it to sign in, and the whole design
  // of that page is to fail loudly and visibly rather than to navigate
  // somewhere quieter. Checking for the token instead of the route sent a
  // brand-new display to a login form it could never complete.
  if (current.meta.public) return
  if (hasDisplayToken()) return

  if (redirecting) return
  redirecting = true

  const auth = useAuthStore()

  // Every mode has a sign-in to send somebody to now. There is no longer a
  // configuration in which a 401 is expected and unactionable.
  auth.forgetSession()

  void router
    .replace({ name: 'login', query: { next: current.fullPath, reason: 'expired' } })
    .finally(() => {
      redirecting = false
    })
}
