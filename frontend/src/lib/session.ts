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
  // A wall display authenticates with a kiosk token and has no session to
  // renew. Sending it to a sign-in page would replace the loud, honest failure
  // the display is designed to show with a screen nobody is standing at.
  if (hasDisplayToken()) return

  if (redirecting) return
  redirecting = true

  const auth = useAuthStore()

  // Anonymous development returns 401 for other reasons entirely, and there is
  // no sign-in to send anybody to.
  if (auth.mode !== 'oidc') {
    redirecting = false
    return
  }

  auth.forgetSession()

  const current = router.currentRoute.value
  if (current.name === 'login') {
    redirecting = false
    return
  }

  void router
    .replace({ name: 'login', query: { next: current.fullPath, reason: 'expired' } })
    .finally(() => {
      redirecting = false
    })
}
