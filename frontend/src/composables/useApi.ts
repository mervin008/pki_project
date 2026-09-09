import { displayTokenHeaders } from '@/lib/displayToken'
import { onUnauthorized } from '@/lib/session'

export function useApi() {
  async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    }

    // A wall display has no session. It authenticates with a kiosk token, which
    // must reach every REST call and not only the event stream — a screen whose
    // feed connects while each panel returns 401 is the worst of both.
    Object.assign(headers, displayTokenHeaders(false))

    const response = await fetch(endpoint, {
      ...options,
      // The credential is the session cookie, which is httpOnly and therefore
      // invisible to this code. Stated explicitly rather than left to the
      // same-origin default: this line is the whole authentication story for a
      // person using the console, and it should be visible as such. A federated
      // sign-in gets the same cookie — the browser stopped handling bearer
      // tokens when the core took over redeeming the authorization code.
      credentials: 'same-origin',
      headers,
    })

    // A 401 once the token has already been refreshed means the session is
    // genuinely over — revoked, or the refresh token spent. Handled centrally
    // so that every panel does not have to recognise it, and so the operator is
    // told rather than left reading a screen of failed requests as an outage.
    if (response.status === 401) {
      onUnauthorized()
    }

    if (!response.ok) {
      // The API returns {"error": "..."}; prefer that message, since it is
      // written for the operator, over a bare status code.
      const errorData = await response.json().catch(() => ({ error: response.statusText }))
      throw new Error(errorData.error || `Request failed with status ${response.status}`)
    }

    // 204 No Content has no body to parse.
    if (response.status === 204) {
      return undefined as T
    }

    return response.json()
  }

  // Every verb accepts an AbortSignal so useAsyncData can cancel a request that
  // has been superseded — otherwise a slow earlier response can land after a
  // newer one and roll the view back to stale data.
  return {
    get: <T>(url: string, signal?: AbortSignal) => request<T>(url, { method: 'GET', signal }),
    post: <T>(url: string, body?: any, signal?: AbortSignal) =>
      request<T>(url, { method: 'POST', body: body ? JSON.stringify(body) : undefined, signal }),
    put: <T>(url: string, body?: any, signal?: AbortSignal) =>
      request<T>(url, { method: 'PUT', body: body ? JSON.stringify(body) : undefined, signal }),
    patch: <T>(url: string, body?: any, signal?: AbortSignal) =>
      request<T>(url, { method: 'PATCH', body: body ? JSON.stringify(body) : undefined, signal }),
    delete: <T>(url: string, signal?: AbortSignal) => request<T>(url, { method: 'DELETE', signal }),
  }
}
