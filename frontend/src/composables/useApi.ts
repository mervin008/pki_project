import { supabase } from '@/lib/supabase'
import { displayTokenHeaders } from '@/lib/displayToken'

export function useApi() {
  async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    }

    // Attach the access token when signed in. With no Supabase project
    // configured, requests go out unauthenticated — which the core accepts only
    // in development mode on a loopback address, and rejects otherwise.
    if (supabase) {
      const {
        data: { session },
      } = await supabase.auth.getSession()
      if (session?.access_token) {
        headers['Authorization'] = `Bearer ${session.access_token}`
      }
    }

    // A wall display has no session. It authenticates with a kiosk token, which
    // must reach every REST call and not only the event stream — a screen whose
    // feed connects while each panel returns 401 is the worst of both.
    Object.assign(headers, displayTokenHeaders(headers['Authorization'] !== undefined))

    const response = await fetch(endpoint, {
      ...options,
      headers,
    })

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
