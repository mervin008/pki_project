import { supabase } from '@/lib/supabase'

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

  return {
    get: <T>(url: string) => request<T>(url, { method: 'GET' }),
    post: <T>(url: string, body?: any) =>
      request<T>(url, { method: 'POST', body: body ? JSON.stringify(body) : undefined }),
    put: <T>(url: string, body?: any) =>
      request<T>(url, { method: 'PUT', body: body ? JSON.stringify(body) : undefined }),
    patch: <T>(url: string, body?: any) =>
      request<T>(url, { method: 'PATCH', body: body ? JSON.stringify(body) : undefined }),
    delete: <T>(url: string) => request<T>(url, { method: 'DELETE' }),
  }
}
