/**
 * API response types, mirroring core/store/models.go.
 *
 * The views previously typed every response as `any` and bound field names that
 * the backend never returns — `common_name` on a CA (it is `name`),
 * `key_algorithm` (`key_type`), `certs_issued` (`certificates_issued_count`),
 * `issuer` (`issuer_dn`). Those render blank or zero against a live backend and
 * nothing catches it, because `any` silences the compiler.
 *
 * Keep these in sync with the Go structs. `vue-tsc` then fails the build when a
 * template binds a field that does not exist.
 */

import type { CaStatus, CaType, CertStatus } from './severity'

/** core/store/models.go — CAAuthority */
export interface CaAuthority {
  id: string
  name: string
  ca_type: CaType
  subject_dn: string
  issuer_dn: string
  serial_number?: string
  not_before: string
  not_after: string
  days_remaining: number
  key_type: string
  key_size: number
  fingerprint_sha256: string
  certificate_pem: string
  parent_ca_id?: string | null
  crl_distribution_url?: string
  ocsp_responder_url?: string
  is_crl_fresh: boolean
  crl_last_checked?: string
  is_ocsp_responsive: boolean
  ocsp_last_checked?: string
  certificates_issued_count: number
  alert_thresholds?: string
  last_alert_sent_at?: string
  last_alert_threshold?: number
  status: CaStatus
  ca_account_id?: string | null
  tags?: string
  notes?: string
  created_at: string
  updated_at: string
}

/** core/store/models.go — Certificate */
export interface Certificate {
  id: string
  fingerprint_sha256: string
  common_name: string
  sans: string[]
  serial_number?: string
  issuer_dn?: string
  not_before?: string
  not_after?: string
  days_remaining: number
  key_type?: string
  key_size?: number
  status: CertStatus
  auto_renew: boolean
  renewal_lead_days: number
  last_renewal_attempt?: string
  renewal_error?: string
  renewal_count: number
  ca_account_id?: string | null
  ca_authority_id?: string | null
  certificate_pem?: string
  chain_pem?: string
  discovered_via: 'MANUAL' | 'SCAN' | 'CT_LOG' | 'IMPORT' | 'REQUESTED'
  environment?: string
  team?: string
  tags?: string[]
  created_at: string
  updated_at: string
}

/** core/store/models.go — CAAccount. `config_encrypted` is never serialized. */
export interface CaAccount {
  id: string
  name: string
  provider_type: string
  gateway_addr: string
  is_default: boolean
  status: 'CONNECTED' | 'DISCONNECTED' | 'ERROR'
  last_health_at?: string
  created_at: string
  updated_at: string
}

/** core/store/models.go — AuditLog. Note the timestamp field is `created_at`. */
export interface AuditLog {
  id: string
  action: string
  entity_type: string
  entity_id?: string
  actor_id?: string
  actor_email?: string
  /** JSON-encoded string, not an object. Parse with `parseDetails`. */
  details?: string
  ip_address?: string
  created_at: string
}

/** Shape of `details` on a `ca.expiry_alert` — core/engine/pki/ca_monitor.go */
export interface CaExpiryAlertDetails {
  ca_name: string
  ca_type: CaType
  days_remaining: number
  threshold: number
  severity: 'WARNING' | 'CRITICAL'
  not_after: string
}

/** Safely parses an audit log's JSON `details` field. */
export function parseDetails<T = Record<string, unknown>>(details?: string): T | null {
  if (!details) return null
  try {
    return JSON.parse(details) as T
  } catch {
    return null
  }
}

/** core/store/models.go — DashboardStats */
export interface DashboardStats {
  total_certificates: number
  healthy_certs: number
  expiring_soon_certs: number
  expired_certs: number
  total_cas: number
  healthy_cas: number
  warning_cas: number
  critical_cas: number
  total_scans: number
}

/** core/store/models.go — Policy */
export interface Policy {
  id: string
  name: string
  description?: string
  is_enabled: boolean
  rule_type: string
  rule_config: string
  domain_pattern?: string
  severity: 'INFO' | 'WARNING' | 'BLOCK'
  created_at: string
  updated_at: string
}

/** Gateway summary from GET /api/v1/gateways — core/api/ca_accounts.go */
export interface GatewaySummary {
  name: string
  addr: string
  type: string
  is_connected: boolean
  capabilities: ProviderCapabilities | null
  last_checked: string
}

export interface ProviderCapabilities {
  provider_name: string
  provider_version: string
  provider_type: string
  supports_wildcard: boolean
  supports_multi_domain: boolean
  supported_key_types: string[]
  supported_challenges: string[]
  validation_levels: string[]
  supports_revocation: boolean
  supports_ca_info: boolean
  description: string
}

/** Most list endpoints wrap results this way. `GET /dashboard/stats` does not. */
export interface ListResponse<T> {
  data: T[]
  total: number
}

/** The empty list, for endpoints that legitimately return nothing yet. */
export function emptyList<T>(): ListResponse<T> {
  return { data: [], total: 0 }
}
