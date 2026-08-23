/**
 * Status vocabulary and severity mapping.
 *
 * The backend emits fixed uppercase status strings (see core/store/models.go).
 * Four separate copies of this mapping had drifted apart across the views, each
 * with a slightly different idea of which statuses count as critical, plus a
 * fifth disconnected hex palette in the charts. For a monitoring tool that is
 * not cosmetic: two panels disagreeing about whether a CA is in trouble is a
 * correctness bug.
 *
 * This module is the single source of truth. Add a status here, nowhere else.
 */

/** Severity ranks how much attention something needs, worst first. */
export type Severity = 'critical' | 'warning' | 'ok' | 'unknown'

/** Ordering used for urgency sorts. Lower sorts first. */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  warning: 1,
  unknown: 2,
  ok: 3,
}

/** CA authority statuses — core/store/models.go CAAuthority.Status. */
export type CaStatus = 'HEALTHY' | 'WARNING' | 'CRITICAL' | 'EXPIRED' | 'UNKNOWN'

/** Certificate statuses — core/store/models.go Certificate.Status. */
export type CertStatus =
  | 'PENDING'
  | 'ISSUED'
  | 'EXPIRING'
  | 'EXPIRED'
  | 'REVOKED'
  | 'RENEWAL_FAILED'

/** CA hierarchy positions — core/store/models.go CAAuthority.CAType. */
export type CaType = 'ROOT' | 'INTERMEDIATE' | 'ISSUING'

const CA_SEVERITY: Record<CaStatus, Severity> = {
  HEALTHY: 'ok',
  WARNING: 'warning',
  CRITICAL: 'critical',
  EXPIRED: 'critical',
  UNKNOWN: 'unknown',
}

const CERT_SEVERITY: Record<CertStatus, Severity> = {
  ISSUED: 'ok',
  PENDING: 'unknown',
  EXPIRING: 'warning',
  EXPIRED: 'critical',
  REVOKED: 'critical',
  // A failed renewal is on its way to expiry with nobody watching, which is
  // exactly the situation this tool exists to prevent.
  RENEWAL_FAILED: 'critical',
}

/** Normalizes a status the backend sent, tolerating case drift. */
function normalize(status: string | null | undefined): string {
  return (status ?? '').trim().toUpperCase()
}

export function caSeverity(status: string | null | undefined): Severity {
  return CA_SEVERITY[normalize(status) as CaStatus] ?? 'unknown'
}

export function certSeverity(status: string | null | undefined): Severity {
  return CERT_SEVERITY[normalize(status) as CertStatus] ?? 'unknown'
}

/**
 * Severity from a remaining-days count, matching the thresholds the CA monitor
 * uses server-side (core/engine/pki/ca_monitor.go).
 */
export function severityFromDays(days: number | null | undefined): Severity {
  if (days === null || days === undefined || Number.isNaN(days)) return 'unknown'
  if (days <= 0) return 'critical'
  if (days <= 30) return 'critical'
  if (days <= 180) return 'warning'
  return 'ok'
}

/**
 * How urgent a certificate actually is.
 *
 * `status` alone is not enough, and relying on it is a real defect rather than a
 * cosmetic one: the core leaves a certificate `ISSUED` until a renewal sweep
 * moves it, so a certificate two days from expiry reports `ISSUED` and renders
 * as healthy — while `/dashboard/stats` counts it under `expiring_soon_certs` in
 * the very same response. The dashboard contradicting its own totals is exactly
 * the failure this product exists to prevent.
 *
 * The threshold is the certificate's own `renewal_lead_days`, not a number
 * invented here. Inside its renewal window and still not renewed is a fact about
 * that certificate's configuration; past `not_after` is a fact about time.
 */
export function certUrgency(cert: {
  status: string
  days_remaining: number
  renewal_lead_days?: number
}): Severity {
  if (cert.days_remaining < 0) return 'critical'

  const fromStatus = certSeverity(cert.status)
  const lead = cert.renewal_lead_days && cert.renewal_lead_days > 0 ? cert.renewal_lead_days : 30

  let fromClock: Severity = 'ok'
  if (cert.days_remaining <= Math.ceil(lead / 3)) fromClock = 'critical'
  else if (cert.days_remaining <= lead) fromClock = 'warning'

  // Whichever is worse. A REVOKED certificate with a year left is still
  // critical, and an ISSUED one with two days left is too.
  return compareSeverity(fromStatus, fromClock) <= 0 ? fromStatus : fromClock
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[a] - SEVERITY_RANK[b]
}

/**
 * Console class for a severity, for the converted views.
 *
 * These resolve to the `--sev-*` tokens in main.css. The daisyUI helpers below
 * are what the not-yet-converted views still use; both read the same palette,
 * so the two halves of the app agree about what critical looks like while the
 * conversion is in progress.
 */
export function sevClass(severity: Severity): string {
  return `sev-${severity}`
}

/** Background variant, for dots, rails and horizon marks. */
export function sevBg(severity: Severity): string {
  return `sev-bg-${severity}`
}

/** The CSS custom property holding a severity's colour. */
export function sevVar(severity: Severity): string {
  return `var(--sev-${severity})`
}

/**
 * Short uppercase label for a chip.
 *
 * "CRIT" rather than "Critical": in a column of chips the eye is matching
 * shapes, and four characters at four different severities are told apart
 * faster than nine.
 */
export function sevLabel(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'CRIT'
    case 'warning':
      return 'WARN'
    case 'ok':
      return 'OK'
    default:
      return 'UNKN'
  }
}

/** daisyUI badge class for a severity. */
export function severityBadge(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'badge-error'
    case 'warning':
      return 'badge-warning'
    case 'ok':
      return 'badge-success'
    default:
      return 'badge-ghost'
  }
}

/** daisyUI text-colour class for a severity. */
export function severityText(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'text-error'
    case 'warning':
      return 'text-warning'
    case 'ok':
      return 'text-success'
    default:
      return 'text-base-content/60'
  }
}

/** Border/stripe class, for the severity rail on CA rows. */
export function severityBorder(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'border-error'
    case 'warning':
      return 'border-warning'
    case 'ok':
      return 'border-success'
    default:
      return 'border-base-300'
  }
}

/**
 * What to call a certificate's state, given that urgency and status can differ.
 *
 * `certUrgency` colours a certificate two days from expiry as critical while its
 * stored status is still `ISSUED`, which produced a red chip reading "ISSUED" —
 * the colour saying one thing and the word another, on the single element whose
 * job is to say what is wrong. When the clock is what made it urgent, the label
 * has to say so.
 */
export function certStateLabel(cert: {
  status: string
  days_remaining: number
  renewal_lead_days?: number
}): string {
  if (cert.days_remaining < 0) return 'Expired'
  const stated = certSeverity(cert.status)
  const actual = certUrgency(cert)
  // Only override when the clock is the thing that raised it. A REVOKED
  // certificate stays REVOKED — that is the more important fact.
  if (actual !== stated && compareSeverity(actual, stated) < 0) return 'Expiring'
  return statusLabel(cert.status)
}

/** Turns SCREAMING_SNAKE into Title Case for display. */
export function statusLabel(status: string | null | undefined): string {
  const s = normalize(status)
  if (!s) return 'Unknown'
  return s
    .split('_')
    .map((word) => word.charAt(0) + word.slice(1).toLowerCase())
    .join(' ')
}

/**
 * Resolves theme colours to concrete values for chart.js, which cannot consume
 * CSS custom properties.
 *
 * Charts previously hardcoded hex values copied from a daisyUI v4 palette, so
 * they stayed light-themed no matter what the rest of the page did. Reading the
 * computed values means one palette follows the theme toggle.
 *
 * Call this from a `watch` on the theme, not once at module load, or the charts
 * keep the palette they were born with.
 */
export function themePalette(): Record<string, string> {
  const fallback = {
    success: '#36d399',
    warning: '#fbbd23',
    error: '#f87272',
    info: '#3abff8',
    primary: '#570df8',
    secondary: '#f000b8',
    accent: '#37cdbe',
    neutral: '#3d4451',
  }

  if (typeof window === 'undefined') return fallback

  const styles = getComputedStyle(document.documentElement)
  const read = (name: string, fb: string) => {
    const value = styles.getPropertyValue(name).trim()
    return value || fb
  }

  return {
    success: read('--color-success', fallback.success),
    warning: read('--color-warning', fallback.warning),
    error: read('--color-error', fallback.error),
    info: read('--color-info', fallback.info),
    primary: read('--color-primary', fallback.primary),
    secondary: read('--color-secondary', fallback.secondary),
    accent: read('--color-accent', fallback.accent),
    neutral: read('--color-neutral', fallback.neutral),
  }
}

/** Chart colours in severity order: ok, warning, critical, unknown. */
export function severityPalette(): string[] {
  const p = themePalette()
  return [p.success, p.warning, p.error, p.neutral]
}

/** A categorical palette for non-severity breakdowns, e.g. certificates per CA. */
export function categoricalPalette(): string[] {
  const p = themePalette()
  return [p.info, p.primary, p.accent, p.secondary, p.success, p.warning]
}
