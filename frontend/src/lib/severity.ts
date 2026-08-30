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
 * Console class for a severity.
 *
 * Resolves to the `--sev-*` tokens in main.css. This is now the only way a
 * severity becomes a colour anywhere in the frontend — the parallel set of
 * daisyUI helpers that existed during the conversion is gone, so there is no
 * longer a second palette for a view to pick up by accident.
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
 * Resolves theme colours to concrete values for chart.js.
 *
 * chart.js draws to a canvas and cannot consume CSS custom properties, so every
 * colour has to be read out as a concrete value first.
 *
 * These read the `--sev-*` design tokens — the same ones the tables and chips
 * use. They previously read daisyUI's `--color-*`, which meant the charts had
 * their own palette: a slice could be a different red from the row it
 * summarised, and when daisyUI was removed the variables would have resolved to
 * nothing and every chart would have drawn in transparent black.
 *
 * Call this from a `watch` on the theme, not once at module load, or the charts
 * keep the palette they were born with.
 */
export function themePalette(): Record<string, string> {
  const fallback = {
    ok: '#58a06f',
    warning: '#ffa726',
    critical: '#ff4d3d',
    unknown: '#6b7480',
    signal: '#5ac8fa',
  }

  if (typeof window === 'undefined') return fallback

  const styles = getComputedStyle(document.documentElement)
  const read = (name: string, fb: string) => styles.getPropertyValue(name).trim() || fb

  return {
    ok: read('--sev-ok', fallback.ok),
    warning: read('--sev-warning', fallback.warning),
    critical: read('--sev-critical', fallback.critical),
    unknown: read('--sev-unknown', fallback.unknown),
    signal: read('--signal', fallback.signal),
  }
}

/** Chart colours in severity order: ok, warning, critical, unknown. */
export function severityPalette(): string[] {
  const p = themePalette()
  return [p.ok, p.warning, p.critical, p.unknown]
}

/**
 * A palette for non-severity breakdowns, e.g. certificates per CA.
 *
 * Deliberately not a rainbow. A categorical chart on this product must not
 * introduce warm hues that read as severity to someone scanning past it, so
 * this is the signal blue stepped by lightness and nothing else.
 */
export function categoricalPalette(): string[] {
  const p = themePalette()
  return [
    p.signal,
    color(p.signal, 0.75),
    color(p.signal, 0.55),
    color(p.signal, 0.4),
    p.unknown,
    color(p.unknown, 0.6),
  ]
}

/** Fades a colour towards the page ground, for categorical steps. */
function color(base: string, alpha: number): string {
  return `color-mix(in srgb, ${base} ${Math.round(alpha * 100)}%, transparent)`
}
