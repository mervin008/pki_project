/**
 * Rendering for live stream events.
 *
 * Kept out of the store and out of the views because three surfaces will show
 * the same event — the alert list, the dashboard feed, and the wall display —
 * and three copies of "what does cert.renewal_failed mean" would drift the way
 * the four copies of the severity mapping did.
 */

import type { Severity } from './severity'
import type {
  CaExpiryAlertPayload,
  CaHealthPayload,
  CertEventPayload,
  StreamEvent,
} from './types'

/**
 * Severity of an event, from the severity the *server* assigned.
 *
 * Deliberately not recomputed from the payload. The core decided this was
 * critical when it published it, and a dashboard that reaches a different
 * verdict than the thing that sends the alerts is worse than one that simply
 * mirrors it.
 */
export function eventSeverity(event: StreamEvent): Severity {
  switch (event.severity) {
    case 'CRITICAL':
      return 'critical'
    case 'WARNING':
      return 'warning'
    case 'INFO':
      return 'ok'
    default:
      return 'unknown'
  }
}

/** True for events a PKI team needs to act on, as opposed to routine noise. */
export function isActionable(event: StreamEvent): boolean {
  return event.severity === 'WARNING' || event.severity === 'CRITICAL'
}

/** One-line description of an event, for a feed. */
export function describeEvent(event: StreamEvent): string {
  const payload = event.payload ?? {}

  switch (event.topic) {
    case 'ca.health': {
      const p = payload as unknown as CaHealthPayload
      const name = p.ca_name ?? 'A certificate authority'
      if (p.previous_status && p.status) {
        return `${name} moved from ${humanize(p.previous_status)} to ${humanize(p.status)}`
      }
      return `${name} is now ${humanize(p.status)}`
    }

    case 'ca.expiry_alert': {
      const p = payload as unknown as CaExpiryAlertPayload
      const name = p.ca_name ?? 'A certificate authority'
      // The threshold matters: it is why this fired now rather than yesterday,
      // and it is what an operator silences or adjusts.
      return `${name} expires in ${p.days_remaining} days — crossed the ${p.threshold}-day threshold`
    }

    case 'cert.issued': {
      const p = payload as unknown as CertEventPayload
      return `Issued ${p.common_name ?? 'a certificate'}${p.gateway ? ` via ${p.gateway}` : ''}`
    }

    case 'cert.renewed': {
      const p = payload as unknown as CertEventPayload
      return `Renewed ${p.common_name ?? 'a certificate'}${
        p.days_remaining !== undefined ? ` — valid for ${p.days_remaining} more days` : ''
      }`
    }

    case 'cert.renewal_failed': {
      const p = payload as unknown as CertEventPayload
      const subject = p.common_name ?? 'a certificate'
      return `Renewal failed for ${subject}${p.error ? `: ${p.error}` : ''}`
    }

    case 'cert.expiring': {
      const p = payload as unknown as CertEventPayload
      return `${p.common_name ?? 'A certificate'} expires in ${p.days_remaining ?? '?'} days`
    }

    case 'gateway.status': {
      const p = payload as { name?: string; connected?: boolean }
      return `Gateway ${p.name ?? 'unknown'} is ${p.connected ? 'connected' : 'unreachable'}`
    }

    default:
      // An unrecognised topic still renders. A future core publishing something
      // this build has never heard of should show up as an unfamiliar line, not
      // vanish from the feed.
      return event.topic
  }
}

/** Short label for the entity kind an event concerns. */
export function eventCategory(event: StreamEvent): string {
  if (event.topic.startsWith('ca.')) return 'CA'
  if (event.topic.startsWith('cert.')) return 'Certificate'
  if (event.topic.startsWith('gateway.')) return 'Gateway'
  return 'Event'
}

function humanize(value: string | undefined): string {
  if (!value) return 'unknown'
  return value.toLowerCase()
}
