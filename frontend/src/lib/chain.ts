/**
 * Where each CA sits in the hierarchy, derived from the flat list the store
 * already holds.
 *
 * The core exposes `GET /api/v1/pki/tree`, which returns the same thing. This
 * derives it client-side anyway, for two reasons:
 *
 *  - **It stays live for free.** The CA store is kept current by the event
 *    stream; a separately fetched tree would be a second copy of the estate that
 *    goes out of date the moment a CA is added, and reconciling the two is more
 *    machinery than the derivation itself.
 *  - **It costs nothing.** The tree endpoint returns whole authorities including
 *    every certificate PEM, which is a large response to fetch for one integer
 *    per row. `parent_ca_id` is already on the records in hand.
 *
 * The placement rules match core/engine/pki/chain_resolver.go deliberately, so
 * the two do not disagree about a malformed hierarchy. In particular, a CA whose
 * issuer chain loops is **shown, flagged** rather than hidden: this is a
 * monitoring tool, and a CA that quietly fails to render is the one nobody
 * notices expiring.
 */

import type { CaAuthority } from './types'

export interface ChainPosition {
  /** Issuing steps from the root of this chain. A root is 0. */
  depth: number
  /** Ancestor names, root first, excluding the CA itself. */
  ancestors: string[]
  /** The root of this chain, or null when there isn't a reachable one. */
  rootName: string | null
  /** True when the CA could not be placed under a real root. */
  detached: boolean
  /** Why, in words an operator can act on. */
  detachedReason?: string
}

const ROOT: ChainPosition = { depth: 0, ancestors: [], rootName: null, detached: false }

/**
 * Maps every CA id to its position.
 *
 * Walks up from each CA rather than building a tree downwards: the answer wanted
 * here is per-row, the estate is tens of CAs deep at most, and walking upwards
 * makes loop detection a single `Set` on the path rather than a second pass over
 * everything a descent failed to reach.
 */
export function resolveChains(cas: readonly CaAuthority[]): Map<string, ChainPosition> {
  const byId = new Map(cas.map((ca) => [ca.id, ca]))
  const positions = new Map<string, ChainPosition>()

  for (const ca of cas) {
    positions.set(ca.id, walkUp(ca, byId))
  }
  return positions
}

function walkUp(start: CaAuthority, byId: Map<string, CaAuthority>): ChainPosition {
  // Names from the CA itself upwards. Reversed at the end.
  const upwards: string[] = [start.name]
  const seen = new Set<string>([start.id])

  let current = start
  for (;;) {
    const parentId = current.parent_ca_id
    if (!parentId) break // A genuine root.

    if (parentId === current.id) {
      return detached(upwards, 'this CA is recorded as its own issuer')
    }
    if (seen.has(parentId)) {
      return detached(upwards, 'its issuer chain forms a loop, so it has no root')
    }

    const parent = byId.get(parentId)
    if (!parent) {
      // Ordinary rather than broken: a root held offline in a safe, or an
      // intermediate imported on its own.
      return detached(upwards, 'its issuing CA is not registered in CertPilot')
    }

    seen.add(parent.id)
    upwards.push(parent.name)
    current = parent
  }

  if (upwards.length === 1) return ROOT

  const ancestors = upwards.slice(1).reverse()
  return {
    depth: ancestors.length,
    ancestors,
    rootName: ancestors[0],
    detached: false,
  }
}

function detached(upwards: string[], reason: string): ChainPosition {
  const ancestors = upwards.slice(1).reverse()
  return {
    // Depth is measured from a root. Without one there is nothing to measure
    // from, so it is reported as unknown rather than guessed at.
    depth: 0,
    ancestors,
    rootName: null,
    detached: true,
    detachedReason: reason,
  }
}

/** One short line for a table cell: where this CA hangs. */
export function describeChainPosition(position: ChainPosition | undefined): string {
  if (!position) return 'Unknown'
  if (position.detached) return 'No known root'
  if (position.depth === 0) return 'Root of its own chain'
  const issuer = position.ancestors[position.ancestors.length - 1]
  return position.depth === 1 ? `Issued by ${issuer}` : `Under ${issuer}`
}

/** The full lineage, root first, for a tooltip. */
export function describeLineage(
  position: ChainPosition | undefined,
  name: string,
): string {
  if (!position) return name
  return [...position.ancestors, name].join(' › ')
}
