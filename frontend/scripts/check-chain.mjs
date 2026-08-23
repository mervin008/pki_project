/**
 * Checks the CA chain-position derivation.
 *
 * Run: node scripts/check-chain.mjs   (or `make test-frontend` from the repo root)
 *
 * Same approach as check-sse.mjs: Node strips TypeScript types natively from
 * v22.18, so the module under test is imported directly with no build step and
 * no test runner in the dependency tree.
 *
 * It exists because this code decides what a row on the CA health view says
 * about where a CA sits in the hierarchy, and because the equivalent Go code got
 * two things wrong that do not announce themselves: depth that depended on
 * iteration order, and a loop in `parent_ca_id` that made CAs vanish from the
 * output entirely. A CA silently missing from a monitoring view is the exact
 * failure this product exists to prevent, so both cases are pinned here as well
 * as in core/engine/pki/chain_resolver_test.go.
 */

import { resolveChains, describeChainPosition, describeLineage } from '../src/lib/chain.ts'

let failures = 0

function check(name, actual, expected) {
  const a = JSON.stringify(actual)
  const e = JSON.stringify(expected)
  if (a === e) {
    console.log(`  ok   ${name}`)
  } else {
    failures++
    console.log(`  FAIL ${name}\n         want ${e}\n         got  ${a}`)
  }
}

const ca = (id, name, parent) => ({ id, name, parent_ca_id: parent ?? null })

// A three-deep chain, fed in every order. Depth must not depend on the order the
// API happened to return the authorities in.
{
  const root = ca('root', 'Corporate Root')
  const mid = ca('mid', 'Corporate Intermediate', 'root')
  const leaf = ca('leaf', 'TLS Issuing CA', 'mid')

  for (const [label, list] of [
    ['parents first', [root, mid, leaf]],
    ['children first', [leaf, mid, root]],
    ['interleaved', [mid, leaf, root]],
  ]) {
    const chains = resolveChains(list)
    check(
      `depth is order-independent (${label})`,
      [chains.get('root').depth, chains.get('mid').depth, chains.get('leaf').depth],
      [0, 1, 2],
    )
  }

  const chains = resolveChains([root, mid, leaf])
  check('the root of a chain is named', chains.get('leaf').rootName, 'Corporate Root')
  check('ancestors run root-first', chains.get('leaf').ancestors, [
    'Corporate Root',
    'Corporate Intermediate',
  ])
  check(
    'lineage reads as a path',
    describeLineage(chains.get('leaf'), 'TLS Issuing CA'),
    'Corporate Root › Corporate Intermediate › TLS Issuing CA',
  )
  check('a root describes itself as one', describeChainPosition(chains.get('root')), 'Root of its own chain')
  check('a direct child names its issuer', describeChainPosition(chains.get('mid')), 'Issued by Corporate Root')
}

// The case that must not hang and must not drop anyone. A loop in parent_ca_id
// is bad data, but a monitoring view that silently omits the CAs involved is
// worse than one that shows them flagged.
{
  const chains = resolveChains([
    ca('a', 'Alpha CA', 'b'),
    ca('b', 'Bravo CA', 'a'),
    ca('healthy', 'Standalone Root'),
  ])
  check('every CA in a loop is still placed', chains.size, 3)
  check('a looping CA is flagged detached', [chains.get('a').detached, chains.get('b').detached], [true, true])
  check('an unrelated root is unaffected', chains.get('healthy').detached, false)
  check('a detached CA reads honestly', describeChainPosition(chains.get('a')), 'No known root')
}

// A CA naming itself. Distinct message, because the fix is different.
{
  const chains = resolveChains([ca('solo', 'Ouroboros CA', 'solo')])
  check('self-issued is detected', chains.get('solo').detached, true)
  check(
    'self-issued says why',
    chains.get('solo').detachedReason,
    'this CA is recorded as its own issuer',
  )
}

// Ordinary and legitimate: a root held offline, or an intermediate imported on
// its own. Flagged, but the subtree below it still has to resolve.
{
  const chains = resolveChains([
    ca('mid', 'Corporate Intermediate', 'root-in-a-safe'),
    ca('leaf', 'TLS Issuing CA', 'mid'),
  ])
  check('an unregistered issuer is flagged', chains.get('mid').detached, true)
  check(
    'an unregistered issuer says why',
    chains.get('mid').detachedReason,
    'its issuing CA is not registered in CertPilot',
  )
  // The leaf's own parent is present, so the leaf itself resolves; it simply
  // runs out of chain one level up.
  check('the CA below it still resolves', chains.get('leaf').detached, true)
  check('and keeps the ancestors it does know', chains.get('leaf').ancestors, [
    'Corporate Intermediate',
  ])
}

// Long chains terminate. A depth of 40 is not realistic; a derivation that
// cannot survive one is not trustworthy on a chain of 4.
{
  const list = [ca('n0', 'CA 0')]
  for (let i = 1; i < 40; i++) list.push(ca(`n${i}`, `CA ${i}`, `n${i - 1}`))
  const chains = resolveChains(list)
  check('a 40-deep chain resolves', chains.get('n39').depth, 39)
  check('and knows its root', chains.get('n39').rootName, 'CA 0')
}

check('an empty estate produces no positions', resolveChains([]).size, 0)

console.log(
  failures === 0 ? '\nChain resolution: all checks passed' : `\nChain resolution: ${failures} failure(s)`,
)
process.exit(failures === 0 ? 0 : 1)
