/**
 * Checks the Server-Sent Events frame parser.
 *
 * Run: node scripts/check-sse.mjs   (or `make test-frontend` from the repo root)
 *
 * There is no test runner in the frontend yet. This deliberately needs none:
 * Node strips TypeScript types natively from v22.18, so the module under test is
 * imported directly with no build step and no dependency to install.
 *
 * It exists because src/lib/sse.ts is hand-rolled protocol parsing, and the way
 * that code fails is the worst possible failure for this product. A frame
 * boundary missed at a chunk edge does not throw and does not log — it means
 * events silently never arrive, and a dashboard that has stopped receiving
 * events looks exactly like a PKI with nothing wrong. Every case below is a
 * shape the core actually emits (see core/api/events.go).
 */

import { createSseParser } from '../src/lib/sse.ts'

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

// The opening sequence the core writes on every connection.
{
  const p = createSseParser()
  const frames = p.push(
    'retry: 3000\n\nevent: snapshot\ndata: {"stats":{"total_cas":3},"cas":[]}\n\n',
  )
  check('retry directive is surfaced', frames[0], { event: 'message', data: '', retry: 3000 })
  check('snapshot frame parses', frames[1], {
    event: 'snapshot',
    data: '{"stats":{"total_cas":3},"cas":[]}',
  })
}

// A topic event, exactly as writeEvent formats it. The id is what a reconnect
// echoes back as Last-Event-ID, so losing it means silently refetching
// everything instead of resuming.
{
  const p = createSseParser()
  const [frame] = p.push(
    'id: 7\nevent: ca.expiry_alert\ndata: {"id":7,"topic":"ca.expiry_alert"}\n\n',
  )
  check('event id is captured', frame.id, '7')
  check('event name is captured', frame.event, 'ca.expiry_alert')
}

// The heartbeat is an SSE comment. It must yield no frame, and must not eat
// whatever follows it.
{
  const p = createSseParser()
  check('heartbeat alone yields nothing', p.push(': heartbeat\n\n'), [])
  check('an event after a heartbeat still parses', p.push('event: snapshot\ndata: {"ok":1}\n\n').length, 1)
}

// The case this file mainly exists for. A TCP segment can end anywhere,
// including inside a field name or between the two newlines of a boundary.
{
  const whole = 'id: 12\nevent: cert.issued\ndata: {"common_name":"a.example.com"}\n\n'
  let bad = null
  for (let cut = 1; cut < whole.length && !bad; cut++) {
    const p = createSseParser()
    const frames = [...p.push(whole.slice(0, cut)), ...p.push(whole.slice(cut))]
    if (frames.length !== 1 || frames[0].event !== 'cert.issued' || frames[0].id !== '12') {
      bad = `split at byte ${cut} produced ${JSON.stringify(frames)}`
    }
  }
  check('a frame survives being split at every byte', bad, null)
}

// Several frames in one read, which is what a burst from a health sweep or a
// history replay looks like.
{
  const p = createSseParser()
  const frames = p.push(
    'id: 1\nevent: ca.health\ndata: {"a":1}\n\n' +
      ': heartbeat\n\n' +
      'id: 2\nevent: ca.health\ndata: {"a":2}\n\n',
  )
  check(
    'a burst yields every event and drops the comment',
    frames.map((f) => f.id),
    ['1', '2'],
  )
}

// The core emits LF, but nothing obliges a proxy in between to preserve that.
// The nasty case is a CR that lands as the last byte of a chunk.
{
  const p = createSseParser()
  const frames = [...p.push('event: snapshot\r'), ...p.push('\ndata: {"ok":1}\r\n\r\n')]
  check('CRLF split across two chunks', frames, [{ event: 'snapshot', data: '{"ok":1}' }])
}

// Spec details that JSON payloads depend on.
{
  const p = createSseParser()
  const [multiline] = p.push('event: x\ndata: {"a":\ndata: 1}\n\n')
  check('multi-line data joins with newlines', multiline.data, '{"a":\n1}')

  const [tight] = p.push('event:ca.health\ndata:{"url":"https://x/y"}\n\n')
  check('a value with no leading space', tight.event, 'ca.health')
  check('colons inside a value survive', tight.data, '{"url":"https://x/y"}')
}

console.log(failures === 0 ? '\nSSE parser: all checks passed' : `\nSSE parser: ${failures} failure(s)`)
process.exit(failures === 0 ? 0 : 1)
