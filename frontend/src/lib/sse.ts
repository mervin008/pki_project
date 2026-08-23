/**
 * Server-Sent Events framing.
 *
 * Split out from useEventStream so the protocol handling is a pure function of
 * its input: byte chunks in, frames out, no refs, no fetch, no clock. Hand-rolled
 * parsing of a wire format is the part of a live dashboard most likely to be
 * subtly wrong — a frame boundary missed across a chunk edge shows up as events
 * that silently never arrive, which on this product looks exactly like a healthy
 * PKI.
 *
 * Framing per the WHATWG spec: frames are separated by a blank line, fields are
 * `name: value` with one optional leading space stripped from the value, and a
 * line beginning with a colon is a comment.
 */

export interface SseFrame {
  /** The `event:` name, defaulting to `message` as the spec requires. */
  event: string
  /** All `data:` lines joined with newlines. */
  data: string
  /** The `id:` field, if this frame carried one. */
  id?: string
  /** The `retry:` field in milliseconds, if this frame carried one. */
  retry?: number
}

export interface SseParser {
  /**
   * Feeds a decoded chunk and returns the frames it completed.
   *
   * Comment-only frames — the server's heartbeat — are not returned: they carry
   * no data. The caller treats the arrival of *any* byte as proof of life, which
   * is what keeps a quiet estate distinguishable from a dead connection.
   */
  push: (chunk: string) => SseFrame[]
  /** Discards partial state. Called when a connection is replaced. */
  reset: () => void
}

export function createSseParser(): SseParser {
  let buffer = ''
  /** Holds a lone trailing CR, so a CRLF split across two chunks still parses. */
  let carry = ''

  function push(chunk: string): SseFrame[] {
    let text = carry + chunk
    carry = ''
    if (text.endsWith('\r')) {
      carry = '\r'
      text = text.slice(0, -1)
    }
    buffer += text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')

    const frames: SseFrame[] = []
    for (;;) {
      const boundary = buffer.indexOf('\n\n')
      if (boundary === -1) break
      const raw = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      const frame = parseFrame(raw)
      if (frame) frames.push(frame)
    }
    return frames
  }

  function reset() {
    buffer = ''
    carry = ''
  }

  return { push, reset }
}

function parseFrame(raw: string): SseFrame | null {
  let event = 'message'
  const data: string[] = []
  let id: string | undefined
  let retry: number | undefined

  for (const line of raw.split('\n')) {
    if (line === '' || line.startsWith(':')) continue

    const colon = line.indexOf(':')
    const field = colon === -1 ? line : line.slice(0, colon)
    let value = colon === -1 ? '' : line.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)

    switch (field) {
      case 'event':
        event = value
        break
      case 'data':
        data.push(value)
        break
      case 'id':
        // The spec ignores an id containing a NUL; an empty one clears it,
        // which we treat as "no id on this frame" rather than resetting.
        if (value !== '' && !value.includes('\0')) id = value
        break
      case 'retry': {
        const ms = Number(value)
        if (Number.isInteger(ms) && ms > 0) retry = ms
        break
      }
    }
  }

  // A comment-only or field-only frame carries nothing to dispatch. The
  // heartbeat lands here, having already served its purpose by arriving.
  if (data.length === 0 && id === undefined && retry === undefined) return null

  return { event, data: data.join('\n'), id, retry }
}
