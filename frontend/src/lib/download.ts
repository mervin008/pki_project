/**
 * Handing a file to the browser.
 *
 * Certificates and keys arrive as PEM text in a JSON response, and there is no
 * URL to link to — so the file has to be produced client-side from a blob. The
 * object URL is revoked on the next frame; without that, every export leaks the
 * blob for the life of the tab, which for private keys means the material stays
 * reachable in memory long after the page has moved on.
 */
export function downloadText(filename: string, contents: string, mime = 'application/x-pem-file') {
  const blob = new Blob([contents], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  requestAnimationFrame(() => URL.revokeObjectURL(url))
}

/**
 * A filename derived from a common name.
 *
 * Wildcards and dots are what make this necessary: `*.example.com` is not a
 * legal filename on Windows and is a glob on a shell. `_wildcard.example.com`
 * is the convention mkcert established and people recognise it.
 */
export function pemFilename(commonName: string, suffix: string): string {
  const base = (commonName || 'certificate')
    .replace(/^\*/, '_wildcard')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
  return `${base}.${suffix}`
}

/**
 * Concatenates a leaf and its chain into the file most servers actually want.
 *
 * nginx's `ssl_certificate` and HAProxy both expect leaf-first, issuers after,
 * in one file. Offering only the two halves separately means everyone
 * downloading them does this concatenation by hand, and gets the order wrong
 * often enough that "why does Chrome say untrusted" is a support question.
 */
export function fullChain(certificatePEM: string, chainPEM?: string | null): string {
  const parts = [certificatePEM.trim()]
  if (chainPEM && chainPEM.trim()) parts.push(chainPEM.trim())
  return parts.join('\n') + '\n'
}
