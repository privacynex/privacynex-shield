/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : runtime configuration
   Runtime-neutral request configuration built on the Fetch API.
   The provided deployment scaffold targets Cloudflare Pages; other
   platform adapters must be validated in their target environment.

   Only the client IP header name is platform-dependent: each edge
   network sets its own authoritative header, and this package has
   no way to guess it safely. Configure it once at startup; signals
   that depend on unavailable platform metadata are skipped.
   ═══════════════════════════════════════════════════════════════ */

const DEFAULT_CLIENT_IP_HEADER = 'CF-Connecting-IP';

let clientIpHeader = DEFAULT_CLIENT_IP_HEADER;

/**
 * Set the request header that carries the authoritative client IP for the
 * current platform (e.g. `True-Client-IP` on Fastly, `X-Real-IP` behind a
 * trusted reverse proxy). Defaults to `CF-Connecting-IP`. Call this once
 * before handling requests; an empty or missing value keeps the default.
 */
export function configureClientIpHeader(headerName: string | undefined): void {
  clientIpHeader = headerName && headerName.trim() ? headerName.trim() : DEFAULT_CLIENT_IP_HEADER;
}

export function getClientIpHeaderName(): string {
  return clientIpHeader;
}

export function getClientIp(request: Request): string {
  return (request.headers.get(clientIpHeader) || '').trim();
}
