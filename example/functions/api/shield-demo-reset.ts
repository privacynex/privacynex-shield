/**
 * Local demo helper only.
 *
 * This file is deliberately outside server/ and is not copied by the
 * Privacynex Shield initializer. It only clears demo cookies for same-origin
 * POST requests served from a loopback hostname.
 */

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

interface DemoContext {
  request: Request;
}

function response(status: number): Response {
  return new Response(null, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export function onRequest(context: DemoContext): Response {
  const request = context.request;
  const url = new URL(request.url);

  if (request.method !== 'POST' || !LOCAL_HOSTS.has(url.hostname)) {
    return response(404);
  }
  if (request.headers.get('Origin') !== url.origin) {
    return response(403);
  }

  const headers = new Headers({
    'Cache-Control': 'no-store',
    'Location': '/?shield-demo=' + Date.now(),
    'X-Content-Type-Options': 'nosniff',
  });
  const expired = 'Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax';
  headers.append('Set-Cookie', `__pnx_shield=; ${expired}; HttpOnly`);
  headers.append('Set-Cookie', `__Host-pnx_shield=; ${expired}; Secure; HttpOnly`);
  headers.append('Set-Cookie', `__pnx_shield_ok=; ${expired}`);

  return new Response(null, { status: 303, headers });
}
