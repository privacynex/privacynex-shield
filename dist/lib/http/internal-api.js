const DEFAULT_LOCAL_ORIGINS = [
    'http://localhost:8788',
    'http://127.0.0.1:8788',
    'http://localhost:8791',
    'http://127.0.0.1:8791',
];
export function getAllowedOrigins(request, options = {}) {
    const url = new URL(request.url);
    const host = url.hostname.toLowerCase();
    const canonicalHost = host.startsWith('www.') ? host.slice(4) : host;
    const origins = [...DEFAULT_LOCAL_ORIGINS, ...(options.extraOrigins || [])];
    if (canonicalHost !== 'localhost' && canonicalHost !== '127.0.0.1') {
        origins.push(`https://${canonicalHost}`);
        if (!canonicalHost.endsWith('.pages.dev')) {
            origins.push(`https://www.${canonicalHost}`);
        }
    }
    return Array.from(new Set(origins));
}
export function extractOrigin(value) {
    if (!value)
        return '';
    try {
        return new URL(value).origin;
    }
    catch {
        return '';
    }
}
export function isAllowedOriginOrReferer(request, options = {}) {
    const allowed = getAllowedOrigins(request, options);
    const origin = request.headers.get('Origin');
    const referer = request.headers.get('Referer');
    if (origin && allowed.includes(origin))
        return true;
    const refererOrigin = extractOrigin(referer);
    if (refererOrigin && allowed.includes(refererOrigin))
        return true;
    return false;
}
export function isAllowedFetchContext(request, options = {}) {
    const secFetchMode = request.headers.get('Sec-Fetch-Mode');
    const secFetchDest = request.headers.get('Sec-Fetch-Dest');
    const accept = request.headers.get('Accept') || '';
    // Reject direct browser navigation even from same origin :
    // - Sec-Fetch-Mode/Dest : signaux modernes
    // - Accept text/html sans application/json : repli si la plateforme/le proxy retire les en-têtes Sec-Fetch
    if (secFetchMode === 'navigate' || secFetchDest === 'document') {
        return false;
    }
    if (accept.includes('text/html') && !accept.includes('application/json')) {
        return false;
    }
    const secFetchSite = request.headers.get('Sec-Fetch-Site');
    if (secFetchSite === 'same-origin' || secFetchSite === 'same-site') {
        return true;
    }
    return isAllowedOriginOrReferer(request, options);
}
export function hasBrowserContextSignals(request) {
    return Boolean(request.headers.get('Sec-Fetch-Site') ||
        request.headers.get('Sec-Fetch-Mode') ||
        request.headers.get('Sec-Fetch-Dest') ||
        request.headers.get('Origin') ||
        request.headers.get('Referer'));
}
export function isDirectNavigation(request, expectedAccept = 'application/json') {
    const secFetchMode = request.headers.get('Sec-Fetch-Mode');
    const secFetchDest = request.headers.get('Sec-Fetch-Dest');
    const accept = request.headers.get('Accept') || '';
    return (secFetchMode === 'navigate' ||
        secFetchDest === 'document' ||
        (accept.includes('text/html') && !accept.includes(expectedAccept)));
}
export function isSuspiciousBot(request) {
    const ua = request.headers.get('User-Agent') || '';
    return /bot|crawler|spider|scraper|curl|wget|python|postman|insomnia|axios|node-fetch|got\/|httpie/i.test(ua);
}
export function getInternalCorsHeaders(request, methods, allowHeaders = 'Content-Type', options = {}) {
    const origin = request.headers.get('Origin') || '';
    const allowedOrigin = getAllowedOrigins(request, options).includes(origin) ? origin : '';
    return {
        'Content-Type': 'application/json; charset=utf-8',
        ...(allowedOrigin ? { 'Access-Control-Allow-Origin': allowedOrigin } : {}),
        'Access-Control-Allow-Methods': methods,
        'Access-Control-Allow-Headers': allowHeaders,
        'Access-Control-Max-Age': '86400',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        Vary: 'Origin, Referer, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Accept',
    };
}
export function returnInternal404(request, expectedAccept = 'application/json') {
    if (isDirectNavigation(request, expectedAccept)) {
        return Response.redirect(new URL('/404', request.url).toString(), 302);
    }
    return new Response('Not Found', {
        status: 404,
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
        },
    });
}
//# sourceMappingURL=internal-api.js.map