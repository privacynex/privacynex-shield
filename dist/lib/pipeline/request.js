/**
 * Determine whether a request can return an HTML document protected by the Shield.
 *
 * Client-controlled content-negotiation headers are deliberately ignored. A scraper
 * can omit Sec-Fetch-Dest or send a wildcard Accept header; the route and method are the only
 * reliable inputs available before the origin response is read.
 */
export function isShieldDocumentRequest(request, path) {
    if (request.method !== 'GET')
        return false;
    if (path === '/api' || path.startsWith('/api/'))
        return false;
    return true;
}
export function isShieldDocumentResponse(request, path, response) {
    if (!isShieldDocumentRequest(request, path))
        return false;
    const contentType = (response.headers.get('Content-Type') || '').toLowerCase();
    if (!contentType)
        return true;
    return contentType.includes('text/html') || contentType.includes('application/xhtml+xml');
}
/**
 * Convert scoring into an access decision without ever treating a clean score
 * as proof of humanity. Only a verified server-signed cookie can serve content.
 */
export function getShieldDocumentDisposition(action, hasValidCookie) {
    if (action === 'deny')
        return 'deny';
    return hasValidCookie ? 'serve' : 'challenge';
}
//# sourceMappingURL=request.js.map