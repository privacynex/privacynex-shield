/**
 * Set the request header that carries the authoritative client IP for the
 * current platform (e.g. `True-Client-IP` on Fastly, `X-Real-IP` behind a
 * trusted reverse proxy). Defaults to `CF-Connecting-IP`. Call this once
 * before handling requests; an empty or missing value keeps the default.
 */
export declare function configureClientIpHeader(headerName: string | undefined): void;
export declare function getClientIpHeaderName(): string;
export declare function getClientIp(request: Request): string;
