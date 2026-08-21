interface InternalApiOptions {
    extraOrigins?: string[];
}
export declare function getAllowedOrigins(request: Request, options?: InternalApiOptions): string[];
export declare function extractOrigin(value: string | null): string;
export declare function isAllowedOriginOrReferer(request: Request, options?: InternalApiOptions): boolean;
export declare function isAllowedFetchContext(request: Request, options?: InternalApiOptions): boolean;
export declare function hasBrowserContextSignals(request: Request): boolean;
export declare function isDirectNavigation(request: Request, expectedAccept?: string): boolean;
export declare function isSuspiciousBot(request: Request): boolean;
export declare function getInternalCorsHeaders(request: Request, methods: string, allowHeaders?: string, options?: InternalApiOptions): Record<string, string>;
export declare function returnInternal404(request: Request, expectedAccept?: string): Response;
export {};
