type ShieldDocumentAction = 'allow' | 'log' | 'soft-challenge' | 'hard-challenge' | 'deny';
export type ShieldDocumentDisposition = 'serve' | 'challenge' | 'deny';
/**
 * Determine whether a request can return an HTML document protected by the Shield.
 *
 * Client-controlled content-negotiation headers are deliberately ignored. A scraper
 * can omit Sec-Fetch-Dest or send a wildcard Accept header; the route and method are the only
 * reliable inputs available before the origin response is read.
 */
export declare function isShieldDocumentRequest(request: Request, path: string): boolean;
export declare function isShieldDocumentResponse(request: Request, path: string, response: Response): boolean;
/**
 * Convert scoring into an access decision without ever treating a clean score
 * as proof of humanity. Only a verified server-signed cookie can serve content.
 */
export declare function getShieldDocumentDisposition(action: ShieldDocumentAction, hasValidCookie: boolean): ShieldDocumentDisposition;
export {};
