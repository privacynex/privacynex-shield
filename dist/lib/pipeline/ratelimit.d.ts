export declare const RATE_LIMIT_MAX_ENTRIES = 2048;
export type RateLimitBucket = 'doc' | 'api' | 'verify';
export interface RateLimitResult {
    limited: boolean;
    retryAfter: number;
    count: number;
}
/**
 * Returns `limited: true` when the IP has exceeded the threshold for the bucket
 * in the fixed window. Increments the counter atomically.
 * Caller is responsible for the response (302 / 429 / etc.).
 *
 * Buckets are independent (doc, api and verify have separate counters per IP) so an
 * aggressive scraper on HTML doesn't starve an active user's API calls.
 */
export declare function checkRateLimit(ip: string, bucket?: RateLimitBucket): RateLimitResult;
/** Test-only helper : reset the rate limit map (not used in prod code paths). */
export declare function __resetRateLimitForTest(): void;
export declare function __rateLimitSizeForTest(): number;
/** Config surface for documentation / tuning. */
export declare const RATE_LIMIT_CONFIG: {
    readonly maxRequestsDoc: 30;
    readonly maxRequestsApi: 120;
    readonly maxRequestsVerify: 10;
    readonly windowSeconds: 60;
};
