/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : native rate limiting (doc + api + verify buckets)
   In-memory, scoped to the running server instance. No external
   store required, works on any Fetch API runtime.

   Complements your platform's own WAF rate limiting with an
   application-layer throttle tied to the Shield gate. Mitigates
   automated clients that pass the declared-UA and scoring checks,
   and floods targeting the Shield API routes.
   ═══════════════════════════════════════════════════════════════ */
// Thresholds per bucket :
// - doc : 30 HTML requests per minute per IP (human browsing rarely exceeds this).
// - api : 120 API calls per minute per IP (headroom for normal challenge/verify traffic).
// - verify : 10 PoW submissions per minute per IP.
const RL_MAX_DOC = 30;
const RL_MAX_API = 120;
const RL_MAX_VERIFY = 10;
const RL_WINDOW_SECONDS = 60;
export const RATE_LIMIT_MAX_ENTRIES = 2048;
const rlMap = new Map();
// Opportunistic eviction : every N inserts, prune expired entries.
// Keeps the map bounded without needing setInterval (unavailable in Workers).
let insertCount = 0;
const EVICTION_INTERVAL = 200;
function evictExpired() {
    const now = Math.floor(Date.now() / 1000);
    for (const [ip, entry] of rlMap) {
        if (entry.reset <= now) {
            rlMap.delete(ip);
        }
    }
}
function evictOldest() {
    const oldest = rlMap.keys().next();
    if (!oldest.done)
        rlMap.delete(oldest.value);
}
/**
 * Returns `limited: true` when the IP has exceeded the threshold for the bucket
 * in the fixed window. Increments the counter atomically.
 * Caller is responsible for the response (302 / 429 / etc.).
 *
 * Buckets are independent (doc, api and verify have separate counters per IP) so an
 * aggressive scraper on HTML doesn't starve an active user's API calls.
 */
export function checkRateLimit(ip, bucket = 'doc') {
    if (!ip || typeof ip !== 'string') {
        // Can't identify the client : fail open (don't block anonymous requests
        // on infra errors, WAF layer still protects).
        return { limited: false, retryAfter: 0, count: 0 };
    }
    const max = bucket === 'api'
        ? RL_MAX_API
        : bucket === 'verify'
            ? RL_MAX_VERIFY
            : RL_MAX_DOC;
    const key = bucket + ':' + ip;
    const now = Math.floor(Date.now() / 1000);
    const entry = rlMap.get(key);
    if (!entry || entry.reset <= now) {
        if (!entry && rlMap.size >= RATE_LIMIT_MAX_ENTRIES) {
            evictOldest();
        }
        rlMap.set(key, { count: 1, reset: now + RL_WINDOW_SECONDS });
        insertCount++;
        if (insertCount >= EVICTION_INTERVAL) {
            insertCount = 0;
            evictExpired();
        }
        return { limited: false, retryAfter: 0, count: 1 };
    }
    entry.count++;
    if (entry.count > max) {
        return {
            limited: true,
            retryAfter: entry.reset - now,
            count: entry.count,
        };
    }
    return { limited: false, retryAfter: 0, count: entry.count };
}
/** Test-only helper : reset the rate limit map (not used in prod code paths). */
export function __resetRateLimitForTest() {
    rlMap.clear();
    insertCount = 0;
}
export function __rateLimitSizeForTest() {
    return rlMap.size;
}
/** Config surface for documentation / tuning. */
export const RATE_LIMIT_CONFIG = {
    maxRequestsDoc: RL_MAX_DOC,
    maxRequestsApi: RL_MAX_API,
    maxRequestsVerify: RL_MAX_VERIFY,
    windowSeconds: RL_WINDOW_SECONDS,
};
//# sourceMappingURL=ratelimit.js.map