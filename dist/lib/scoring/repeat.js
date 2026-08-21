/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Repeat offender tracking
   In-memory, scoped to the running server instance.

   Problem: a scraper that gets a DENY comes back 10, 50, 100 times
   with the same IP+UA in seconds. Each hit was scored independently.
   This module adds a counter: after REPEAT_THRESHOLD denies in the
   window, the IP is marked as a repeat offender and blocked
   pre-emptively.

   Limitations: scoped to one server instance (an attacker rotating
   across instances of a multi-instance deployment is not caught),
   no persistence across restarts. Add a shared store in front of
   this module if that matters for your deployment.
   ═══════════════════════════════════════════════════════════════ */
import { REPEAT_THRESHOLD, REPEAT_WINDOW, REPEAT_BAN } from "../config/defaults.js";
const repeatMap = new Map();
let insertCount = 0;
const EVICTION_INTERVAL = 200;
function evictExpired() {
    const now = Math.floor(Date.now() / 1000);
    for (const [ip, entry] of repeatMap) {
        if (entry.windowReset <= now && entry.bannedUntil <= now) {
            repeatMap.delete(ip);
        }
    }
}
/**
 * Called BEFORE scoring. Pre-emptively checks if the IP is already
 * marked as a repeat offender. If banned=true, the request should be
 * denied without further processing.
 */
export function checkRepeatOffender(ip) {
    if (!ip || typeof ip !== 'string') {
        return { banned: false, count: 0, banRemaining: 0 };
    }
    const now = Math.floor(Date.now() / 1000);
    const entry = repeatMap.get(ip);
    if (!entry) {
        return { banned: false, count: 0, banRemaining: 0 };
    }
    if (entry.bannedUntil > now) {
        return {
            banned: true,
            count: entry.count,
            banRemaining: entry.bannedUntil - now,
        };
    }
    if (entry.windowReset <= now) {
        return { banned: false, count: 0, banRemaining: 0 };
    }
    return { banned: false, count: entry.count, banRemaining: 0 };
}
/**
 * Called when a DENY is actually emitted for this IP. Increments the
 * counter. If the threshold is reached, marks the IP as banned.
 */
export function recordRepeatDeny(ip) {
    if (!ip || typeof ip !== 'string') {
        return { banned: false, count: 0, banRemaining: 0 };
    }
    const now = Math.floor(Date.now() / 1000);
    const existing = repeatMap.get(ip);
    let entry;
    if (!existing || existing.windowReset <= now) {
        entry = {
            count: 1,
            windowReset: now + REPEAT_WINDOW,
            bannedUntil: 0,
        };
    }
    else {
        entry = {
            count: existing.count + 1,
            windowReset: existing.windowReset,
            bannedUntil: existing.bannedUntil,
        };
    }
    if (entry.count >= REPEAT_THRESHOLD) {
        entry.bannedUntil = Math.max(entry.bannedUntil, now + REPEAT_BAN);
    }
    repeatMap.set(ip, entry);
    insertCount++;
    if (insertCount >= EVICTION_INTERVAL) {
        insertCount = 0;
        evictExpired();
    }
    return {
        banned: entry.bannedUntil > now,
        count: entry.count,
        banRemaining: entry.bannedUntil > now ? entry.bannedUntil - now : 0,
    };
}
/** Test-only helper. */
export function __resetRepeatForTest() {
    repeatMap.clear();
    insertCount = 0;
}
export const REPEAT_CONFIG = {
    threshold: REPEAT_THRESHOLD,
    windowSeconds: REPEAT_WINDOW,
    banSeconds: REPEAT_BAN,
};
//# sourceMappingURL=repeat.js.map