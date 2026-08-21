/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Challenge replay prevention (spent flag)
   In-memory, scoped to the running server instance. No external
   store required.

   Each challenge token can be verified only once. A replay attacker
   hitting the same server instance gets a 403. Replaying against a
   different instance of a multi-instance deployment remains
   theoretically possible but is deterred by rate limiting and the
   short challenge lifetime; see the README for adding a shared store
   if that residual risk matters to your deployment.
   ═══════════════════════════════════════════════════════════════ */
import { CHALLENGE_TTL } from "../core/crypto.js";
// jti → tentative ayant consommé le challenge + expiration.
const spentJti = new Map();
// Opportunistic eviction : every N inserts, prune expired entries.
// Keeps the map bounded without needing setInterval (unavailable in Workers).
let insertCount = 0;
const EVICTION_INTERVAL = 100;
function evictExpired() {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, entry] of spentJti) {
        if (entry.expiry <= now) {
            spentJti.delete(jti);
        }
    }
}
/**
 * Returns true if this jti was already consumed (replay).
 * If not yet seen, marks it as spent and returns false.
 */
export function markSpentOrReject(jti, attemptId) {
    if (!jti || typeof jti !== 'string' || jti.length < 8 || !attemptId) {
        // Invalid jti format : treat as replay to fail closed.
        return { replay: true, idempotent: false };
    }
    const now = Math.floor(Date.now() / 1000);
    const existing = spentJti.get(jti);
    if (existing !== undefined && existing.expiry > now) {
        return { replay: true, idempotent: false };
    }
    spentJti.set(jti, { expiry: now + CHALLENGE_TTL });
    insertCount++;
    if (insertCount >= EVICTION_INTERVAL) {
        insertCount = 0;
        evictExpired();
    }
    return { replay: false, idempotent: false };
}
/** Test-only helper : reset the spent map (not used in prod code paths). */
export function __resetSpentForTest() {
    spentJti.clear();
    insertCount = 0;
}
//# sourceMappingURL=replay.js.map