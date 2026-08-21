/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Alert dedup
   In-memory dedup of (IP, reason) pairs, scoped to the running
   server instance. Skips duplicate alerts within 5 minutes to
   avoid flooding your alert sink under sustained attack.

   Example: 1000 req/s from the same attacker with the same reason
   = 1 alert recorded instead of 1000.
   ═══════════════════════════════════════════════════════════════ */

const DEDUP_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface DedupEntry {
  reason: string;
  timestamp: number;
}

const dedupMap = new Map<string, DedupEntry>();

let dedupInsertCount = 0;
const DEDUP_EVICTION_INTERVAL = 200;

function evictExpiredDedup(): void {
  const now = Date.now();
  for (const [key, entry] of dedupMap) {
    if (now - entry.timestamp > DEDUP_TTL_MS) {
      dedupMap.delete(key);
    }
  }
}

/**
 * Returns true if this (IP, reason) pair should be dispatched.
 * Returns false if it was already dispatched within 5 minutes.
 */
export function shouldDispatchAlert(ip: string, reason: string): boolean {
  if (!ip || !reason) return false;

  const key = ip + ':' + reason;
  const now = Date.now();
  const existing = dedupMap.get(key);

  if (existing && now - existing.timestamp < DEDUP_TTL_MS) {
    return false;
  }

  dedupMap.set(key, { reason, timestamp: now });

  dedupInsertCount++;
  if (dedupInsertCount >= DEDUP_EVICTION_INTERVAL) {
    dedupInsertCount = 0;
    evictExpiredDedup();
  }

  return true;
}

/** Test-only helper. */
export function __resetDedupForTest(): void {
  dedupMap.clear();
  dedupInsertCount = 0;
}
