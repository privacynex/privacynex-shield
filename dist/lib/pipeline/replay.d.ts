/**
 * Returns true if this jti was already consumed (replay).
 * If not yet seen, marks it as spent and returns false.
 */
export declare function markSpentOrReject(jti: string, attemptId: string): {
    replay: boolean;
    idempotent: boolean;
};
/** Test-only helper : reset the spent map (not used in prod code paths). */
export declare function __resetSpentForTest(): void;
