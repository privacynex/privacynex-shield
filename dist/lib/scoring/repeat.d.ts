export interface RepeatResult {
    /** True if the IP is currently marked as a repeat offender. */
    banned: boolean;
    /** Number of denies recorded in the current window. */
    count: number;
    /** Seconds remaining of the ban (0 if not banned). */
    banRemaining: number;
}
/**
 * Called BEFORE scoring. Pre-emptively checks if the IP is already
 * marked as a repeat offender. If banned=true, the request should be
 * denied without further processing.
 */
export declare function checkRepeatOffender(ip: string): RepeatResult;
/**
 * Called when a DENY is actually emitted for this IP. Increments the
 * counter. If the threshold is reached, marks the IP as banned.
 */
export declare function recordRepeatDeny(ip: string): RepeatResult;
/** Test-only helper. */
export declare function __resetRepeatForTest(): void;
export declare const REPEAT_CONFIG: {
    readonly threshold: 3;
    readonly windowSeconds: 3600;
    readonly banSeconds: 3600;
};
