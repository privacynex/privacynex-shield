/**
 * Returns true if this (IP, reason) pair should be dispatched.
 * Returns false if it was already dispatched within 5 minutes.
 */
export declare function shouldDispatchAlert(ip: string, reason: string): boolean;
/** Test-only helper. */
export declare function __resetDedupForTest(): void;
