export type SinkDecision = 'allow' | 'challenge' | 'deny' | 'ratelimit';
export interface ShieldSinkEvent {
    timestamp: number;
    path: string;
    ipMasked: string;
    uaHash: string;
    asn: string;
    country: string;
    tlsVersion: string;
    score: number;
    decision: SinkDecision;
    signals: string[];
    reason?: string;
    shadowAction?: string;
    shadowReason?: string;
}
export interface ShieldSink {
    /** Write a Shield event. Must not throw; errors are caught by the caller. */
    write(event: ShieldSinkEvent): Promise<void>;
}
export declare const consoleSink: ShieldSink;
/**
 * Build a sink event from a request and partial scoring data.
 * IP is anonymized: only the first two octets (IPv4) or first
 * two groups (IPv6) are kept.
 */
export declare function buildShieldSinkEvent(request: Request, partial: {
    score: number;
    decision: SinkDecision;
    signals: string[];
    reason?: string;
    shadowAction?: string;
    shadowReason?: string;
}): ShieldSinkEvent;
