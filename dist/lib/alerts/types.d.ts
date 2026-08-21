export interface ShieldMailer {
    sendEmail(params: {
        to: string;
        subject: string;
        html: string;
    }): Promise<{
        ok: boolean;
        error?: string;
    }>;
}
export interface ShieldAlertEnv {
    SHIELD_ALERTS?: unknown;
    SHIELD_ALERTS_ENABLED?: string;
    SHIELD_ALERT_TO_EMAIL?: string;
    SHIELD_ALERT_SUBJECT_PREFIX?: string;
    SHIELD_ALERT_BUCKET_HOURS?: string;
}
export interface ShieldAlertEvent {
    timestamp: number;
    source: 'server' | 'client';
    reason: string;
    path: string;
    ip: string;
    uaHash: string;
    asn: string;
    country: string;
}
export declare function buildShieldAlertEvent(request: Request, source: 'server' | 'client', reason: string): ShieldAlertEvent;
export declare function normalizeShieldReason(raw: string | null, fallback: string): string;
export declare function recordShieldAlert(env: ShieldAlertEnv, mailer: ShieldMailer | null, event: ShieldAlertEvent): Promise<void>;
