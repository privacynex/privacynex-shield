export interface ShieldEnv {
    SHIELD_ENABLED?: string;
    SHIELD_SECRET?: string;
    SHIELD_POLICY_VERSION?: string;
    SHIELD_DECISION_MODE?: string;
    SHIELD_COHERENCE_ENABLED?: string;
    BAD_ASNS_EXTRA?: string;
    SHIELD_BRAND_NAME?: string;
    SHIELD_LANGUAGE?: string;
    SHIELD_LOGO_PATH?: string;
    SHIELD_WORKER_PATH?: string;
    SHIELD_CLIENT_PATH?: string;
    SHIELD_CLIENT_IP_HEADER?: string;
}
/**
 * Runs the Shield gate for one request. `next` produces the response your
 * app would normally return; Shield decides whether to pass it through,
 * gate it behind a challenge, or block it. Signals sourced from
 * `request.cf` (ASN, country, TLS version, HTTP protocol) are
 * Cloudflare-specific and are skipped gracefully everywhere else.
 */
export declare function shieldFetch(request: Request, env: ShieldEnv, next: () => Promise<Response>): Promise<Response>;
