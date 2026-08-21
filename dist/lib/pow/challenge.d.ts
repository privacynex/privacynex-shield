export interface ChallengeEnv {
    SHIELD_ENABLED?: string;
    SHIELD_SECRET?: string;
    SHIELD_POLICY_VERSION?: string;
    BAD_ASNS_EXTRA?: string;
    SHIELD_CLIENT_IP_HEADER?: string;
}
export declare function handleShieldChallengeOptions(request: Request): Response;
export declare function handleShieldChallenge(request: Request, env: ChallengeEnv): Promise<Response>;
