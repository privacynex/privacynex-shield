export interface VerifyEnv {
    SHIELD_ENABLED?: string;
    SHIELD_SECRET?: string;
    SHIELD_POLICY_VERSION?: string;
    SHIELD_CLIENT_IP_HEADER?: string;
}
export declare function handleShieldVerifyOptions(request: Request): Response;
export declare function handleShieldVerify(request: Request, env: VerifyEnv): Promise<Response>;
