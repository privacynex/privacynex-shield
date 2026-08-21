/**
 * Privacynex Shield
 * Copyright (c) 2026 Slym B.
 * Licensed under the Apache License, Version 2.0
 */
export declare const COOKIE_TTL = 86400;
export declare const CHALLENGE_TTL = 300;
export declare const MAX_NUMBER = 100000;
export declare const MAX_POW_NUMBER = 1000000;
export declare const DEFAULT_POLICY_VERSION = "v1";
export declare function normalizePolicyVersion(input: string | undefined): string;
export declare function hexToBytes(hex: string): Uint8Array<ArrayBuffer>;
export declare function toHex(buffer: ArrayBuffer): string;
export declare function hmacSign(payload: string, secret: string): Promise<string>;
export declare function hmacVerify(payload: string, signature: string, secret: string): Promise<boolean>;
export declare function verifyPoW(salt: string, nonce: number, target: string): Promise<boolean>;
export declare function generateSignedChallenge(request: Request, secret: string, policyVersion?: string, maxNumber?: number): Promise<{
    challengeToken: string;
    salt: string;
    target: string;
    max: number;
    ttl: number;
}>;
export declare function verifySignedChallenge(challengeToken: string, request: Request, secret: string, policyVersion?: string): Promise<{
    salt: string;
    target: string;
    jti: string;
    max: number;
} | null>;
export declare function generateSignedCookie(powHash: string, request: Request, secret: string, policyVersion?: string): Promise<string>;
export declare function verifySignedCookie(cookieValue: string, request: Request, secret: string, policyVersion?: string): Promise<boolean>;
