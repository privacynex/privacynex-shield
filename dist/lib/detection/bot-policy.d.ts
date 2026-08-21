export type CrawlerScope = 'full' | 'content';
interface TrustedCrawlerRule {
    readonly label: string;
    readonly pattern: RegExp;
    readonly addressesUrl: string;
    readonly scope: CrawlerScope;
}
export declare const DENY_SIGNALS: readonly string[];
export declare const HARD_CHALLENGE_SIGNALS: readonly string[];
export declare const SOFT_CHALLENGE_SIGNALS: readonly string[];
export declare const LOG_ONLY_SIGNALS: readonly string[];
export declare const SENSITIVE_PATHS: readonly string[];
export declare const ADMIN_PATHS: readonly string[];
export declare function detectBlockedBotUA(ua: string): string | null;
export declare function isTrustedShieldBypassRequest(request: Request, path?: string): boolean;
export declare function isContentBypassRequest(request: Request, path?: string): boolean;
export declare function isKeepInternetWorkingPath(path: string): boolean;
export declare function listTrustedCrawlerRules(): readonly TrustedCrawlerRule[];
export {};
