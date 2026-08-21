import { getClientIp } from "../config/runtime.js";
import { SHIELD_BOT_IP_SNAPSHOT } from "./bot-ip-snapshot.js";
const TRUSTED_CRAWLERS = Object.freeze([
    {
        label: 'Googlebot',
        pattern: /Googlebot(?!-Extended)/i,
        addressesUrl: 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json',
        scope: 'full',
    },
    {
        label: 'Bingbot',
        pattern: /Bingbot/i,
        addressesUrl: 'https://www.bing.com/toolbox/bingbot.json',
        scope: 'full',
    },
    {
        label: 'OAI-SearchBot',
        pattern: /OAI-SearchBot/i,
        addressesUrl: 'https://openai.com/searchbot.json',
        scope: 'full',
    },
    {
        label: 'Claude-SearchBot',
        pattern: /Claude-SearchBot/i,
        addressesUrl: 'https://claude.com/crawling/bots.json',
        scope: 'full',
    },
    {
        label: 'PerplexityBot',
        pattern: /PerplexityBot/i,
        addressesUrl: 'https://www.perplexity.ai/perplexitybot.json',
        scope: 'full',
    },
    {
        label: 'ChatGPT-User',
        pattern: /ChatGPT-User/i,
        addressesUrl: 'https://openai.com/chatgpt-user.json',
        scope: 'content',
    },
    {
        label: 'Claude user fetcher',
        pattern: /Claude-(?:User|Web)/i,
        addressesUrl: 'https://claude.com/crawling/bots.json',
        scope: 'content',
    },
    {
        label: 'DuckAssistBot',
        pattern: /DuckAssistBot/i,
        addressesUrl: 'https://duckduckgo.com/duckassistbot.json',
        scope: 'content',
    },
    {
        label: 'Gemini-Deep-Research',
        pattern: /Gemini-Deep-Research/i,
        addressesUrl: 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json',
        scope: 'content',
    },
]);
const DENY_UA_PATTERNS = Object.freeze([
    'GPTBot', 'ClaudeBot', 'CCBot', 'Bytespider', 'Google-Extended',
    'Applebot-Extended', 'Meta-ExternalAgent', 'meta-externalfetcher',
    'PetalBot', 'Amazonbot', 'cohere-ai', 'DeepSeekBot', 'Diffbot',
    'python-requests/', 'python-urllib/', 'aiohttp/', 'httpx/', 'curl/',
    'wget/', 'libcurl/', 'Go-http-client/', 'Apache-HttpClient/',
    'node-fetch/', 'axios/', 'got/', 'Scrapy/', 'colly/', 'scraperapi',
    'HeadlessChrome', 'PhantomJS', 'Censys', 'Shodan', 'sqlmap', 'nikto',
]);
export const DENY_SIGNALS = Object.freeze([
    'ua:python', 'ua:curl', 'ua:wget', 'ua:libcurl', 'ua:Censys',
    'ua:Shodan', 'ua:sqlmap', 'ua:nikto', 'ua:nmap', 'ua:masscan',
    'ua:gobuster', 'ua:ffuf', 'ua:nuclei', 'ua:Scrapy',
]);
export const HARD_CHALLENGE_SIGNALS = Object.freeze([
    'playwright', 'phantomjs', 'webdriver', 'cdp:automation',
    'selenium:cdc', 'selenium:globals', 'puppeteer',
]);
export const SOFT_CHALLENGE_SIGNALS = Object.freeze([
    'headless:dims', 'coherence:platform-mismatch',
    'coherence:mobile-mismatch', 'coherence:lang-country-mismatch',
]);
export const LOG_ONLY_SIGNALS = Object.freeze([
    'asset-direct-access', 'hidden-api',
]);
export const SENSITIVE_PATHS = Object.freeze([
    '/.env', '/.git', '/.aws', '/.ssh', '/.netrc', '/.npmrc',
    '/wp-config', '/wp-admin', '/wp-login', '/xmlrpc', '/phpmyadmin',
    '/server-status',
]);
export const ADMIN_PATHS = Object.freeze([
    '/api/admin', '/api/auth', '/api/internal', '/api/private', '/admin',
]);
const KEEP_WORKING_PATHS = new Set([
    '/robots.txt',
    '/favicon.ico',
    '/favicon.png',
    '/sitemap.xml',
]);
function trustedRuleFor(ua) {
    return TRUSTED_CRAWLERS.find((rule) => rule.pattern.test(ua)) || null;
}
function pathStartsWithAny(path, prefixes) {
    return prefixes.some((prefix) => path.startsWith(prefix));
}
function isCrawlerPathAllowed(path) {
    const normalized = path.toLowerCase();
    const segments = normalized.split('/').filter(Boolean);
    if (segments.some((segment) => segment.startsWith('.')))
        return false;
    if (segments.some((segment) => segment === 'admin' || segment === 'api'))
        return false;
    return !pathStartsWithAny(normalized, SENSITIVE_PATHS)
        && !pathStartsWithAny(normalized, ADMIN_PATHS);
}
function parseIpv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4)
        return null;
    let value = 0;
    for (const part of parts) {
        const octet = Number(part);
        if (!/^\d{1,3}$/.test(part) || !Number.isInteger(octet) || octet < 0 || octet > 255)
            return null;
        value = ((value << 8) | octet) >>> 0;
    }
    return value;
}
function normalizeIpv6(input) {
    if (!input.includes('.'))
        return input;
    const lastColon = input.lastIndexOf(':');
    if (lastColon === -1)
        return input;
    const ipv4 = parseIpv4(input.slice(lastColon + 1));
    if (ipv4 === null)
        return input;
    const high = ((ipv4 >>> 16) & 0xffff).toString(16);
    const low = (ipv4 & 0xffff).toString(16);
    return input.slice(0, lastColon) + ':' + high + ':' + low;
}
function parseIpv6(ip) {
    const normalized = normalizeIpv6(ip.trim().toLowerCase());
    const parts = normalized.split('::');
    if (parts.length > 2)
        return null;
    const compressed = normalized.includes('::');
    const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
    const right = parts[1] ? parts[1].split(':').filter(Boolean) : [];
    const total = left.length + right.length;
    if ((!compressed && total !== 8) || total > 8)
        return null;
    const groups = [...left, ...Array(compressed ? 8 - total : 0).fill('0'), ...right];
    if (groups.length !== 8)
        return null;
    let value = 0n;
    for (const group of groups) {
        if (!/^[0-9a-f]{1,4}$/i.test(group))
            return null;
        value = (value << 16n) + BigInt(parseInt(group, 16));
    }
    return value;
}
function compileCidr(cidr) {
    const [base, prefixRaw] = cidr.split('/');
    const prefix = Number(prefixRaw);
    if (base.includes(':')) {
        const baseValue = parseIpv6(base);
        if (baseValue === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128)
            return null;
        const shift = 128n - BigInt(prefix);
        return { family: 6, base: baseValue >> shift, maskOrShift: shift };
    }
    const baseValue = parseIpv4(base);
    if (baseValue === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32)
        return null;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return { family: 4, base: baseValue & mask, maskOrShift: mask };
}
function authoritativeClientIp(request) {
    return getClientIp(request);
}
const COMPILED_BOT_IP_SNAPSHOT = new Map(Object.entries(SHIELD_BOT_IP_SNAPSHOT).map(([url, prefixes]) => [
    url,
    Object.freeze(prefixes.map(compileCidr).filter((value) => value !== null)),
]));
const VERIFICATION_CACHE_MAX = 512;
const VERIFICATION_CACHE_TTL_MS = 300_000;
const verificationCache = new Map();
function matchesCompiledIp(ip, prefix) {
    if (prefix.family === 4) {
        const value = parseIpv4(ip);
        const mask = prefix.maskOrShift;
        return value !== null && (value & mask) === prefix.base;
    }
    const value = parseIpv6(ip);
    const shift = prefix.maskOrShift;
    return value !== null && (value >> shift) === prefix.base;
}
function isRuleVerified(request, rule) {
    const clientIp = authoritativeClientIp(request);
    if (!clientIp)
        return false;
    const cacheKey = rule.addressesUrl + '\n' + clientIp;
    const now = Date.now();
    const cached = verificationCache.get(cacheKey);
    if (cached && cached.expiresAt > now)
        return cached.verified;
    const prefixes = COMPILED_BOT_IP_SNAPSHOT.get(rule.addressesUrl) || [];
    const verified = prefixes.some((prefix) => matchesCompiledIp(clientIp, prefix));
    if (verificationCache.size >= VERIFICATION_CACHE_MAX) {
        const oldest = verificationCache.keys().next();
        if (!oldest.done)
            verificationCache.delete(oldest.value);
    }
    verificationCache.set(cacheKey, { expiresAt: now + VERIFICATION_CACHE_TTL_MS, verified });
    return verified;
}
export function detectBlockedBotUA(ua) {
    if (!ua || trustedRuleFor(ua))
        return null;
    return DENY_UA_PATTERNS.find((pattern) => ua.toLowerCase().includes(pattern.toLowerCase())) || null;
}
export function isTrustedShieldBypassRequest(request, path = new URL(request.url).pathname) {
    if (!isCrawlerPathAllowed(path))
        return false;
    const rule = trustedRuleFor(request.headers.get('User-Agent') || '');
    return Boolean(rule && rule.scope === 'full' && isRuleVerified(request, rule));
}
export function isContentBypassRequest(request, path = new URL(request.url).pathname) {
    if (!isCrawlerPathAllowed(path))
        return false;
    const rule = trustedRuleFor(request.headers.get('User-Agent') || '');
    return Boolean(rule && rule.scope === 'content' && isRuleVerified(request, rule));
}
export function isKeepInternetWorkingPath(path) {
    return KEEP_WORKING_PATHS.has(path)
        || path === '/.well-known/security.txt'
        || path === '/.well-known/gpc.json'
        || path.startsWith('/cdn-cgi/');
}
export function listTrustedCrawlerRules() {
    return TRUSTED_CRAWLERS;
}
//# sourceMappingURL=bot-policy.js.map