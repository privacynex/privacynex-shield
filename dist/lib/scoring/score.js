/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Weight-based request scoring
   Pure function, no I/O, no network, no side effects.

   Signals are conservative: tuned to avoid false positives.
   Each signal is documented with its rationale and weight.
   ═══════════════════════════════════════════════════════════════ */
import { detectBlockedBotUA } from "../detection/bot-policy.js";
import { BAD_ASNS_PUBLIC, ICLOUD_RELAY_ASNS, RESIDENTIAL_ASNS_HINT } from "../config/defaults.js";
function getCf(request) {
    // @ts-expect-error : request.cf is Cloudflare-specific
    return request.cf || {};
}
// ─── Bad ASNs : built from defaults + BAD_ASNS_EXTRA env var ───
export function buildBadAsns(extraRaw) {
    const set = new Set(BAD_ASNS_PUBLIC);
    if (extraRaw) {
        extraRaw.split(',')
            .map((s) => parseInt(s.trim(), 10))
            .filter((n) => Number.isSafeInteger(n) && n > 0)
            .forEach((n) => set.add(n));
    }
    return set;
}
// ─── Weights (documented with rationale) ───
const W = {
    /** Deny signal: declared automation and scanner User-Agent patterns. */
    UA_DECLARED_AUTOMATION: 100,
    /** TLS 1.0/1.1: obsolete, used by old automation tools. */
    TLS_OLD: 25,
    /** Cloud/datacenter ASN on document path. */
    ASN_CLOUD: 20,
    /** Modern Chrome without Sec-CH-UA: possible User-Agent inconsistency. */
    SECCHUA_MISSING_MODERN_CHROME: 20,
    /** Tor exit node (country=T1). */
    COUNTRY_TOR: 20,
    /** Missing Accept-Language: weak browser-coherence signal. */
    ACCEPT_LANG_MISSING: 10,
    /** Missing Sec-Fetch-Dest on HTTP/2+: browsers send it. */
    SEC_FETCH_DEST_MISSING_HTTP2: 15,
    /** Suspect Referer: cache proxies, Google Translate. */
    REFERER_SUSPECT: 10,
    /** High TCP RTT (>500ms): weak signal, could be satellite. */
    TCP_RTT_HIGH: 5,
    /** Residential ASN on HTTP/2+: trust boost. */
    RESIDENTIAL_BOOST: -5,
    /** iCloud Private Relay: Apple's privacy proxy. */
    ICLOUD_RELAY_BOOST: -10,
};
// ─── Detect modern Chrome without client hints ───
function isModernChromeUA(ua) {
    const m = ua.match(/Chrome\/(\d+)/);
    if (!m)
        return false;
    return parseInt(m[1], 10) >= 90;
}
// ─── Suspect referer patterns ───
const SUSPECT_REFERER_PATTERNS = [
    'googleusercontent.com',
    'translate.google',
    'webcache.googleusercontent',
];
function hasSuspectReferer(referer) {
    if (!referer)
        return false;
    const lower = referer.toLowerCase();
    return SUSPECT_REFERER_PATTERNS.some((p) => lower.includes(p));
}
// ─── Path kind ───
function isAssetPath(path) {
    return /\.(js|css|svg|png|jpg|jpeg|gif|webp|woff2?|ttf|otf|ico|map|txt|xml|webmanifest|json)$/i.test(path);
}
export function scoreRequest(request, options = {}) {
    const { badAsns } = options;
    const signals = [];
    let weight = 0;
    const ua = request.headers.get('User-Agent') || '';
    const acceptLang = request.headers.get('Accept-Language') || '';
    const secChUa = request.headers.get('Sec-CH-UA') || '';
    const secFetchDest = request.headers.get('Sec-Fetch-Dest') || '';
    const referer = request.headers.get('Referer') || '';
    const url = new URL(request.url);
    const path = url.pathname;
    const isAsset = isAssetPath(path);
    const cf = getCf(request);
    // 1. Declared automation or scanner User-Agent
    const botLabel = detectBlockedBotUA(ua);
    if (botLabel) {
        weight += W.UA_DECLARED_AUTOMATION;
        signals.push('ua:' + botLabel);
    }
    // 2. Old TLS versions
    if (cf.tlsVersion === 'TLSv1' || cf.tlsVersion === 'TLSv1.1') {
        weight += W.TLS_OLD;
        signals.push('tls:old-' + cf.tlsVersion);
    }
    // 3. Cloud ASN on document path (not assets)
    if (!isAsset && typeof cf.asn === 'number' && badAsns && badAsns.has(cf.asn)) {
        weight += W.ASN_CLOUD;
        signals.push('asn:cloud-' + cf.asn);
    }
    // 4. iCloud Private Relay trust boost
    if (typeof cf.asn === 'number' && ICLOUD_RELAY_ASNS.includes(cf.asn)) {
        weight += W.ICLOUD_RELAY_BOOST;
        signals.push('asn:icloud-relay-' + cf.asn);
    }
    // 5. Residential ASN on HTTP/2+ trust boost
    if (typeof cf.asn === 'number' &&
        RESIDENTIAL_ASNS_HINT.includes(cf.asn) &&
        (cf.httpProtocol === 'HTTP/2' || cf.httpProtocol === 'HTTP/3')) {
        weight += W.RESIDENTIAL_BOOST;
        signals.push('asn:residential-' + cf.asn);
    }
    // 6. Tor exit node
    if (cf.country === 'T1') {
        weight += W.COUNTRY_TOR;
        signals.push('country:tor');
    }
    // 7. Modern Chrome UA without client hints (spoofed)
    if (!isAsset && isModernChromeUA(ua) && !secChUa) {
        weight += W.SECCHUA_MISSING_MODERN_CHROME;
        signals.push('hints:chrome-no-secchua');
    }
    // 8. Missing Accept-Language
    if (!isAsset && !acceptLang) {
        weight += W.ACCEPT_LANG_MISSING;
        signals.push('header:no-accept-lang');
    }
    // 9. Missing Sec-Fetch-Dest on HTTP/2+ GET document
    if (!isAsset &&
        request.method === 'GET' &&
        (cf.httpProtocol === 'HTTP/2' || cf.httpProtocol === 'HTTP/3') &&
        !secFetchDest) {
        weight += W.SEC_FETCH_DEST_MISSING_HTTP2;
        signals.push('header:no-sec-fetch-dest');
    }
    // 10. Suspect referer
    if (hasSuspectReferer(referer)) {
        weight += W.REFERER_SUSPECT;
        signals.push('referer:suspect');
    }
    // 11. High TCP RTT (weak signal)
    if (typeof cf.clientTcpRtt === 'number' && cf.clientTcpRtt > 500) {
        weight += W.TCP_RTT_HIGH;
        signals.push('rtt:high');
    }
    return { weight, signals };
}
// ─── Thresholds + difficulty mapping (from config defaults) ───
import { THRESHOLD_PASS, THRESHOLD_CHALLENGE, THRESHOLD_HARD, POW_MAX_EASY, POW_MAX_NORMAL, POW_MAX_HARD, } from "../config/defaults.js";
export { THRESHOLD_PASS, THRESHOLD_CHALLENGE, THRESHOLD_HARD, POW_MAX_EASY, POW_MAX_NORMAL, POW_MAX_HARD, };
/** Pick adaptive PoW max based on weight. */
export function pickPowMax(weight) {
    if (weight < THRESHOLD_PASS)
        return POW_MAX_EASY;
    if (weight < THRESHOLD_CHALLENGE)
        return POW_MAX_NORMAL;
    return POW_MAX_HARD;
}
export function isHighRiskScore(weight) {
    return weight >= THRESHOLD_HARD;
}
//# sourceMappingURL=score.js.map