/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Header coherence checks
   Cross-checks UA against Sec-CH-UA headers.
   Flags mismatches as scoring signals.
   Opt-in, shadow mode for tuning before activation.
   ═══════════════════════════════════════════════════════════════ */

export interface CoherenceResult {
  weight: number;
  signals: string[];
}

// ─── Weight constants ───

const W = {
  PLATFORM_MISMATCH: 25,
  MOBILE_MISMATCH: 20,
  LANG_COUNTRY_MISMATCH: 15,
  UA_OS_STALE: 10,
};

// ─── Helpers ───

function extractSecChUaPlatform(secChUaPlatform: string): string {
  if (!secChUaPlatform) return '';
  const cleaned = secChUaPlatform.replace(/^"+|"+$/g, '').trim();
  return cleaned.toLowerCase();
}

function extractSecChUaMobile(secChUaMobile: string): string | null {
  if (!secChUaMobile) return null;
  const cleaned = secChUaMobile.replace(/^"+|"+$/g, '').trim();
  return cleaned === '?1' || cleaned === '?0' ? cleaned : null;
}

// Match platform from UA against Sec-CH-UA-Platform.
// Detects: UA claims Windows but Sec-CH-UA-Platform says macOS (spoofed UA).

function checkPlatform(ua: string, secChUaPlatform: string): string | null {
  if (!ua || !secChUaPlatform) return null;
  const platform = extractSecChUaPlatform(secChUaPlatform);
  if (!platform) return null;

  const uaLower = ua.toLowerCase();
  let uaPlatform: string | null = null;

  if (uaLower.includes('windows nt') || uaLower.includes('win64') || uaLower.includes('win32')) {
    uaPlatform = 'windows';
  } else if (uaLower.includes('macintosh') || uaLower.includes('mac os x')) {
    uaPlatform = 'macos';
  } else if (uaLower.includes('linux')) {
    uaPlatform = 'linux';
  } else if (uaLower.includes('android')) {
    uaPlatform = 'android';
  } else if (uaLower.includes('iphone') || uaLower.includes('ipad') || uaLower.includes('ipod')) {
    uaPlatform = 'ios';
  }

  if (!uaPlatform) return null;

  // Direct match
  if (platform === uaPlatform) return null;
  // "macos" in Sec-CH-UA-Platform vs "macintosh" in UA
  if (platform === 'macos' && uaPlatform === 'macos') return null;
  // "linux" covers both
  if (platform === 'linux' && uaPlatform === 'linux') return null;

  return `coherence:platform-mismatch:ua-${uaPlatform}:hint-${platform}`;
}

// Check ?1/?0 mismatch between UA and Sec-CH-UA-Mobile.

function checkMobile(ua: string, secChUaMobile: string): string | null {
  if (!ua || !secChUaMobile) return null;
  const mobile = extractSecChUaMobile(secChUaMobile);
  if (!mobile) return null;

  const uaLower = ua.toLowerCase();
  const uaIsMobile = uaLower.includes('android') || uaLower.includes('iphone') || uaLower.includes('mobile');
  const hintIsMobile = mobile === '?1';

  if (uaIsMobile !== hintIsMobile) {
    return `coherence:mobile-mismatch:ua-${uaIsMobile ? 'mobile' : 'desktop'}:hint-${hintIsMobile ? 'mobile' : 'desktop'}`;
  }

  return null;
}

// Check language-to-country coherence.

function checkLangCountry(acceptLang: string, country: string): string | null {
  if (!acceptLang || !country || country === 'XX' || country === 'T1') return null;

  const primaryLang = acceptLang.split(',')[0].trim().toLowerCase().slice(0, 2);
  if (primaryLang.length !== 2) return null;

  // Common language-to-country mismatches that indicate suspicious traffic.
  // A user with Accept-Language: zh-CN connecting from France is unusual
  // but not impossible (tourist, expat). Signal weight is modest (15).

  const languageToExpectedCountries: Record<string, string[]> = {
    'zh': ['CN', 'TW', 'HK', 'SG', 'MO'],
    'ja': ['JP'],
    'ko': ['KR', 'KP'],
    'ru': ['RU', 'UA', 'BY', 'KZ', 'KG', 'UZ'],
    'ar': ['SA', 'AE', 'EG', 'DZ', 'MA', 'IQ', 'JO', 'LB', 'KW', 'QA', 'BH', 'OM'],
    'fa': ['IR', 'AF'],
    'vi': ['VN'],
    'th': ['TH'],
    'hi': ['IN'],
    'bn': ['BD', 'IN'],
    'ur': ['PK', 'IN'],
    'id': ['ID'],
    'ms': ['MY', 'ID'],
    'tl': ['PH'],
    'tr': ['TR'],
    'uk': ['UA'],
    'kk': ['KZ'],
    'uz': ['UZ'],
    'az': ['AZ'],
    'ka': ['GE'],
    'hy': ['AM'],
    'he': ['IL'],
    'ta': ['IN', 'LK', 'SG'],
    'te': ['IN'],
    'mr': ['IN'],
    'pa': ['IN', 'PK'],
    'gu': ['IN'],
  };

  const expectedCountries = languageToExpectedCountries[primaryLang];
  if (!expectedCountries) return null;

  if (!expectedCountries.includes(country.toUpperCase())) {
    return `coherence:lang-country-mismatch:${primaryLang}:${country}`;
  }

  return null;
}

// Check if the browser OS version in UA seems stale relative to current releases.
// Weak signal (weight 10): browsers auto-update, but some bots pin old versions.

function checkUaOsStale(ua: string): string | null {
  if (!ua) return null;
  const uaLower = ua.toLowerCase();

  // Firefox < 100 on modern OS is suspicious (Firefox auto-updates aggressively).
  const firefoxMatch = uaLower.match(/firefox\/(\d+)/);
  if (firefoxMatch) {
    const v = parseInt(firefoxMatch[1], 10);
    if (v < 100) return 'coherence:ua-os-stale:firefox-old';
  }

  return null;
}

// ─── Main coherence scoring ───

interface CfLike {
  country?: string;
}

function getCf(request: Request): CfLike {
  // @ts-expect-error : request.cf is Cloudflare-specific
  return request.cf || {};
}

/**
 * Run all coherence checks against the request.
 * Returns signals and their combined weight.
 * Callers decide whether to add these weights to the main score.
 */
export function scoreCoherence(request: Request): CoherenceResult {
  const signals: string[] = [];
  let weight = 0;

  const ua = request.headers.get('User-Agent') || '';
  const secChUaPlatform = request.headers.get('Sec-CH-UA-Platform') || '';
  const secChUaMobile = request.headers.get('Sec-CH-UA-Mobile') || '';
  const acceptLang = request.headers.get('Accept-Language') || '';

  const cf = getCf(request);
  const country = cf.country || '';

  // 1. Platform mismatch
  const platformSignal = checkPlatform(ua, secChUaPlatform);
  if (platformSignal) {
    weight += W.PLATFORM_MISMATCH;
    signals.push(platformSignal);
  }

  // 2. Mobile mismatch
  const mobileSignal = checkMobile(ua, secChUaMobile);
  if (mobileSignal) {
    weight += W.MOBILE_MISMATCH;
    signals.push(mobileSignal);
  }

  // 3. Language-to-country mismatch
  const langSignal = checkLangCountry(acceptLang, country);
  if (langSignal) {
    weight += W.LANG_COUNTRY_MISMATCH;
    signals.push(langSignal);
  }

  // 4. Browser OS version stale
  const staleSignal = checkUaOsStale(ua);
  if (staleSignal) {
    weight += W.UA_OS_STALE;
    signals.push(staleSignal);
  }

  return { weight, signals };
}
