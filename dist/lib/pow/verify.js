import { configureClientIpHeader, getClientIp } from "../config/runtime.js";
import { CHALLENGE_TTL, COOKIE_TTL, MAX_POW_NUMBER, generateSignedCookie, verifyPoW, verifySignedChallenge } from "../core/crypto.js";
import { getInternalCorsHeaders, isAllowedFetchContext, isAllowedOriginOrReferer, isSuspiciousBot, returnInternal404 } from "../http/internal-api.js";
import { readBoundedJson, RequestBodyError } from "../http/request-body.js";
import { checkRateLimit, RATE_LIMIT_CONFIG } from "../pipeline/ratelimit.js";
import { markSpentOrReject } from "../pipeline/replay.js";
function json(request, data, status) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            ...getInternalCorsHeaders(request, 'POST, OPTIONS'),
            'Cache-Control': 'no-store',
        },
    });
}
function isValidNonce(value) {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_POW_NUMBER;
}
function isValidChallengeToken(value) {
    return typeof value === 'string' && value.length >= 128 && value.length <= 1024;
}
function verifyRateLimit(request) {
    const ip = getClientIp(request) || 'unknown';
    return checkRateLimit(ip, 'verify').limited ? 'limited' : 'ok';
}
function cookieHeaders(request, value) {
    const secure = new URL(request.url).protocol === 'https:';
    const secureAttribute = secure ? '; Secure' : '';
    const cookieName = secure ? '__Host-pnx_shield' : '__pnx_shield';
    const now = Math.floor(Date.now() / 1000);
    return [
        `${cookieName}=${value}; HttpOnly${secureAttribute}; SameSite=Lax; Path=/; Max-Age=${COOKIE_TTL}`,
        `__pnx_shield_ok=${now}${secureAttribute}; SameSite=Lax; Path=/; Max-Age=${COOKIE_TTL}`,
    ];
}
export function handleShieldVerifyOptions(request) {
    if (!isAllowedFetchContext(request))
        return returnInternal404(request);
    return new Response(null, {
        status: 204,
        headers: getInternalCorsHeaders(request, 'POST, OPTIONS'),
    });
}
export async function handleShieldVerify(request, env) {
    configureClientIpHeader(env.SHIELD_CLIENT_IP_HEADER);
    if (request.method !== 'POST' || !isAllowedFetchContext(request))
        return returnInternal404(request);
    if (isSuspiciousBot(request) && !isAllowedOriginOrReferer(request))
        return returnInternal404(request);
    if (env.SHIELD_ENABLED === 'false' || !env.SHIELD_SECRET) {
        return json(request, { error: 'Shield unavailable' }, 503);
    }
    if (verifyRateLimit(request) === 'limited') {
        const response = json(request, { error: 'Rate limited' }, 429);
        response.headers.set('Retry-After', String(RATE_LIMIT_CONFIG.windowSeconds));
        return response;
    }
    if (!(request.headers.get('Content-Type') || '').toLowerCase().startsWith('application/json')) {
        return json(request, { error: 'Invalid content type' }, 400);
    }
    let body;
    try {
        body = await readBoundedJson(request, 2048);
    }
    catch (error) {
        const status = error instanceof RequestBodyError ? error.status : 400;
        return json(request, { error: status === 413 ? 'Payload too large' : 'Invalid JSON' }, status);
    }
    const { challengeToken, nonce } = body;
    if (!isValidChallengeToken(challengeToken))
        return json(request, { error: 'Missing challenge token' }, 400);
    if (!isValidNonce(nonce))
        return json(request, { error: 'Invalid nonce' }, 400);
    try {
        const verified = await verifySignedChallenge(challengeToken, request, env.SHIELD_SECRET, env.SHIELD_POLICY_VERSION);
        if (!verified)
            return json(request, { error: 'Invalid challenge token' }, 403);
        if (nonce > verified.max)
            return json(request, { error: 'Nonce outside signed challenge range' }, 403);
        if (!(await verifyPoW(verified.salt, nonce, verified.target))) {
            return json(request, { error: 'Invalid proof of work' }, 403);
        }
        const signedCookie = await generateSignedCookie(verified.target, request, env.SHIELD_SECRET, env.SHIELD_POLICY_VERSION);
        const spent = markSpentOrReject(verified.jti, `${verified.jti}.${nonce}`);
        if (spent.replay)
            return json(request, { error: 'Challenge already consumed' }, 403);
        const response = json(request, { ok: true, ttl: COOKIE_TTL, challengeTtl: CHALLENGE_TTL }, 200);
        for (const header of cookieHeaders(request, signedCookie))
            response.headers.append('Set-Cookie', header);
        return response;
    }
    catch {
        const response = json(request, { error: 'Temporary server error' }, 503);
        response.headers.set('Retry-After', '5');
        return response;
    }
}
//# sourceMappingURL=verify.js.map