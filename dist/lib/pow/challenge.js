import { configureClientIpHeader } from "../config/runtime.js";
import { generateSignedChallenge } from "../core/crypto.js";
import { getInternalCorsHeaders, isAllowedFetchContext, isAllowedOriginOrReferer, isSuspiciousBot, returnInternal404 } from "../http/internal-api.js";
import { buildBadAsns, pickPowMax, scoreRequest } from "../scoring/score.js";
function json(request, data, status) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            ...getInternalCorsHeaders(request, 'GET, OPTIONS'),
            'Cache-Control': 'no-store',
        },
    });
}
export function handleShieldChallengeOptions(request) {
    if (!isAllowedFetchContext(request))
        return returnInternal404(request);
    return new Response(null, {
        status: 204,
        headers: getInternalCorsHeaders(request, 'GET, OPTIONS'),
    });
}
export async function handleShieldChallenge(request, env) {
    configureClientIpHeader(env.SHIELD_CLIENT_IP_HEADER);
    if (request.method !== 'GET' || !isAllowedFetchContext(request))
        return returnInternal404(request);
    if (isSuspiciousBot(request) && !isAllowedOriginOrReferer(request))
        return returnInternal404(request);
    if (env.SHIELD_ENABLED === 'false' || !env.SHIELD_SECRET) {
        return json(request, { error: 'Shield unavailable' }, 503);
    }
    try {
        const scored = scoreRequest(request, { badAsns: buildBadAsns(env.BAD_ASNS_EXTRA) });
        const challenge = await generateSignedChallenge(request, env.SHIELD_SECRET, env.SHIELD_POLICY_VERSION, pickPowMax(scored.weight));
        return json(request, { ok: true, ...challenge }, 200);
    }
    catch {
        const response = json(request, { error: 'Temporary server error' }, 503);
        response.headers.set('Retry-After', '5');
        return response;
    }
}
//# sourceMappingURL=challenge.js.map