/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : request gate
   Pure Fetch API function: takes a Request/Env, produces a Response.
   It has no Cloudflare Pages import. Platform adapters remain
   responsible for routing and trusted request metadata.
   ═══════════════════════════════════════════════════════════════ */

import { configureClientIpHeader, getClientIp } from '../config/runtime.ts';
import { generateSignedChallenge, verifySignedCookie } from '../core/crypto.ts';
import { decideMultiLevel, getDecisionMode } from '../decision/engine.ts';
import {
  detectBlockedBotUA,
  isContentBypassRequest,
  isKeepInternetWorkingPath,
  isTrustedShieldBypassRequest,
} from '../detection/bot-policy.ts';
import { scoreCoherence } from '../detection/coherence.ts';
import { checkRateLimit } from './ratelimit.ts';
import { isShieldDocumentRequest, isShieldDocumentResponse } from './request.ts';
import { buildBadAsns, pickPowMax, scoreRequest } from '../scoring/score.ts';

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

function resolveRateLimit(request: Request, bucket: 'document' | 'api'): { limited: boolean } {
  const ip = getClientIp(request);
  const localBucket = bucket === 'document' ? 'doc' : 'api';
  return { limited: checkRateLimit(ip, localBucket).limited };
}

const DEFAULT_CLIENT_PATH = '/pnx-shield/shield.js';
const DEFAULT_WORKER_PATH = '/pnx-shield/pow-worker.js';
const SAFE_ASSET_PATH = /^\/[a-zA-Z0-9/_-]+\.(?:js|png|jpg|jpeg|svg|webp)$/;

function safeAssetPath(value: string | undefined, fallback: string): string {
  return value && value.length <= 200 && SAFE_ASSET_PATH.test(value) ? value : fallback;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char] || char);
}

function brandName(value: string | undefined): string {
  if (!value) return 'Protected site';
  return value.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 80) || 'Protected site';
}

function cookieName(request: Request): string {
  return new URL(request.url).protocol === 'https:' ? '__Host-pnx_shield' : '__pnx_shield';
}

function cookieValue(request: Request): string | null {
  const name = cookieName(request).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = (request.headers.get('Cookie') || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;\\s]+)`));
  return match ? match[1] : null;
}

function blockedResponse(): Response {
  return new Response('Access denied', {
    status: 403,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function unavailableResponse(): Response {
  return new Response('Shield temporarily unavailable', {
    status: 503,
    headers: { 'Cache-Control': 'no-store', 'Retry-After': '5' },
  });
}

interface EmbeddedChallenge {
  challengeToken: string;
  salt: string;
  target: string;
  max: number;
}

function challengePage(env: ShieldEnv, challenge: EmbeddedChallenge): Response {
  const clientPath = safeAssetPath(env.SHIELD_CLIENT_PATH, DEFAULT_CLIENT_PATH);
  const workerPath = safeAssetPath(env.SHIELD_WORKER_PATH, DEFAULT_WORKER_PATH);
  const logoPath = safeAssetPath(env.SHIELD_LOGO_PATH, '');
  const brand = brandName(env.SHIELD_BRAND_NAME);
  const language = ['fr', 'en', 'es', 'de'].includes(env.SHIELD_LANGUAGE || '')
    ? env.SHIELD_LANGUAGE as string
    : 'en';
  const attributes = [
    'data-shield-active="true"',
    `data-shield-brand="${escapeHtml(brand)}"`,
    `data-shield-worker="${escapeHtml(workerPath)}"`,
    `data-shield-challenge-token="${escapeHtml(challenge.challengeToken)}"`,
    `data-shield-salt="${challenge.salt}"`,
    `data-shield-target="${challenge.target}"`,
    `data-shield-max="${challenge.max}"`,
    logoPath ? `data-shield-logo="${escapeHtml(logoPath)}"` : '',
  ].filter(Boolean).join(' ');
  const clientUrl = clientPath + '?challenge=' + challenge.salt;
  const html = `<!doctype html><html lang="${language}" data-lang="${language}" ${attributes}><head>`
    + '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<meta name="robots" content="noindex,nofollow">'
    + `<title>${escapeHtml(brand)} security check</title>`
    + `<script src="${escapeHtml(clientUrl)}" defer></script>`
    + '</head><body></body></html>';

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    },
  });
}

/**
 * Runs the Shield gate for one request. `next` produces the response your
 * app would normally return; Shield decides whether to pass it through,
 * gate it behind a challenge, or block it. Signals sourced from
 * `request.cf` (ASN, country, TLS version, HTTP protocol) are
 * Cloudflare-specific and are skipped gracefully everywhere else.
 */
export async function shieldFetch(request: Request, env: ShieldEnv, next: () => Promise<Response>): Promise<Response> {
  configureClientIpHeader(env.SHIELD_CLIENT_IP_HEADER);
  if (env.SHIELD_ENABLED === 'false') return next();
  if (!env.SHIELD_SECRET) return unavailableResponse();

  const url = new URL(request.url);
  const path = url.pathname;
  if (isKeepInternetWorkingPath(path)) return next();

  const blockedBot = detectBlockedBotUA(request.headers.get('User-Agent') || '');
  if (blockedBot) return blockedResponse();

  if (path.startsWith('/api/')) {
    if (resolveRateLimit(request, 'api').limited) return blockedResponse();
    return next();
  }

  if (!isShieldDocumentRequest(request, path)) return next();
  const downstream = await next();
  if (!isShieldDocumentResponse(request, path, downstream)) return downstream;

  if (resolveRateLimit(request, 'document').limited) return blockedResponse();

  const scored = scoreRequest(request, { badAsns: buildBadAsns(env.BAD_ASNS_EXTRA) });
  if (env.SHIELD_COHERENCE_ENABLED === '1') {
    const coherence = scoreCoherence(request);
    scored.weight += coherence.weight;
    scored.signals.push(...coherence.signals);
  }

  const mode = getDecisionMode(env);
  const decision = decideMultiLevel({ score: scored.weight, signals: scored.signals, path });
  if (decision.action === 'deny') return blockedResponse();
  if (
    isTrustedShieldBypassRequest(request, path)
    || isContentBypassRequest(request, path)
  ) {
    return downstream;
  }

  const existingCookie = cookieValue(request);
  const validCookie = existingCookie
    ? await verifySignedCookie(existingCookie, request, env.SHIELD_SECRET, env.SHIELD_POLICY_VERSION)
    : false;
  if (validCookie) return downstream;

  const max = mode === 'multi' && decision.action === 'hard-challenge'
    ? 400000
    : pickPowMax(scored.weight);
  try {
    const challenge = await generateSignedChallenge(
      request,
      env.SHIELD_SECRET,
      env.SHIELD_POLICY_VERSION,
      max,
    );
    return challengePage(env, challenge);
  } catch {
    return unavailableResponse();
  }
}
