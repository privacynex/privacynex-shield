/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Pluggable email alert interface
   Provider-agnostic. Implement sendEmail() for any mailer.

   Alerts aggregate into KV buckets (configurable window) and
   flush as a single summary email to reduce repeated notifications
   during an attack.
   ═══════════════════════════════════════════════════════════════ */

import { getClientIp } from '../config/runtime.ts';

// ─── Types ───

export interface ShieldMailer {
  sendEmail(params: { to: string; subject: string; html: string }): Promise<{ ok: boolean; error?: string }>;
}

export interface ShieldAlertEnv {
  SHIELD_ALERTS?: unknown; // KV namespace binding
  SHIELD_ALERTS_ENABLED?: string;
  SHIELD_ALERT_TO_EMAIL?: string;
  SHIELD_ALERT_SUBJECT_PREFIX?: string;
  SHIELD_ALERT_BUCKET_HOURS?: string;
}

export interface ShieldAlertEvent {
  timestamp: number;
  source: 'server' | 'client';
  reason: string;
  path: string;
  ip: string;
  uaHash: string;
  asn: string;
  country: string;
}

// ─── Alert builder ───

function maskIp(ip: string): string {
  if (!ip) return 'unknown';
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.slice(0, 2).join(':') + ':xxxx:xxxx:xxxx:xxxx';
  }
  const parts = ip.split('.');
  return parts.slice(0, 2).join('.') + '.xxx.xxx';
}

export function buildShieldAlertEvent(
  request: Request,
  source: 'server' | 'client',
  reason: string,
): ShieldAlertEvent {
  const url = new URL(request.url);
  const ua = request.headers.get('User-Agent') || '';
  const ip = getClientIp(request);

  // @ts-expect-error : request.cf is Cloudflare-specific
  const cf = request.cf || {};

  let hash = 0;
  for (let i = 0; i < ua.length; i++) {
    hash = ((hash << 5) - hash) + ua.charCodeAt(i);
    hash = hash & hash;
  }

  return {
    timestamp: Date.now(),
    source,
    reason,
    path: url.pathname,
    ip: maskIp(ip),
    uaHash: Math.abs(hash).toString(16).padStart(8, '0'),
    asn: String(cf.asn || ''),
    country: cf.country || '',
  };
}

export function normalizeShieldReason(
  raw: string | null,
  fallback: string,
): string {
  if (!raw || typeof raw !== 'string') return fallback;
  return raw.substring(0, 100);
}

// ─── Reference implementation (placeholder) ───
// Operators implement their own recordShieldAlert that uses their
// specific KV binding and mailer. The interface is documented at
// the top of this file.

export async function recordShieldAlert(
  env: ShieldAlertEnv,
  mailer: ShieldMailer | null,
  event: ShieldAlertEvent,
): Promise<void> {
  // Placeholder: log the alert to console.
  // Replace with your own aggregation + email logic.
  console.log('[SHIELD][ALERT]', JSON.stringify(event));

  if (mailer && env.SHIELD_ALERTS_ENABLED === 'true' && env.SHIELD_ALERT_TO_EMAIL) {
    // Aggregation and dedup should happen here before sending.
    // See the reference implementation in the docs for a complete
    // KV-backed bucketed alert system.
  }
}
