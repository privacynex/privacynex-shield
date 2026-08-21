/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Pluggable event sink interface
   Implement this interface to send Shield events to your
   logging/monitoring infrastructure.

   Default: console sink (zero config, logs to console).
   Providers: implement write() and swap in your middleware.
   ═══════════════════════════════════════════════════════════════ */

import { getClientIp } from '../config/runtime.ts';

export type SinkDecision = 'allow' | 'challenge' | 'deny' | 'ratelimit';

export interface ShieldSinkEvent {
  timestamp: number;
  path: string;
  ipMasked: string;
  uaHash: string; // first 16 chars of SHA-256(UA), not the raw UA
  asn: string;
  country: string;
  tlsVersion: string;
  score: number;
  decision: SinkDecision;
  signals: string[];
  reason?: string;
  shadowAction?: string;
  shadowReason?: string;
}

export interface ShieldSink {
  /** Write a Shield event. Must not throw; errors are caught by the caller. */
  write(event: ShieldSinkEvent): Promise<void>;
}

// ─── Console sink (default) ───

export const consoleSink: ShieldSink = {
  async write(event: ShieldSinkEvent): Promise<void> {
    console.log('[SHIELD][SINK]', JSON.stringify(event));
  },
};

// ─── Helpers ───

/**
 * Build a sink event from a request and partial scoring data.
 * IP is anonymized: only the first two octets (IPv4) or first
 * two groups (IPv6) are kept.
 */
export function buildShieldSinkEvent(
  request: Request,
  partial: {
    score: number;
    decision: SinkDecision;
    signals: string[];
    reason?: string;
    shadowAction?: string;
    shadowReason?: string;
  },
): ShieldSinkEvent {
  const url = new URL(request.url);
  const ua = request.headers.get('User-Agent') || '';
  const ip = getClientIp(request);

  // @ts-expect-error : request.cf is Cloudflare-specific
  const cf = request.cf || {};

  return {
    timestamp: Date.now(),
    path: url.pathname,
    ipMasked: maskIp(ip),
    uaHash: hashUA(ua),
    asn: String(cf.asn || ''),
    country: cf.country || '',
    tlsVersion: cf.tlsVersion || '',
    score: partial.score,
    decision: partial.decision,
    signals: partial.signals,
    reason: partial.reason,
    shadowAction: partial.shadowAction,
    shadowReason: partial.shadowReason,
  };
}

function maskIp(ip: string): string {
  if (!ip) return '';
  if (ip.includes(':')) {
    const parts = ip.split(':');
    if (parts.length < 4) return ip;
    return parts.slice(0, 2).join(':') + ':xxxx:xxxx:xxxx:xxxx';
  }
  const parts = ip.split('.');
  if (parts.length < 4) return ip;
  return parts[0] + '.' + parts[1] + '.xxx.xxx';
}

function hashUA(ua: string): string {
  // Simple hash for privacy: we don't log raw UAs.
  // For a real deployment, use SHA-256(UA).substring(0, 16).
  // This placeholder uses a simple length+first char method.
  if (!ua) return 'empty';
  let hash = 0;
  for (let i = 0; i < ua.length; i++) {
    const c = ua.charCodeAt(i);
    hash = ((hash << 5) - hash) + c;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}
