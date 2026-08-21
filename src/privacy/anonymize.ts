/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : IP anonymization (opt-in, disabled by default)
   Masks the last two octets of IPv4 or the last six groups of
   IPv6 before logging. Keeps enough context for ASN/country-based
   analysis without storing the full IP.

   Design constraint: opt-in. Disabled by default because even
   partial IPs can be considered personal data in some jurisdictions.
   ═══════════════════════════════════════════════════════════════ */

/**
 * Mask the last two octets of an IPv4 address (e.g. 192.168.xxx.xxx)
 * or the last six groups of an IPv6 address (e.g. 2001:db8:xxxx:...).
 */
export function anonymizeIpPartial(ip: string): string {
  if (!ip || typeof ip !== 'string') return 'unknown';

  const trimmed = ip.trim();

  if (trimmed.includes(':')) {
    // IPv6
    const parts = trimmed.split(':');
    if (parts.length < 4) {
      // Too short to meaningfully mask, return as-is
      return trimmed;
    }
    return parts.slice(0, 2).join(':') + ':xxxx:xxxx:xxxx:xxxx';
  }

  // IPv4
  const parts = trimmed.split('.');
  if (parts.length < 4) {
    return trimmed;
  }
  return parts[0] + '.' + parts[1] + '.xxx.xxx';
}

/**
 * Full IP removal. Returns only the IP version prefix.
 * For when even partial IPs must not be logged.
 */
export function anonymizeIpFull(ip: string): string {
  if (!ip) return 'unknown';
  if (ip.includes(':')) return 'IPv6';
  return 'IPv4';
}
