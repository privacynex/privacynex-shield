/**
 * Mask the last two octets of an IPv4 address (e.g. 192.168.xxx.xxx)
 * or the last six groups of an IPv6 address (e.g. 2001:db8:xxxx:...).
 */
export declare function anonymizeIpPartial(ip: string): string;
/**
 * Full IP removal. Returns only the IP version prefix.
 * For when even partial IPs must not be logged.
 */
export declare function anonymizeIpFull(ip: string): string;
