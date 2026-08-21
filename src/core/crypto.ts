/**
 * Privacynex Shield
 * Copyright (c) 2026 Slym B.
 * Licensed under the Apache License, Version 2.0
 */

/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Server-side HMAC-SHA-256 utilities
   Cookie signing + PoW verification for anti-forgery defense.

   Native Web Crypto API, strict input validation, zero runtime dependency.
   ═══════════════════════════════════════════════════════════════ */

import { getClientIp } from '../config/runtime.ts';

const HMAC_ALGO = { name: 'HMAC', hash: 'SHA-256' };
let cachedHmacSecret = '';
let cachedHmacKey: Promise<CryptoKey> | null = null;

// Must match client-side config in shield.js
export const COOKIE_TTL = 86400; // 24 hours
export const CHALLENGE_TTL = 300; // 5 minutes
export const MAX_NUMBER = 100000;
export const MAX_POW_NUMBER = 1000000;
const CLOCK_SKEW_SECONDS = 60;

// Policy version : bump SHIELD_POLICY_VERSION env var to invalidate every
// issued cookie/challenge globally. Alphanumeric + dash/dot only, no colon
// (colon is the payload separator).
export const DEFAULT_POLICY_VERSION = 'v1';
const POLICY_VERSION_RE = /^[a-zA-Z0-9.-]{1,32}$/;

export function normalizePolicyVersion(input: string | undefined): string {
  if (typeof input !== 'string' || !POLICY_VERSION_RE.test(input)) {
    return DEFAULT_POLICY_VERSION;
  }
  return input;
}

// ─── Hex / Buffer helpers (Web Crypto API) ───

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(hex.length / 2));
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function toHex(buffer: ArrayBuffer): string {
  const arr = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < arr.length; i++) {
    hex += (arr[i] < 16 ? '0' : '') + arr[i].toString(16);
  }
  return hex;
}

// ─── Secret format validation ───

const HEX_RE = /^[0-9a-f]+$/i;
const HASH_RE = /^[0-9a-f]{64}$/i;
const JTI_RE = /^[0-9a-f]{16}$/i;
const SALT_RE = /^[0-9a-f]{32}$/i;

function isValidSecret(secret: string): boolean {
  return typeof secret === 'string' && secret.length >= 64 && secret.length % 2 === 0 && HEX_RE.test(secret);
}

// ─── HMAC key import ───

async function importHmacKey(secret: string): Promise<CryptoKey> {
  if (!isValidSecret(secret)) {
    throw new Error('SHIELD_SECRET: invalid hex format or too short (minimum 32 bytes / 64 hex chars)');
  }
  if (cachedHmacKey && cachedHmacSecret === secret) return cachedHmacKey;

  const raw = hexToBytes(secret);
  cachedHmacSecret = secret;
  cachedHmacKey = crypto.subtle.importKey('raw', raw, HMAC_ALGO, false, ['sign', 'verify']);
  try {
    return await cachedHmacKey;
  } catch (error) {
    if (cachedHmacSecret === secret) {
      cachedHmacSecret = '';
      cachedHmacKey = null;
    }
    throw error;
  }
}

// ─── SHA-256 digest ───

async function sha256(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  return toHex(hash);
}

function randomHex(bytes = 16): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return toHex(value.buffer);
}

function randomNonce(maxNumber: number = MAX_NUMBER): number {
  const bound = Math.max(1, Math.floor(maxNumber));
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  // Nonce within [bound/2, bound] so PoW is non-trivial.
  const half = Math.floor(bound / 2);
  return half + (value[0] % (bound - half + 1));
}

function ipv4Prefix(ip: string): string | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => /^\d{1,3}$/.test(part) ? Number(part) : -1);
  if (octets.some((part) => part < 0 || part > 255)) return null;
  return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
}

function ipv6Bytes(ip: string): Uint8Array | null {
  if (!ip || ip.includes('%') || ip.split('::').length > 2) return null;
  let normalized = ip.toLowerCase();
  const lastColon = normalized.lastIndexOf(':');
  const ipv4Tail = lastColon >= 0 ? normalized.slice(lastColon + 1) : '';
  const mapped = ipv4Prefix(ipv4Tail);
  if (mapped) {
    const octets = ipv4Tail.split('.').map(Number);
    normalized = normalized.slice(0, lastColon + 1)
      + ((octets[0] << 8) | octets[1]).toString(16)
      + ':'
      + ((octets[2] << 8) | octets[3]).toString(16);
  }

  const halves = normalized.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (fill < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const groups = [...left, ...Array(fill).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;

  const bytes = new Uint8Array(16);
  groups.forEach((part, index) => {
    const value = Number.parseInt(part, 16);
    bytes[index * 2] = value >> 8;
    bytes[index * 2 + 1] = value & 0xff;
  });
  return bytes;
}

function networkPrefix(request: Request): string {
  const ip = getClientIp(request);
  const v4 = ipv4Prefix(ip);
  if (v4) return 'v4:' + v4;

  const embeddedV4 = ipv4Prefix(ip.slice(ip.lastIndexOf(':') + 1));
  if (embeddedV4) return 'v4:' + embeddedV4;

  const v6 = ipv6Bytes(ip);
  if (v6) {
    return 'v6:' + Array.from(v6.slice(0, 7))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('') + '/56';
  }
  return 'unknown';
}

async function buildChallengeBinding(request: Request, secret: string): Promise<string> {
  const host = new URL(request.url).hostname.toLowerCase();
  return hmacSign(host + '\n' + networkPrefix(request), secret);
}

// ─── HMAC sign / verify ───

export async function hmacSign(payload: string, secret: string): Promise<string> {
  const key = await importHmacKey(secret);
  const data = new TextEncoder().encode(payload);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return toHex(sig);
}

export async function hmacVerify(payload: string, signature: string, secret: string): Promise<boolean> {
  if (!HASH_RE.test(signature)) return false;
  const key = await importHmacKey(secret);
  const data = new TextEncoder().encode(payload);
  const sigBytes = hexToBytes(signature);
  return crypto.subtle.verify('HMAC', key, sigBytes, data);
}

// ─── PoW server-side verification ───
// Recomputes SHA-256(salt + ':' + nonce), compares to claimed target.
// Prevents sending a fake hash without actually solving the challenge.

export async function verifyPoW(salt: string, nonce: number, target: string): Promise<boolean> {
  const computed = await sha256(salt + ':' + nonce);
  // Constant-time byte comparison.
  const a = new TextEncoder().encode(computed);
  const b = new TextEncoder().encode(target);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export async function generateSignedChallenge(
  request: Request,
  secret: string,
  policyVersion: string = DEFAULT_POLICY_VERSION,
  maxNumber: number = MAX_NUMBER,
): Promise<{
  challengeToken: string;
  salt: string;
  target: string;
  max: number;
  ttl: number;
}> {
  if (!Number.isFinite(maxNumber)) {
    throw new Error('Shield challenge difficulty must be finite');
  }
  const pv = normalizePolicyVersion(policyVersion);
  const max = Math.max(1000, Math.floor(maxNumber));
  if (max > MAX_POW_NUMBER) {
    throw new Error('Shield challenge difficulty exceeds the supported maximum');
  }
  const ts = Math.floor(Date.now() / 1000);
  const jti = randomHex(8); // 16 hex chars, unique per challenge
  const salt = randomHex(16);
  const nonce = randomNonce(max);
  const target = await sha256(salt + ':' + nonce);
  const binding = await buildChallengeBinding(request, secret);
  // jti is baked into the signed payload : tampering invalidates the HMAC.
  const payload = `${ts}:${pv}:${jti}:${salt}:${target}:${max}:${binding}`;
  const sig = await hmacSign(payload, secret);

  return {
    challengeToken: btoa(`${payload}:${sig}`),
    salt,
    target,
    max,
    ttl: CHALLENGE_TTL,
  };
}

export async function verifySignedChallenge(
  challengeToken: string,
  request: Request,
  secret: string,
  policyVersion: string = DEFAULT_POLICY_VERSION,
): Promise<{ salt: string; target: string; jti: string; max: number } | null> {
  try {
    const pv = normalizePolicyVersion(policyVersion);
    const decoded = atob(challengeToken);
    const parts = decoded.split(':');

    // Expected format: ts:policyVersion:jti:salt:target:max:binding:hmacSig
    if (parts.length !== 8) return null;

    const [tsStr, tokenPv, jti, salt, target, maxStr, binding, hmacSig] = parts;
    if (!/^\d{1,12}$/.test(tsStr) || !/^\d{1,7}$/.test(maxStr)) return null;
    const ts = Number(tsStr);
    const max = Number(maxStr);
    if (!Number.isSafeInteger(ts) || !Number.isSafeInteger(max)) return null;
    if (max < 1000 || max > MAX_POW_NUMBER) return null;
    if (!JTI_RE.test(jti) || !SALT_RE.test(salt) || !HASH_RE.test(target)) return null;
    if (!HASH_RE.test(binding) || !HASH_RE.test(hmacSig)) return null;

    // Policy version match required : bumping env var invalidates all tokens
    if (tokenPv !== pv) return null;

    const now = Math.floor(Date.now() / 1000);
    if (ts > now + CLOCK_SKEW_SECONDS || now - ts > CHALLENGE_TTL) return null;

    const expectedBinding = await buildChallengeBinding(request, secret);
    if (binding !== expectedBinding) return null;

    const payload = `${ts}:${tokenPv}:${jti}:${salt}:${target}:${max}:${binding}`;
    const isValid = await hmacVerify(payload, hmacSig, secret);
    if (!isValid) return null;

    return { salt, target, jti, max };
  } catch {
    return null;
  }
}

// ─── Signed cookie generation ───
// Format: base64( timestamp:policyVersion:powHash:binding:hmacSignature )
// The host and network-prefix binding limits transfer between clients.
// policyVersion lets us invalidate every live cookie by bumping an env var.

export async function generateSignedCookie(
  powHash: string,
  request: Request,
  secret: string,
  policyVersion: string = DEFAULT_POLICY_VERSION,
): Promise<string> {
  if (!HASH_RE.test(powHash)) {
    throw new Error('Shield cookie proof hash is invalid');
  }
  const pv = normalizePolicyVersion(policyVersion);
  const ts = Math.floor(Date.now() / 1000);
  const binding = await buildChallengeBinding(request, secret);
  const payload = ts + ':' + pv + ':' + powHash + ':' + binding;
  const sig = await hmacSign(payload, secret);
  return btoa(payload + ':' + sig);
}

// ─── Signed cookie verification ───
// For middleware (Phase 2) : validates HMAC + expiry + policy version server-side.

export async function verifySignedCookie(
  cookieValue: string,
  request: Request,
  secret: string,
  policyVersion: string = DEFAULT_POLICY_VERSION,
): Promise<boolean> {
  try {
    const pv = normalizePolicyVersion(policyVersion);
    const decoded = atob(cookieValue);
    const parts = decoded.split(':');

    // Signed = 5 parts (timestamp:policyVersion:powHash:binding:hmacSig)
    if (parts.length !== 5) return false;

    const [tsStr, cookiePv, powHash, binding, hmacSig] = parts;
    if (!/^\d{1,12}$/.test(tsStr)) return false;
    const ts = Number(tsStr);
    if (!Number.isSafeInteger(ts)) return false;
    if (!HASH_RE.test(powHash) || !HASH_RE.test(binding) || !HASH_RE.test(hmacSig)) return false;

    // Policy version match : bumping env var invalidates all live cookies
    if (cookiePv !== pv) return false;

    // Expiry check
    const now = Math.floor(Date.now() / 1000);
    if (ts > now + CLOCK_SKEW_SECONDS || now - ts > COOKIE_TTL) return false;

    const expectedBinding = await buildChallengeBinding(request, secret);
    if (binding !== expectedBinding) return false;

    // HMAC verification
    const payload = ts + ':' + cookiePv + ':' + powHash + ':' + binding;
    return hmacVerify(payload, hmacSig, secret);
  } catch {
    return false;
  }
}
