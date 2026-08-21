#!/usr/bin/env node
/**
 * ═══════════════════════════════════════════════════════════════
 *  Privacynex Shield: official crawler IP snapshot refresh
 *  Downloads official IP range lists from each search/AI bot
 *  operator and writes src/detection/bot-ip-snapshot.ts
 *  as an embedded constant. The Shield reads this snapshot at
 *  runtime, so validation is offline and fail-closed.
 *
 *  Run monthly : node scripts/refresh-bot-ips.mjs
 *  Commit the resulting .ts file.
 * ═══════════════════════════════════════════════════════════════
 */

import fs from 'fs';
import { isIP } from 'net';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'src/detection/bot-ip-snapshot.ts');
const MAX_RESPONSE_BYTES = 2_000_000;
const MAX_PREFIXES_PER_SOURCE = 5_000;
const MIN_IPV4_PREFIX = 16;
const MIN_IPV6_PREFIX = 32;

const SOURCES = [
  { id: 'googlebot', url: 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json' },
  { id: 'bingbot', url: 'https://www.bing.com/toolbox/bingbot.json' },
  { id: 'oai-searchbot', url: 'https://openai.com/searchbot.json' },
  { id: 'chatgpt-user', url: 'https://openai.com/chatgpt-user.json' },
  { id: 'perplexitybot', url: 'https://www.perplexity.ai/perplexitybot.json' },
  { id: 'anthropic', url: 'https://claude.com/crawling/bots.json' },
  { id: 'duckassistbot', url: 'https://duckduckgo.com/duckassistbot.json' },
  { id: 'gemini-deep-research', url: 'https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json' },
];

async function readBoundedJsonResponse(res) {
  const reader = res.body?.getReader();
  if (!reader) throw new Error(`Empty response body from ${res.url}`);
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel('response-too-large').catch(() => undefined);
        throw new Error(`Response too large from ${res.url}`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

export function validateCrawlerPrefix(value, family) {
  if (typeof value !== 'string' || value !== value.trim()) {
    throw new Error('Crawler prefix must be a trimmed string');
  }
  const parts = value.split('/');
  if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1])) {
    throw new Error(`Invalid crawler CIDR: ${value}`);
  }
  const addressFamily = isIP(parts[0]);
  const expectedFamily = family === 'ipv4' ? 4 : 6;
  const prefix = Number(parts[1]);
  const minPrefix = expectedFamily === 4 ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX;
  const maxPrefix = expectedFamily === 4 ? 32 : 128;
  if (addressFamily !== expectedFamily || prefix < minPrefix || prefix > maxPrefix) {
    throw new Error(`Unsafe crawler CIDR: ${value}`);
  }
  return value;
}

export function validateCrawlerPrefixes(entries) {
  if (!Array.isArray(entries)) throw new Error('Crawler prefixes must be an array');
  if (entries.length > MAX_PREFIXES_PER_SOURCE) throw new Error('Too many crawler prefixes');
  const out = new Set();
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') throw new Error('Invalid crawler prefix entry');
    if (entry.ipv4Prefix !== undefined) {
      out.add(validateCrawlerPrefix(entry.ipv4Prefix, 'ipv4'));
    }
    if (entry.ipv6Prefix !== undefined) {
      out.add(validateCrawlerPrefix(entry.ipv6Prefix, 'ipv6'));
    }
  }
  if (out.size === 0) throw new Error('Empty crawler prefix list');
  return [...out];
}

export async function fetchPrefixes(url) {
  const res = await fetch(url, { headers: { 'Cache-Control': 'no-cache' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} on ${url}`);
  if (new URL(res.url).origin !== new URL(url).origin) {
    throw new Error(`Cross-origin redirect refused for ${url}`);
  }
  const data = await readBoundedJsonResponse(res);
  if (!Array.isArray(data.prefixes)) throw new Error(`No "prefixes" array in ${url}`);
  return validateCrawlerPrefixes(data.prefixes);
}

async function main() {
  const results = {};
  for (const src of SOURCES) {
    process.stdout.write(`  → ${src.id} … `);
    try {
      const prefixes = await fetchPrefixes(src.url);
      results[src.url] = prefixes;
      console.log(`${prefixes.length} prefixes`);
    } catch (err) {
      console.error(`FAIL : ${err.message}`);
      process.exitCode = 1;
      return;
    }
  }

  const now = new Date().toISOString();
  const lines = [
    '// ─────────────────────────────────────────────────────────────',
    '//  AUTO-GENERATED by scripts/refresh-bot-ips.mjs: do not edit.',
    '//  Snapshot of official bot IP ranges. Refresh monthly.',
    `//  Generated : ${now}`,
    '// ─────────────────────────────────────────────────────────────',
    '',
    'export const SHIELD_BOT_IP_SNAPSHOT: Readonly<Record<string, readonly string[]>> = Object.freeze({',
  ];
  for (const [url, prefixes] of Object.entries(results)) {
    lines.push(`  ${JSON.stringify(url)}: Object.freeze([`);
    for (const p of prefixes) lines.push(`    ${JSON.stringify(p)},`);
    lines.push('  ]),');
  }
  lines.push('});');
  lines.push('');

  fs.writeFileSync(OUT, lines.join('\n'), 'utf8');
  console.log(`\n✓ Wrote ${OUT}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
