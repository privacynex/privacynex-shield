import assert from 'node:assert/strict';
import test from 'node:test';

import { SHIELD_BOT_IP_SNAPSHOT } from '../src/detection/bot-ip-snapshot.ts';
import { isContentBypassRequest, isTrustedShieldBypassRequest } from '../src/detection/bot-policy.ts';

const GOOGLE_RANGES = 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json';

function crawlerRequest(ip: string): Request {
  return new Request('https://example.test/', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1)',
      'CF-Connecting-IP': ip,
    },
  });
}

test('a spoofed crawler User-Agent never bypasses the gate', () => {
  assert.equal(isTrustedShieldBypassRequest(crawlerRequest('203.0.113.10')), false);
});

test('a crawler bypass needs both the expected User-Agent and an official IP range', () => {
  const firstPrefix = SHIELD_BOT_IP_SNAPSHOT[GOOGLE_RANGES]?.[0];
  assert.ok(firstPrefix);
  assert.equal(isTrustedShieldBypassRequest(crawlerRequest(firstPrefix.split('/')[0])), true);
});

test('content-scoped crawlers never bypass sensitive or admin paths', () => {
  const url = 'https://openai.com/chatgpt-user.json';
  const firstPrefix = SHIELD_BOT_IP_SNAPSHOT[url]?.[0];
  assert.ok(firstPrefix);
  const request = new Request('https://example.test/', {
    headers: {
      'User-Agent': 'ChatGPT-User',
      'CF-Connecting-IP': firstPrefix.split('/')[0],
    },
  });
  assert.equal(isContentBypassRequest(request, '/article'), true);
  assert.equal(isContentBypassRequest(request, '/admin'), false);
  assert.equal(isContentBypassRequest(request, '/.env'), false);
  assert.equal(isContentBypassRequest(request, '/en/admin'), false);
  assert.equal(isContentBypassRequest(request, '/en/.env'), false);
});
