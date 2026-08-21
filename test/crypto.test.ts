import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  generateSignedChallenge,
  generateSignedCookie,
  verifySignedChallenge,
  verifySignedCookie,
} from '../src/core/crypto.ts';
import { RequestBodyError, readBoundedJson } from '../src/http/request-body.ts';
import { __resetRateLimitForTest } from '../src/pipeline/ratelimit.ts';
import { __resetSpentForTest } from '../src/pipeline/replay.ts';
import { handleShieldVerify } from '../src/pow/verify.ts';

const secret = 'ab'.repeat(32);

function apiRequest(body: unknown): Request {
  return new Request('https://example.test/api/shield-verify', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'CF-Connecting-IP': '203.0.113.10',
      'Sec-Fetch-Site': 'same-origin',
    },
    body: JSON.stringify(body),
  });
}

function apiRequestFromIp(body: unknown, ip: string): Request {
  const request = apiRequest(body);
  const headers = new Headers(request.headers);
  headers.set('CF-Connecting-IP', ip);
  return new Request(request, { headers });
}

function solve(salt: string, target: string, max: number): number {
  for (let nonce = 0; nonce <= max; nonce++) {
    const digest = createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
    if (digest === target) return nonce;
  }
  throw new Error('challenge solution not found');
}

test('signed challenges and cookies reject tampering and host changes', async () => {
  const request = new Request('https://example.test/private', {
    headers: { 'CF-Connecting-IP': '203.0.113.10' },
  });
  const challenge = await generateSignedChallenge(request, secret, 'v1', 1000);
  assert.ok(await verifySignedChallenge(challenge.challengeToken, request, secret, 'v1'));
  assert.equal(await verifySignedChallenge(challenge.challengeToken + 'x', request, secret, 'v1'), null);
  assert.equal(
    await verifySignedChallenge(challenge.challengeToken, new Request('https://other.test/private'), secret, 'v1'),
    null,
  );

  const cookie = await generateSignedCookie(challenge.target, request, secret, 'v1');
  assert.equal(await verifySignedCookie(cookie, request, secret, 'v1'), true);
  assert.equal(await verifySignedCookie(cookie, request, secret, 'v2'), false);
  assert.equal(
    await verifySignedCookie(
      cookie,
      new Request('https://example.test/private', {
        headers: { 'CF-Connecting-IP': '203.0.113.200' },
      }),
      secret,
      'v1',
    ),
    true,
  );
  assert.equal(
    await verifySignedCookie(
      cookie,
      new Request('https://example.test/private', {
        headers: { 'CF-Connecting-IP': '203.0.114.10' },
      }),
      secret,
      'v1',
    ),
    false,
  );
});

test('verify endpoint never accepts an unsigned salt and target fallback', async () => {
  __resetRateLimitForTest();
  __resetSpentForTest();
  const salt = '11'.repeat(16);
  const nonce = 0;
  const target = createHash('sha256').update(`${salt}:${nonce}`).digest('hex');
  const response = await handleShieldVerify(apiRequest({ salt, target, nonce }), {
    SHIELD_SECRET: secret,
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'Missing challenge token' });
});

test('verify endpoint issues only server-signed clearance cookies', async () => {
  __resetRateLimitForTest();
  __resetSpentForTest();
  const contextRequest = apiRequest({});
  const challenge = await generateSignedChallenge(contextRequest, secret, 'v1', 1000);
  const nonce = solve(challenge.salt, challenge.target, challenge.max);
  const requestBody = { challengeToken: challenge.challengeToken, nonce };
  const response = await handleShieldVerify(apiRequest(requestBody), {
    SHIELD_SECRET: secret,
    SHIELD_POLICY_VERSION: 'v1',
  });

  assert.equal(response.status, 200);
  assert.match(response.headers.get('Set-Cookie') || '', /__Host-pnx_shield=.*HttpOnly.*Secure/);

  const replay = await handleShieldVerify(apiRequest(requestBody), {
    SHIELD_SECRET: secret,
    SHIELD_POLICY_VERSION: 'v1',
  });
  assert.equal(replay.status, 403);
  assert.equal(replay.headers.has('Set-Cookie'), false);
});

test('verify endpoint replay protection applies per challenge regardless of client IP', async () => {
  __resetRateLimitForTest();
  __resetSpentForTest();
  const contextRequest = apiRequestFromIp({}, '203.0.113.25');
  const challenge = await generateSignedChallenge(contextRequest, secret, 'v1', 1000);
  const nonce = solve(challenge.salt, challenge.target, challenge.max);
  const requestBody = { challengeToken: challenge.challengeToken, nonce };
  const first = await handleShieldVerify(
    apiRequestFromIp(requestBody, '203.0.113.25'),
    { SHIELD_SECRET: secret, SHIELD_POLICY_VERSION: 'v1' },
  );
  assert.equal(first.status, 200);
  const replay = await handleShieldVerify(
    apiRequestFromIp(requestBody, '203.0.113.26'),
    { SHIELD_SECRET: secret, SHIELD_POLICY_VERSION: 'v1' },
  );
  assert.equal(replay.status, 403);
});

test('bounded JSON reader rejects a streamed oversized body without Content-Length', async () => {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode('{"pad":"'));
      controller.enqueue(encoder.encode('x'.repeat(4096)));
      controller.enqueue(encoder.encode('"}'));
      controller.close();
    },
  });
  const request = new Request('https://example.test/api/shield-verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: stream,
    duplex: 'half',
  } as RequestInit & { duplex: 'half' });
  await assert.rejects(
    readBoundedJson(request, 2048),
    (error) => error instanceof RequestBodyError && error.status === 413,
  );
});

test('verify endpoint rejects cross-origin requests', async () => {
  const request = new Request('https://example.test/api/shield-verify', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Origin: 'https://attacker.test',
      'Sec-Fetch-Site': 'cross-site',
    },
    body: '{}',
  });
  const response = await handleShieldVerify(request, { SHIELD_SECRET: secret });
  assert.equal(response.status, 404);
  assert.equal(response.headers.has('Access-Control-Allow-Origin'), false);
});
