import assert from 'node:assert/strict';
import test from 'node:test';

import { onRequest } from '../server/_middleware.ts';
import { verifySignedChallenge } from '../src/core/crypto.ts';

const secret = 'cd'.repeat(32);

function documentRequest(userAgent = 'Mozilla/5.0', path = '/private'): Request {
  return new Request(`https://example.test${path}`, {
    headers: {
      Accept: 'text/html',
      'CF-Connecting-IP': '203.0.113.22',
      'Sec-Fetch-Dest': 'document',
      'User-Agent': userAgent,
    },
  });
}

test('missing clearance returns a hardened challenge document', async () => {
  let served = false;
  const response = await onRequest({
    request: documentRequest(),
    env: {
      SHIELD_SECRET: secret,
      SHIELD_BRAND_NAME: '<img src=x onerror=alert(1)>',
    },
    next: async () => {
      served = true;
      return new Response('secret content', { headers: { 'Content-Type': 'text/html' } });
    },
  });

  assert.equal(served, true, 'the origin response is inspected before the HTML gate is applied');
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.doesNotMatch(html, /secret content/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(response.headers.get('Content-Security-Policy') || '', /default-src 'none'/);
  assert.match(
    html,
    /src="\/pnx-shield\/shield\.js\?challenge=[0-9a-f]{32}"/,
    'each signed challenge must load a uniquely keyed client script',
  );

  const token = html.match(/data-shield-challenge-token="([^"]+)"/)?.[1];
  assert.ok(token, 'the middleware must embed its signed challenge');
  assert.ok(await verifySignedChallenge(token, documentRequest(), secret));
});

test('sensitive paths are denied even in legacy mode', async () => {
  let served = false;
  const response = await onRequest({
    request: documentRequest('Mozilla/5.0', '/.env'),
    env: {
      SHIELD_SECRET: secret,
      SHIELD_DECISION_MODE: 'legacy',
    },
    next: async () => {
      served = true;
      return new Response('secret content', { headers: { 'Content-Type': 'text/html' } });
    },
  });

  assert.equal(served, true, 'the origin response may be inspected but must never be returned');
  assert.equal(response.status, 403);
  assert.doesNotMatch(await response.text(), /secret content/);
});

test('a bot User-Agent alone cannot obtain protected content', async () => {
  let served = false;
  const response = await onRequest({
    request: documentRequest('Mozilla/5.0 (compatible; Googlebot/2.1)'),
    env: { SHIELD_SECRET: secret },
    next: async () => {
      served = true;
      return new Response('secret content', { headers: { 'Content-Type': 'text/html' } });
    },
  });
  assert.equal(served, true, 'the origin response is inspected before the HTML gate is applied');
  assert.doesNotMatch(await response.text(), /secret content/);
});

test('client rendering contains no HTML string injection sink', async () => {
  const source = await import('node:fs/promises').then((fs) => fs.readFile('src/client/shield.js', 'utf8'));
  assert.doesNotMatch(source, /\.innerHTML\s*=|insertAdjacentHTML|document\.write\s*\(/);
  assert.match(source, /function solveWithoutWorker\(/);
  assert.doesNotMatch(
    source,
    /!crypto\.subtle \|\| typeof Worker === 'undefined'/,
    'missing Worker support must use the bounded in-page fallback',
  );
});

test('an asset-like path returning HTML remains protected', async () => {
  let served = false;
  const response = await onRequest({
    request: documentRequest('Mozilla/5.0', '/fallback.js'),
    env: { SHIELD_SECRET: secret },
    next: async () => {
      served = true;
      return new Response('<h1>private fallback</h1>', {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    },
  });
  assert.equal(served, true);
  assert.doesNotMatch(await response.text(), /private fallback/);
});

test('a real static asset remains available without clearance', async () => {
  const response = await onRequest({
    request: documentRequest('Mozilla/5.0', '/app.js'),
    env: { SHIELD_SECRET: secret },
    next: async () => new Response('console.log("ok")', {
      headers: { 'Content-Type': 'application/javascript' },
    }),
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'console.log("ok")');
});
