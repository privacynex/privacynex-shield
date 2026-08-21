import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { onRequest } from '../example/functions/api/shield-demo-reset.ts';

function resetRequest(url: string, method = 'POST', origin = 'http://127.0.0.1:8767'): Request {
  return new Request(url, { method, headers: { Origin: origin } });
}

test('demo reset clears Shield cookies and redirects to a fresh challenge', () => {
  const result = onRequest({
    request: resetRequest('http://127.0.0.1:8767/api/shield-demo-reset'),
  });

  assert.equal(result.status, 303);
  assert.match(result.headers.get('Location') || '', /^\/\?shield-demo=\d+$/);
  const cookies = result.headers.get('Set-Cookie') || '';
  assert.match(cookies, /__pnx_shield=/);
  assert.match(cookies, /__Host-pnx_shield=/);
  assert.match(cookies, /__pnx_shield_ok=/);
  assert.match(cookies, /Max-Age=0/);
});

test('demo reset rejects cross-origin and non-POST requests', () => {
  const crossOrigin = onRequest({
    request: resetRequest(
      'http://127.0.0.1:8767/api/shield-demo-reset',
      'POST',
      'https://attacker.example',
    ),
  });
  const getRequest = onRequest({
    request: resetRequest('http://127.0.0.1:8767/api/shield-demo-reset', 'GET'),
  });

  assert.equal(crossOrigin.status, 403);
  assert.equal(getRequest.status, 404);
});

test('demo reset is unavailable on non-loopback hosts', () => {
  const result = onRequest({
    request: resetRequest(
      'https://shield.example/api/shield-demo-reset',
      'POST',
      'https://shield.example',
    ),
  });

  assert.equal(result.status, 404);
});

test('demo replay clears its local loop guard before the native POST', async () => {
  const html = await readFile('example/index.html', 'utf8');
  assert.match(html, /method="post" action="\/api\/shield-demo-reset"/);
  assert.match(html, /sessionStorage\.removeItem\('pnx_shield_loop_guard'\)/);
  assert.match(html, /sessionStorage\.removeItem\('pnx_shield_last_reload'\)/);
});
