import assert from 'node:assert/strict';
import test from 'node:test';

import {
  __rateLimitSizeForTest,
  __resetRateLimitForTest,
  checkRateLimit,
  RATE_LIMIT_MAX_ENTRIES,
} from '../src/pipeline/ratelimit.ts';

test('rate-limit state never exceeds its hard capacity', () => {
  __resetRateLimitForTest();
  for (let index = 0; index < RATE_LIMIT_MAX_ENTRIES * 2; index++) {
    checkRateLimit(`2001:db8::${index.toString(16)}`, 'doc');
  }
  assert.equal(__rateLimitSizeForTest() <= RATE_LIMIT_MAX_ENTRIES, true);
});
