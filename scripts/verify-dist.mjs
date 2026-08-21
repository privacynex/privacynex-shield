import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const pairs = [
  ['src/client/shield.js', 'dist/shield.js'],
  ['src/client/pow-worker.js', 'dist/pow-worker.js'],
];

for (const [source, distribution] of pairs) {
  const [left, right] = await Promise.all([readFile(source), readFile(distribution)]);
  assert.deepEqual(right, left, `${distribution} is stale; copy it from ${source}`);
}

console.log('Distribution files match their sources.');
