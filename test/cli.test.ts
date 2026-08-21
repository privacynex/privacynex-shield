import assert from 'node:assert/strict';
import { access, mkdtemp, mkdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('initializer refuses a dangling target symlink without writing through it', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'pnx-shield-cli-'));
  const functionsDir = path.join(root, 'functions');
  const publicDir = path.join(root, 'public');
  const outsideDir = path.join(root, 'outside');
  await mkdir(outsideDir);
  await symlink(outsideDir, functionsDir);

  const result = spawnSync(process.execPath, [
    'bin/pnx-shield.mjs',
    'init',
    '--functions',
    functionsDir,
    '--public',
    publicDir,
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });

  assert.notEqual(result.status, 0);
  await assert.rejects(access(path.join(outsideDir, '_middleware.ts')));
});
