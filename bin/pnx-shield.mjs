#!/usr/bin/env node

/**
 * Privacynex Shield
 * Copyright (c) 2026 Slym B.
 * Licensed under the Apache License, Version 2.0
 */

import { constants } from 'node:fs';
import { access, copyFile, lstat, mkdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);

function option(name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a path`);
  return path.resolve(process.cwd(), value);
}

async function exists(target) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

function isInside(root, target) {
  const relative = path.relative(root, target);
  return relative === ''
    || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}

async function assertNoSymlinkComponents(root, target) {
  const relative = path.relative(root, target);
  if (!isInside(root, target)) throw new Error(`Refusing path outside selected root: ${target}`);
  let current = root;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const stat = await lstat(current);
    if (stat.isSymbolicLink()) {
      throw new Error(`Refusing symbolic link in destination: ${current}`);
    }
  }
}

function usage() {
  console.log('Usage: pnx-shield init [--functions functions] [--public public]');
  console.log('The initializer refuses to overwrite existing files.');
}

async function init() {
  const functionsDir = option('--functions', path.resolve(process.cwd(), 'functions'));
  const publicDir = option('--public', path.resolve(process.cwd(), 'public'));
  await mkdir(functionsDir, { recursive: true });
  await mkdir(publicDir, { recursive: true });
  const realFunctionsDir = await realpath(functionsDir);
  const realPublicDir = await realpath(publicDir);
  if (
    realFunctionsDir !== functionsDir
    || realPublicDir !== publicDir
  ) {
    throw new Error('Refusing symbolic link as a destination root');
  }
  const files = [
    ['server/_middleware.ts', path.join(functionsDir, '_middleware.ts'), functionsDir, realFunctionsDir],
    ['server/api/shield-challenge.ts', path.join(functionsDir, 'api/shield-challenge.ts'), functionsDir, realFunctionsDir],
    ['server/api/shield-verify.ts', path.join(functionsDir, 'api/shield-verify.ts'), functionsDir, realFunctionsDir],
    ['dist/shield.js', path.join(publicDir, 'pnx-shield/shield.js'), publicDir, realPublicDir],
    ['dist/pow-worker.js', path.join(publicDir, 'pnx-shield/pow-worker.js'), publicDir, realPublicDir],
  ];

  const collisions = [];
  for (const [, target] of files) {
    if (await exists(target)) collisions.push(target);
  }
  if (collisions.length > 0) {
    throw new Error(`Refusing to overwrite existing files:\n${collisions.join('\n')}`);
  }

  for (const [source, target, root, realRoot] of files) {
    await mkdir(path.dirname(target), { recursive: true });
    const parent = path.dirname(target);
    await assertNoSymlinkComponents(root, parent);
    const realParent = await realpath(parent);
    if (!isInside(realRoot, realParent)) {
      throw new Error(`Refusing destination outside selected root: ${target}`);
    }
    await copyFile(path.join(packageRoot, source), target, constants.COPYFILE_EXCL);
    console.log(`created ${path.relative(process.cwd(), target)}`);
  }
}

try {
  if (args[0] !== 'init') {
    usage();
    process.exitCode = args.length === 0 ? 0 : 1;
  } else {
    await init();
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
