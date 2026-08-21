import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const ROOT = new URL('../', import.meta.url);

async function readJson(path) {
  return JSON.parse(await readFile(new URL(path, ROOT), 'utf8'));
}

const [packageJson, packageLock, changelog, changelogFr, example] = await Promise.all([
  readJson('package.json'),
  readJson('package-lock.json'),
  readFile(new URL('CHANGELOG.md', ROOT), 'utf8'),
  readFile(new URL('CHANGELOG.fr.md', ROOT), 'utf8'),
  readFile(new URL('example/index.html', ROOT), 'utf8'),
]);

assert.equal(packageJson.name, 'privacynex-shield');
assert.match(packageJson.version, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
assert.equal(packageJson.repository?.url, 'git+https://github.com/privacynex/privacynex-shield.git');
assert.equal(packageJson.homepage, 'https://github.com/privacynex/privacynex-shield#readme');
assert.equal(packageLock.name, packageJson.name);
assert.equal(packageLock.version, packageJson.version);
assert.equal(packageLock.packages?.['']?.name, packageJson.name);
assert.equal(packageLock.packages?.['']?.version, packageJson.version);
assert.match(changelog, new RegExp('^## \\[' + packageJson.version.replaceAll('.', '\\.') + '\\]', 'm'));
assert.match(changelogFr, new RegExp('^## \\[' + packageJson.version.replaceAll('.', '\\.') + '\\]', 'm'));
assert.match(example, /fetch\(['"]\.\.\/package\.json['"]/);
assert.match(example, /id="package-name"/);
assert.match(example, /id="package-version"/);

console.log(`Version metadata is consistent: ${packageJson.name}@${packageJson.version}`);
