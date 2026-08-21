# Versioning

Privacynex Shield follows Semantic Versioning using `MAJOR.MINOR.PATCH`.

## Source of truth

`package.json` is the canonical source for the package name and version.
`package-lock.json` must contain the same name and version.

The HTML example reads `package.json` at runtime, so it never maintains a
separate version string.

## Initial release

The initial repository commit and first public release use `1.0.0`.
Changes made before that first release remain part of `1.0.0`.

After `1.0.0` is published, every public change receives a new version:

- PATCH: compatible fixes, documentation, tests, CI and maintenance changes;
- MINOR: compatible features, exports or configuration capabilities;
- MAJOR: incompatible API, configuration or runtime behavior changes.

Prereleases use standard identifiers such as `1.1.0-rc.1`.

## Required consistency

One published version corresponds to exactly:

- one package version;
- one commit;
- one immutable Git tag named `vX.Y.Z`;
- one GitHub release;
- one npm publication.

Never reuse a published version, move a published tag or replace an npm
artifact.

## Version workflow

1. Select the SemVer increment.
2. Update `package.json` and `package-lock.json`.
3. Update `CHANGELOG.md` and `CHANGELOG.fr.md`.
4. Run `npm run version:check`.
5. Run `npm run check`.
6. Run `npm audit --omit=dev`.
7. Run `npm pack --dry-run` and inspect the file list.
8. Create the release commit.
9. Push the commit before creating its tag and GitHub release.
10. Publish `1.0.0` manually with maintainer 2FA, then configure npm trusted
    publishing for subsequent immutable release tags.

Runtime or security changes also require a local Cloudflare workerd integration
test before the release is considered production-ready.

If a published release needs correction, create a new PATCH version.
