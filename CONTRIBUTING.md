# Contributing

1. Follow [VERSIONING.md](VERSIONING.md) for every public change and
   [DEPLOYMENT.md](DEPLOYMENT.md) for production-facing behaviour.
2. Open an issue for behavioral changes before implementation.
3. Keep runtime dependencies at zero unless the security benefit clearly justifies one.
4. Add a regression test for every security or reliability fix.
5. Run `npm run check` and `npm pack --dry-run`.
6. Never commit local environment files, credentials, logs containing personal data or confidential third-party data.

Security invariants must not become browser-configurable. See `README.md` for the current list.

By submitting a contribution, you agree that it is licensed under the
[Apache License 2.0](LICENSE), as stated in section 5 of that licence.
