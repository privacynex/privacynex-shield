# Changelog

All notable changes to Privacynex Shield are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-21

First public release of Privacynex Shield, a server-verified proof-of-work gate
built on the Fetch API. Released under the Apache License 2.0 with zero runtime
dependencies and a ready-made Cloudflare Pages scaffold.

### Added

- HMAC-SHA-256 signed challenges and `__Host-` clearance cookies, verified server-side.
- Fetch-based gate `shieldFetch(request, env, next)` with platform-specific wiring documented for non-Cloudflare runtimes.
- Ready-made Cloudflare Pages scaffold via `npx privacynex-shield init`.
- Configurable client IP header (`SHIELD_CLIENT_IP_HEADER`) for platforms outside Cloudflare.
- Path-scoped crawler bypass verified against official published IP ranges, failing closed.
- Response Content-Type classification so asset-like URLs returning HTML remain gated.
- Bounded streamed verification bodies and hardened crawler snapshot refresh.
- Symlink-safe Cloudflare Pages initializer.
- Safe browser rendering without HTML string injection.
- Per-challenge client URLs and asynchronous in-page PoW fallback when a browser aborts Web Workers.
- Local-only demo reset that replays the real challenge without exposing a production route.
- Live example page that reads package metadata from `package.json`.
- Public versioning, contribution, security and trademark documentation.
- Repository badges and public funding links.

### Security

- Strict same-origin challenge and verification endpoints.
- Bounded request bodies, tokens, nonce ranges and PoW difficulty.
- Single-use challenge consumption and in-memory rate limiting, dependency-free.
- Host and coarse client-network-prefix binding for challenges and clearance cookies.
- Production cookies use `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`.

### Note

- Package name: `privacynex-shield`.
- The Privacynex names, trademarks and visual identity are not licensed under Apache 2.0 (see `TRADEMARKS.md`).
- 21/21 security regression tests pass under `npm run check`.
