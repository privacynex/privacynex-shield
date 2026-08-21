# Production deployment

Last reviewed: 2026-08-21.

This guide is the production checklist for Privacynex Shield. The package is
an application-layer gate for HTML documents. It complements, but does not
replace, authentication, authorization, a WAF, platform rate limiting or DDoS
protection.

[Version française](DEPLOYMENT.fr.md)

## 1. Confirm the trust boundary

Before installing Shield, confirm all of the following:

- traffic reaches the application through HTTPS;
- the edge or reverse proxy overwrites the header selected by
  `SHIELD_CLIENT_IP_HEADER`;
- clients cannot reach an origin that trusts a client-supplied IP header;
- protected `GET` handlers are safe to call before the challenge is completed;
- application APIs have their own authentication and authorization.

Shield fetches the origin response before deciding whether an HTML document
must be challenged. Do not attach state-changing behaviour to protected `GET`
requests. Requests under `/api/*` are rate-limited but are not authenticated by
Shield.

## 2. Install and review the scaffold

Use Node.js 22 or newer in a clean application checkout:

```bash
npm install privacynex-shield
npx privacynex-shield init --functions functions --public public
```

The initializer refuses to overwrite existing files. Review every generated
file before committing it. If the application already has middleware or either
Shield API route, merge the handlers manually and preserve their same-origin,
request-size, signature and rate-limit checks.

For a static project whose publish directory is the repository root, use
`--public .`. Other Fetch-compatible runtimes can integrate `shieldFetch` as
shown in [README.md](README.md#other-runtimes), but require platform-specific
routing, trusted client-IP configuration and staging validation.

## 3. Provision secrets and configuration

Generate a dedicated 256-bit secret:

```bash
openssl rand -hex 32
```

Store it as `SHIELD_SECRET` in the hosting platform's secret manager. Never put
the value in Git, a client-side variable, a build log, a ticket or a committed
environment file. Use a different value for each environment.

Keep `SHIELD_POLICY_VERSION` stable during normal operation. Change it when
rotating `SHIELD_SECRET` or when all active challenge and clearance tokens must
be invalidated. Treat `SHIELD_ENABLED=false` as an emergency bypass and limit
who can change it.

Outside Cloudflare, set `SHIELD_CLIENT_IP_HEADER` only to a header written or
overwritten by the trusted edge. If that guarantee cannot be made, do not use
the header for security decisions.

## 4. Validate before production

Deploy first to a non-production environment with a test secret, then verify:

- a protected HTML page returns `503` when `SHIELD_SECRET` is absent;
- the same page presents a challenge without a valid clearance cookie;
- a valid challenge results in a secure clearance cookie over HTTPS;
- cross-origin calls to the challenge and verify endpoints are rejected;
- static assets, `robots.txt`, the sitemap and required well-known files remain
  reachable;
- protected content is never present in the challenge response;
- application API authentication still works independently of Shield;
- removing Shield restores the previous request path without data migration.

Use representative mobile, desktop, privacy-proxy, VPN and crawler traffic.
Review false positives before enabling stricter decisions.

`SHIELD_DECISION_MODE=shadow` preserves legacy enforcement while calculating
the multi-level decision. The package does not persist shadow telemetry by
itself. Add observation in the surrounding application if you need a rollout
comparison. `SHIELD_COHERENCE_ENABLED=1` changes the score and can increase PoW
difficulty even outside `multi`; test it separately before production.

## 5. Operate and rotate safely

Rate-limit and replay state are held in memory per runtime instance. A
multi-instance deployment that requires global enforcement must provide a
shared store or an upstream control. Shield does not supply that coordination.

For secret rotation:

1. generate and store a new secret through the platform secret manager;
2. increment `SHIELD_POLICY_VERSION`;
3. deploy the configuration atomically where possible;
4. verify new challenges and cookies;
5. remove the old secret from the platform.

Never deploy `example/functions/api/shield-demo-reset.ts`. It exists only for
the loopback demonstration.

## 6. Release verification

Maintainers must run:

```bash
npm ci
npm run check
npm audit
npm pack --dry-run
```

Inspect the package file list and confirm that it contains `LICENSE`, `NOTICE`,
the public documentation, sources and generated distribution files, but no
credentials, local environment files, logs or dependency directory.
