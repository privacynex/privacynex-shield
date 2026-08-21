# Historique

Toutes les modifications notables de Privacynex Shield sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
et le projet suit [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-21

Première version publique de Privacynex Shield, barrière Proof-of-Work vérifiée
côté serveur construite sur l'API Fetch. Publiée sous licence Apache 2.0, sans
dépendance runtime et avec un scaffold Cloudflare Pages prêt à intégrer.

### Added

- Challenges HMAC-SHA-256 signés et cookies de clearance `__Host-`, vérifiés côté serveur.
- Passerelle Fetch `shieldFetch(request, env, next)`, avec câblage propre à chaque plateforme hors Cloudflare.
- Scaffolding Cloudflare Pages via `npx privacynex-shield init`.
- En-tête IP client configurable (`SHIELD_CLIENT_IP_HEADER`) pour les plateformes hors Cloudflare.
- Bypass crawler limité aux chemins publics et vérifié par plages IP officielles, à échec fermé.
- Classification par Content-Type afin qu'une URL ressemblant à un asset mais servant du HTML reste protégée.
- Lecture en flux bornée des vérifications et rafraîchissement durci des plages crawler.
- Initialiseur Cloudflare Pages protégé contre les liens symboliques.
- Rendu navigateur sans injection de chaînes HTML.
- URL cliente propre à chaque challenge et repli PoW asynchrone si le navigateur interrompt les Web Workers.
- Réinitialisation strictement locale pour rejouer le vrai challenge sans exposer de route de production.
- Page d'exemple reliée aux métadonnées du manifeste du package.
- Documentation publique de version, contribution, sécurité et marque.
- Badges du dépôt et liens publics de soutien.

### Security

- Endpoints de challenge et de vérification strictement same-origin.
- Corps, jetons, plages de nonce et difficulté PoW bornés.
- Consommation unique des challenges et rate limiting en mémoire, sans dépendance.
- Liaison des challenges et cookies au hostname et à un préfixe réseau client grossier.
- Cookies de production avec attributs `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` et `Path=/`.

### Note

- Nom du package : `privacynex-shield`.
- Les noms, marques et identité visuelle Privacynex ne sont pas placés sous licence Apache 2.0 (voir `TRADEMARKS.md`).
- 21/21 tests de sécurité passent sous `npm run check`.
