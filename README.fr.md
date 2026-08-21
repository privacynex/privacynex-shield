# Privacynex Shield

[![CI](https://img.shields.io/github/actions/workflow/status/privacynex/privacynex-shield/ci.yml?branch=main&label=CI&logo=github)](https://github.com/privacynex/privacynex-shield/actions/workflows/ci.yml)
[![Version npm](https://img.shields.io/npm/v/privacynex-shield?label=npm&logo=npm)](https://www.npmjs.com/package/privacynex-shield)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Licence : Apache-2.0](https://img.shields.io/badge/Licence-Apache--2.0-blue.svg)](LICENSE)
[![Dépendances runtime : 0](https://img.shields.io/badge/runtime_dependencies-0-brightgreen)](package.json)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/privacynex/privacynex-shield)

---

<p align="center">
  <img src="./assets/slymb-privacynex-shield.webp" alt="Privacynex Shield" width="100%" style="display:block;border-radius:14px;border:1px solid #2e2e2e;">
</p>

---

[English version](README.md) | [Déploiement en production](DEPLOYMENT.fr.md) | [Sécurité](SECURITY.md) | [Contribution](CONTRIBUTING.md) | [Versioning](VERSIONING.md)

Privacynex Shield est une barrière Proof-of-Work vérifiée côté serveur, construite sur l'API Fetch. Le scaffold fourni cible Cloudflare Pages ; le middleware central peut être câblé dans un autre runtime compatible Fetch après une validation propre à la plateforme.

Cette version publique est dérivée du Shield de [Privacynex](https://privacynex.org).

La marque, la langue, le logo et les chemins d'assets sont configurables. Les décisions de sécurité ne le sont pas depuis le navigateur : challenge signé et lié au réseau, nonce borné, cookie HMAC `HttpOnly`, API same-origin et crawlers vérifiés par User-Agent, plage IP officielle et portée publique autorisée.

Installation rapide (scaffold Cloudflare Pages) :

```bash
npm install privacynex-shield
npx privacynex-shield init --functions functions --public public
openssl rand -hex 32
```

La commande installée reste aussi disponible sous le nom court `pnx-shield`.

Avant toute mise en production, suivez la [checklist de déploiement](DEPLOYMENT.fr.md). Shield n'authentifie pas les API applicatives : les routes sous `/api/*` doivent conserver leur propre authentification et leurs propres autorisations.

La valeur générée doit être enregistrée comme secret `SHIELD_SECRET` dans le gestionnaire de secrets de votre plateforme, jamais dans Git ni dans une variable cliente.

Sur toute plateforme hors Cloudflare, réglez `SHIELD_CLIENT_IP_HEADER` sur l'en-tête qui porte l'IP client authentifiée chez votre hébergeur ou reverse proxy (par défaut `CF-Connecting-IP`). Pour un usage hors Cloudflare Pages, la fonction `shieldFetch(request, env, next)` exportée par `privacynex-shield/middleware` doit être câblée puis validée dans l'environnement cible. Le scaffold publié et la recette de release couvrent Cloudflare Pages/workerd ; les autres plateformes compatibles Fetch ne font pas partie de la matrice automatisée actuelle.

La page d'exemple propose un bouton **Run Shield again** pour rejouer le vrai
challenge. Son endpoint est limité aux requêtes `POST` same-origin sur une
adresse locale et n'est jamais copié par l'initialiseur. Il ne doit pas être
déployé en production.

## Ce qui est bloqué

Chaque requête aboutit à l'un de trois résultats : **refus** (403, aucun challenge proposé), **challenge** (preuve de travail avant tout contenu servi), ou **passage**.

<p align="center">
  <img src="./assets/slymb-privacynex-shield-decisions.webp" alt="Décisions Shield : autoriser, challenger ou refuser" width="100%" style="display:block;border-radius:14px;border:1px solid #2e2e2e;">
</p>

```text
Requête
  │
  ├─→ SHIELD_ENABLED=false ..................... passe sans contrôle
  ├─→ SHIELD_SECRET absent ..................... 503, échec fermé
  ├─→ /robots.txt /sitemap.xml /.well-known/* .. servi
  ├─→ UA crawler IA ou client scripté .......... 403
  │
  ├─→ /api/*  ─→ hors limite de débit .......... 403
  │             └→ sinon ....................... servi
  │
  └─→ document GET
        │
        │   la réponse d'origine est récupérée ici, puis inspectée
        │
        ├─→ réponse non HTML ................... servie telle quelle
        ├─→ hors limite de débit ............... 403
        ├─→ chemin sensible ou signal de refus . 403
        ├─→ plage IP de crawler vérifiée ....... servi
        ├─→ cookie de clearance valide ......... servi
        └─→ sinon .............................. page de challenge
```

L'origine est appelée avant la décision de filtrage afin que Shield puisse lire le `Content-Type` de la réponse : une URL qui ressemble à un asset mais renvoie du HTML reste protégée, et un vrai asset statique est servi intact. La réponse d'origine n'est jamais renvoyée à un visiteur qui n'a pas passé la barrière.

Le passage de la barrière se déroule ainsi :

```text
Page de challenge
  │
  ├─→ le navigateur résout une preuve de travail SHA-256 (Web Worker)
  ├─→ POST /api/shield-verify { challengeToken, nonce }
  │      ├─→ le serveur recalcule la preuve ..... invalide → 403
  │      ├─→ nonce hors de la plage signée ...... 403
  │      ├─→ challenge déjà consommé ............ rejeu    → 403
  │      └─→ cookie HMAC de clearance émis (24 h)
  │
  └─→ la page recharge, cookie vérifié, contenu servi
```

<p align="center">
  <img src="./assets/slymb-privacynex-shield-pow.webp" alt="Proof-of-work vérifié côté serveur : challenge signé, résolution et vérification" width="100%" style="display:block;border-radius:14px;border:1px solid #2e2e2e;">
</p>

**Refusés d'emblée**, sur User-Agent : les crawlers d'entraînement et de scraping IA qui se déclarent (GPTBot, ClaudeBot, CCBot, Bytespider, Google-Extended, Applebot-Extended, Meta-ExternalAgent, PetalBot, Amazonbot, cohere-ai, DeepSeekBot, Diffbot), ainsi que les clients HTTP scriptés et scanners de sécurité (python-requests, curl, wget, Scrapy, Censys, Shodan, sqlmap, nikto, et autres). Refusés également, quel que soit le User-Agent : les sondages de chemins sensibles (`/.env`, `/.git`, `/.ssh`, `/wp-admin`, `/phpmyadmin`, et autres).

Pour ces motifs de crawlers déclarés, le User-Agent sert à appliquer une politique d'opt-out ; ce n'est pas une vérification d'identité. Les clients automatisés utilisant une autre identité sont traités par le scoring et la preuve de travail.

**Challengés** : le reste du trafic non authentifié. La difficulté suit le score (environ 500 ms, 1 à 2 s, ou 4 à 8 s selon les signaux : TLS obsolète, ASN datacenter, en-têtes navigateur incohérents ou manquants, nœud de sortie Tor).

**Autorisés sans challenge sur les chemins éligibles** : les crawlers de recherche vérifiés par plage IP officielle. Les chemins d'infrastructure `/robots.txt`, `/favicon.ico`, `/sitemap.xml`, `/.well-known/security.txt`, `/.well-known/gpc.json` et `/cdn-cgi/*` restent également accessibles.

Le détail complet (poids de chaque signal, seuils, limites de débit) est dans [README.md](README.md#what-gets-blocked).

## Ajuster la liste d'ASN

`BAD_ASNS_PUBLIC` fournit volontairement une liste de départ courte et générique : hyperscalers couramment détournés et un réseau de scan documenté. Ce n'est pas un service de réputation.

Un ASN reconnu ajoute 20 points sur une requête de document et ne déclenche pas de refus à lui seul. Les autres signaux de la requête peuvent toujours modifier la décision finale.

Ajoutez vos propres ASN via la variable d'environnement `BAD_ASNS_EXTRA`, séparés par des virgules. Conserver cette liste dans une variable d'environnement évite de maintenir un fork du code pour une configuration propre au déploiement.

Sources de référence courantes, citées à titre indicatif et non auditées par ce projet, dont la licence et la pertinence restent à évaluer par vous-même : [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) publie des numéros d'AS, directement exploitables dans `BAD_ASNS_EXTRA`. [FireHOL](https://github.com/firehol/blocklist-ipsets), [IPsum](https://github.com/stamparm/ipsum), [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) et [AbuseIPDB](https://www.abuseipdb.com/) publient des adresses IP et des plages CIDR : celles-ci s'appliquent au WAF ou au pare-feu, en amont de Shield, pas dans `BAD_ASNS_EXTRA`.

Utilisez `SHIELD_DECISION_MODE=shadow` avant `multi` : ce mode conserve l'application de la politique `legacy` tout en calculant la décision multi-niveau, mais le paquet ne persiste aucune télémétrie shadow lui-même. Ajoutez l'observation dans l'application englobante si vous avez besoin d'une comparaison. Testez `SHIELD_COHERENCE_ENABLED=1` séparément, car ce réglage modifie le score et peut augmenter la difficulté PoW hors du mode `multi`.

## Tests et audit

Les tests sont dans `test/`, visibles et rejouables par quiconque. Ils encodent les invariants de sécurité : intégrité cryptographique (altération de challenge ou de cookie, changement de hostname, rejeu), contrôle d'accès (contenu HTML jamais servi sans clearance, chemins sensibles refusés, URL déguisée en asset), vérification des crawlers (User-Agent usurpé, plage IP officielle exigée, portée du helper de bypass limitée), limites d'entrée et de ressources, et absence de point d'injection HTML dans le client. Les API applicatives conservent toujours leurs propres contrôles d'accès.

Ce sont des garde-fous contre les régressions connues, pas une preuve d'absence de vulnérabilité. Toute revue indépendante est bienvenue : [CONTRIBUTING.md](CONTRIBUTING.md) pour proposer un test, [SECURITY.md](SECURITY.md) pour signaler une vulnérabilité en privé.

Le détail complet est dans [README.md](README.md#what-the-tests-cover).

Avant publication ou déploiement :

```bash
npm run check
npm pack --dry-run
```

La documentation complète est dans [README.md](README.md). Les règles publiques de version sont dans [VERSIONING.md](VERSIONING.md).

Licence : [Apache-2.0](LICENSE). Auteur : Slym B. Publication : Privacynex.

Les noms, marques, logos et l'identité visuelle Privacynex ne sont pas placés
sous licence Apache. Voir [TRADEMARKS.md](TRADEMARKS.md).

## Soutenir le projet

Si Privacynex Shield vous est utile, vous pouvez soutenir sa maintenance :

[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-soutenir-EA4AAA?logo=githubsponsors)](https://github.com/sponsors/slymb)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-soutenir-FFDD00?logo=buymeacoffee&logoColor=000000)](https://buymeacoffee.com/slym)
