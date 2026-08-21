# Déploiement en production

Dernière revue : 21 août 2026.

Ce guide est la checklist de production de Privacynex Shield. Le paquet est une
barrière applicative pour les documents HTML. Il complète, sans les remplacer,
l'authentification, les autorisations, le WAF, les limites de débit de la
plateforme et la protection DDoS.

[English version](DEPLOYMENT.md)

## 1. Confirmer la frontière de confiance

Avant l'installation, vérifier tous les points suivants :

- le trafic atteint l'application en HTTPS ;
- l'edge ou le reverse proxy écrase l'en-tête choisi par
  `SHIELD_CLIENT_IP_HEADER` ;
- un client ne peut pas joindre directement une origine qui ferait confiance à
  un en-tête IP fourni par le client ;
- les gestionnaires `GET` protégés restent sans effet de bord avant la fin du
  challenge ;
- les API applicatives possèdent leur propre authentification et leurs propres
  autorisations.

Shield récupère la réponse d'origine avant de décider si un document HTML doit
être challengé. Ne rattachez aucun changement d'état à un `GET` protégé. Les
requêtes sous `/api/*` sont limitées en débit, mais Shield ne les authentifie
pas.

## 2. Installer et relire le scaffold

Utilisez Node.js 22 ou plus récent dans un checkout applicatif propre :

```bash
npm install privacynex-shield
npx privacynex-shield init --functions functions --public public
```

L'initialiseur refuse d'écraser un fichier existant. Relisez chaque fichier
généré avant de le committer. Si l'application possède déjà un middleware ou
l'une des routes API de Shield, fusionnez les gestionnaires manuellement sans
retirer les contrôles same-origin, taille de requête, signature et débit.

Pour un site statique publié depuis la racine du dépôt, utilisez `--public .`.
Les autres runtimes compatibles Fetch peuvent intégrer `shieldFetch`, mais
exigent un routage propre à la plateforme, un en-tête IP client de confiance et
une validation en environnement hors production.
Les autres runtimes compatibles avec l'API Fetch peuvent appeler `shieldFetch`
directement comme indiqué dans le [README français](README.fr.md).

## 3. Créer les secrets et la configuration

Générez un secret dédié de 256 bits :

```bash
openssl rand -hex 32
```

Enregistrez-le comme `SHIELD_SECRET` dans le gestionnaire de secrets de
l'hébergeur. Ne placez jamais cette valeur dans Git, une variable cliente, un
log de build, un ticket ou un fichier d'environnement committé. Utilisez une
valeur différente par environnement.

Gardez `SHIELD_POLICY_VERSION` stable en fonctionnement normal. Modifiez-la
lors d'une rotation de `SHIELD_SECRET` ou pour invalider tous les challenges et
cookies encore actifs. Traitez `SHIELD_ENABLED=false` comme un contournement
d'urgence et limitez strictement les personnes autorisées à le modifier.

Hors Cloudflare, configurez `SHIELD_CLIENT_IP_HEADER` uniquement avec un
en-tête écrit ou écrasé par l'edge de confiance. Sans cette garantie, n'utilisez
pas cet en-tête pour une décision de sécurité.

## 4. Valider avant la production

Déployez d'abord dans un environnement hors production avec un secret de test,
puis vérifiez :

- une page HTML protégée répond `503` lorsque `SHIELD_SECRET` manque ;
- la même page présente un challenge sans cookie de clearance valide ;
- un challenge valide produit un cookie de clearance sécurisé en HTTPS ;
- les appels cross-origin aux endpoints de challenge et de vérification sont
  refusés ;
- les assets statiques, `robots.txt`, le sitemap et les fichiers well-known
  requis restent accessibles ;
- le contenu protégé n'apparaît jamais dans la réponse de challenge ;
- l'authentification des API reste indépendante de Shield ;
- retirer Shield restaure le flux précédent sans migration de données.

Testez un trafic représentatif : mobile, desktop, proxy de confidentialité,
VPN et crawlers. Analysez les faux positifs avant d'activer des décisions plus
strictes.

`SHIELD_DECISION_MODE=shadow` conserve l'application de la politique `legacy`
tout en calculant la décision multi-niveau. Le paquet ne persiste aucune
télémétrie shadow lui-même. Ajoutez l'observation dans l'application englobante
si vous avez besoin d'une comparaison. `SHIELD_COHERENCE_ENABLED=1` modifie le
score et peut augmenter la difficulté PoW même hors du mode `multi` ; testez ce
réglage séparément avant la production.

## 5. Exploiter et effectuer une rotation sûre

Les états de limitation de débit et d'anti-rejeu résident en mémoire dans
chaque instance. Un déploiement multi-instance exigeant une application globale
doit fournir un stockage partagé ou un contrôle en amont. Shield ne fournit pas
cette coordination.

Pour effectuer une rotation :

1. générez et stockez un nouveau secret dans le gestionnaire de la plateforme ;
2. incrémentez `SHIELD_POLICY_VERSION` ;
3. déployez la configuration de manière atomique si possible ;
4. vérifiez les nouveaux challenges et cookies ;
5. retirez l'ancien secret de la plateforme.

Ne déployez jamais `example/functions/api/shield-demo-reset.ts`. Ce fichier sert
uniquement à la démonstration locale.

## 6. Vérifier une release

Les mainteneurs doivent exécuter :

```bash
npm ci
npm run check
npm audit
npm pack --dry-run
```

Inspectez la liste du paquet et confirmez la présence de `LICENSE`, `NOTICE`,
la documentation publique, les sources et les fichiers de distribution, sans
credentials, fichier d'environnement local, logs ni répertoire de dépendances.
