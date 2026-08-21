/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Default configuration
   Conservative defaults. Every setting is optional.
   Server integrations may expose a bounded subset through environment variables.

   Design constraint: security decisions remain server-controlled.
   ═══════════════════════════════════════════════════════════════ */

// ─── Cookie settings ───

/** Cookie name for the clearance cookie.
    HTTPS deployments should use __Host- prefix for cookie prefix security. */
export const SHIELD_COOKIE_LOCAL = '__pnx_shield';
export const SHIELD_COOKIE_SECURE = '__Host-pnx_shield';
/** Readable flag cookie (not HttpOnly), contains a plain timestamp.
    Lets client-side JS skip the challenge UI when a valid cookie exists. */
export const FLAG_COOKIE_NAME = '__pnx_shield_ok';
/** Clearance duration in seconds. 24h = good balance between security and UX. */
export const COOKIE_TTL = 86400;

// ─── PoW difficulty (default: ~1-2s on modern hardware) ───

/** Maximum nonce to search. 100k = ~1-2s on modern desktop, ~3-4s on mobile. */
export const POW_MAX_NORMAL = 100000;
/** Easy difficulty: ~500ms. For clean traffic profiles. */
export const POW_MAX_EASY = 50000;
/** Hard difficulty: ~4-8s. For suspicious traffic profiles. */
export const POW_MAX_HARD = 400000;

// ─── Scoring thresholds ───

/** Weight below which traffic passes without challenge (if cookie exists). */
export const THRESHOLD_PASS = 15;
/** Weight triggering normal challenge difficulty. */
export const THRESHOLD_CHALLENGE = 35;
/** Weight triggering hard challenge difficulty. */
export const THRESHOLD_HARD = 50;

// ─── Multi-level decision thresholds (for the decision engine) ───

/** Score >= 15: log event only, no action change. */
export const DECISION_SCORE_LOG = 15;
/** Score >= 30: soft challenge (easy PoW, ~500ms). */
export const DECISION_SCORE_SOFT = 30;
/** Score >= 40: hard challenge (~4-8s PoW). */
export const DECISION_SCORE_HARD = 40;

// ─── Rate limiting ───

/** Max HTML document requests per minute per IP. */
export const RATELIMIT_DOC_MAX = 30;
/** Max API requests per minute per IP. */
export const RATELIMIT_API_MAX = 120;
/** Window size in seconds. */
export const RATELIMIT_WINDOW = 60;

// ─── Repeat offender ───

/** Number of denies in the window to mark an IP as repeat offender. */
export const REPEAT_THRESHOLD = 3;
/** Observation window in seconds (1 hour). */
export const REPEAT_WINDOW = 3600;
/** Ban duration in seconds after threshold is reached (1 hour). */
export const REPEAT_BAN = 3600;

// ─── Challenge settings ───

/** Challenge token validity in seconds (5 minutes). */
export const CHALLENGE_TTL = 300;

// ─── Overlay display delays (client-side) ───

/** Delay before showing overlay for easy PoW (ms). Gives the worker time to
    solve silently. If the worker finishes before this delay, the overlay
    never appears. */
export const OVERLAY_DELAY_EASY_MS = 1500;
/** Delay for normal PoW. */
export const OVERLAY_DELAY_NORMAL_MS = 600;

// ─── Loop guard (client-side) ───

/** Max reloads in the observation window before the client shows an error
    instead of reloading infinitely. */
export const LOOP_GUARD_MAX_RELOADS = 3;
/** Observation window in ms (20 seconds). */
export const LOOP_GUARD_WINDOW_MS = 20000;
/** Min interval between reloads in ms (debounce). */
export const RELOAD_DEBOUNCE_MS = 3000;

// ─── Verify endpoint rate limit (server-side) ───

/** Max POST /api/shield-verify per minute per IP. */
export const VERIFY_RL_MAX = 10;
export const VERIFY_RL_WINDOW = 60;

// ─── Feature flags (environment variables override) ───

/** Enable the Shield. Set to 'false' to disable entirely. */
export const SHIELD_ENABLED_DEFAULT = true;
/** Enable header coherence checks. Opt-in, shadow mode available. */
export const SHIELD_COHERENCE_DEFAULT = false;
/** Decision mode: 'legacy' (binary challenge/not), 'shadow' (log multi-level
    alongside legacy), 'multi' (apply multi-level decisions). */
export const SHIELD_DECISION_MODE_DEFAULT = 'legacy' as const;
/** Enable email alerts. Requires KV binding + mailer implementation. */
export const SHIELD_ALERTS_ENABLED_DEFAULT = false;
/** Alert aggregation window in hours (1, 2, 3, 4, 6, 8, 12, 24). */
export const SHIELD_ALERT_BUCKET_HOURS = 4;
/** Alert email subject prefix. */
export const SHIELD_ALERT_SUBJECT_PREFIX = '[pnx-shield]';

// ─── Client-side worker path ───

export const WORKER_PATH_DEFAULT = '/js/pow-worker.js';

// ─── Public BAD_ASNS (intentionally light) ───
// These are widely-known hyperscalers and documented scanners.
// Operators can extend the list via BAD_ASNS_EXTRA without maintaining
// deployment-specific source changes.

export const BAD_ASNS_PUBLIC: readonly number[] = [
  // Hyperscalers commonly abused by scrapers
  16509,  // Amazon AWS
  14618,  // Amazon AWS us-east-1
  14061,  // DigitalOcean
  24940,  // Hetzner
  16276,  // OVH
  63949,  // Akamai / Linode
  45102,  // Alibaba Cloud
  396982, // Google Cloud
  // Known mass scanners
  398324, // Censys
  // Common scraping infrastructure
  51167,  // Contabo
  132203, // Tencent Cloud
  45090,  // Tencent Cloud (secondary)
];

// ─── iCloud Private Relay ASNs (trust boost) ───
export const ICLOUD_RELAY_ASNS: readonly number[] = [714, 6185];

// ─── Residential ASN hints (trust boost) ───
export const RESIDENTIAL_ASNS_HINT: readonly number[] = [
  3320,  // Deutsche Telekom
  5410,  // Bouygues
  12322, // Free
  3215,  // Orange
  7018,  // AT&T
  7922,  // Comcast
  701,   // Verizon
];

// ─── Client-side i18n defaults ───

export const DEFAULT_TEXTS = {
  fr: {
    title:    'Vérification de sécurité',
    message:  'Nous vérifions que votre connexion est sécurisée.',
    solving:  'Analyse en cours...',
    done:     'Vérification terminée',
    blocked:  'Accès bloqué',
    blockmsg: 'Accès refusé. Votre requête a été identifiée comme automatisée.',
    footer:   'Protection automatique',
    errorTitle: 'Erreur de vérification',
    errorMsg:   'Le contrôle de sécurité a échoué. Veuillez réessayer.',
    errorRetry: 'Réessayer',
    rateLimited: 'Trop de tentatives. Veuillez patienter quelques instants.',
  },
  en: {
    title:    'Security check',
    message:  'We are verifying that your connection is secure.',
    solving:  'Analyzing...',
    done:     'Verification complete',
    blocked:  'Access blocked',
    blockmsg: 'Access denied. Your request has been identified as automated.',
    footer:   'Automatic protection',
    errorTitle: 'Verification error',
    errorMsg:   'The security check failed. Please try again.',
    errorRetry: 'Retry',
    rateLimited: 'Too many attempts. Please wait a moment.',
  },
  es: {
    title:    'Verificación de seguridad',
    message:  'Estamos verificando que su conexión es segura.',
    solving:  'Analizando...',
    done:     'Verificación completada',
    blocked:  'Acceso bloqueado',
    blockmsg: 'Acceso denegado. Su solicitud ha sido identificada como automatizada.',
    footer:   'Protección automática',
    errorTitle: 'Error de verificación',
    errorMsg:   'La verificación de seguridad falló. Inténtelo de nuevo.',
    errorRetry: 'Reintentar',
    rateLimited: 'Demasiados intentos. Espere un momento.',
  },
  de: {
    title:    'Sicherheitsprüfung',
    message:  'Wir überprüfen, dass Ihre Verbindung sicher ist.',
    solving:  'Analyse läuft...',
    done:     'Überprüfung abgeschlossen',
    blocked:  'Zugang blockiert',
    blockmsg: 'Zugang verweigert. Ihre Anfrage wurde als automatisiert identifiziert.',
    footer:   'Automatischer Schutz',
    errorTitle: 'Überprüfungsfehler',
    errorMsg:   'Die Sicherheitsüberprüfung ist fehlgeschlagen. Bitte versuchen Sie es erneut.',
    errorRetry: 'Erneut versuchen',
    rateLimited: 'Zu viele Versuche. Bitte warten Sie einen Moment.',
  },
} as const;

export type ShieldLanguage = keyof typeof DEFAULT_TEXTS;
