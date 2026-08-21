/** Cookie name for the clearance cookie.
    HTTPS deployments should use __Host- prefix for cookie prefix security. */
export declare const SHIELD_COOKIE_LOCAL = "__pnx_shield";
export declare const SHIELD_COOKIE_SECURE = "__Host-pnx_shield";
/** Readable flag cookie (not HttpOnly), contains a plain timestamp.
    Lets client-side JS skip the challenge UI when a valid cookie exists. */
export declare const FLAG_COOKIE_NAME = "__pnx_shield_ok";
/** Clearance duration in seconds. 24h = good balance between security and UX. */
export declare const COOKIE_TTL = 86400;
/** Maximum nonce to search. 100k = ~1-2s on modern desktop, ~3-4s on mobile. */
export declare const POW_MAX_NORMAL = 100000;
/** Easy difficulty: ~500ms. For clean traffic profiles. */
export declare const POW_MAX_EASY = 50000;
/** Hard difficulty: ~4-8s. For suspicious traffic profiles. */
export declare const POW_MAX_HARD = 400000;
/** Weight below which traffic passes without challenge (if cookie exists). */
export declare const THRESHOLD_PASS = 15;
/** Weight triggering normal challenge difficulty. */
export declare const THRESHOLD_CHALLENGE = 35;
/** Weight triggering hard challenge difficulty. */
export declare const THRESHOLD_HARD = 50;
/** Score >= 15: log event only, no action change. */
export declare const DECISION_SCORE_LOG = 15;
/** Score >= 30: soft challenge (easy PoW, ~500ms). */
export declare const DECISION_SCORE_SOFT = 30;
/** Score >= 40: hard challenge (~4-8s PoW). */
export declare const DECISION_SCORE_HARD = 40;
/** Max HTML document requests per minute per IP. */
export declare const RATELIMIT_DOC_MAX = 30;
/** Max API requests per minute per IP. */
export declare const RATELIMIT_API_MAX = 120;
/** Window size in seconds. */
export declare const RATELIMIT_WINDOW = 60;
/** Number of denies in the window to mark an IP as repeat offender. */
export declare const REPEAT_THRESHOLD = 3;
/** Observation window in seconds (1 hour). */
export declare const REPEAT_WINDOW = 3600;
/** Ban duration in seconds after threshold is reached (1 hour). */
export declare const REPEAT_BAN = 3600;
/** Challenge token validity in seconds (5 minutes). */
export declare const CHALLENGE_TTL = 300;
/** Delay before showing overlay for easy PoW (ms). Gives the worker time to
    solve silently. If the worker finishes before this delay, the overlay
    never appears. */
export declare const OVERLAY_DELAY_EASY_MS = 1500;
/** Delay for normal PoW. */
export declare const OVERLAY_DELAY_NORMAL_MS = 600;
/** Max reloads in the observation window before the client shows an error
    instead of reloading infinitely. */
export declare const LOOP_GUARD_MAX_RELOADS = 3;
/** Observation window in ms (20 seconds). */
export declare const LOOP_GUARD_WINDOW_MS = 20000;
/** Min interval between reloads in ms (debounce). */
export declare const RELOAD_DEBOUNCE_MS = 3000;
/** Max POST /api/shield-verify per minute per IP. */
export declare const VERIFY_RL_MAX = 10;
export declare const VERIFY_RL_WINDOW = 60;
/** Enable the Shield. Set to 'false' to disable entirely. */
export declare const SHIELD_ENABLED_DEFAULT = true;
/** Enable header coherence checks. Opt-in, shadow mode available. */
export declare const SHIELD_COHERENCE_DEFAULT = false;
/** Decision mode: 'legacy' (binary challenge/not), 'shadow' (log multi-level
    alongside legacy), 'multi' (apply multi-level decisions). */
export declare const SHIELD_DECISION_MODE_DEFAULT: "legacy";
/** Enable email alerts. Requires KV binding + mailer implementation. */
export declare const SHIELD_ALERTS_ENABLED_DEFAULT = false;
/** Alert aggregation window in hours (1, 2, 3, 4, 6, 8, 12, 24). */
export declare const SHIELD_ALERT_BUCKET_HOURS = 4;
/** Alert email subject prefix. */
export declare const SHIELD_ALERT_SUBJECT_PREFIX = "[pnx-shield]";
export declare const WORKER_PATH_DEFAULT = "/js/pow-worker.js";
export declare const BAD_ASNS_PUBLIC: readonly number[];
export declare const ICLOUD_RELAY_ASNS: readonly number[];
export declare const RESIDENTIAL_ASNS_HINT: readonly number[];
export declare const DEFAULT_TEXTS: {
    readonly fr: {
        readonly title: "Vérification de sécurité";
        readonly message: "Nous vérifions que votre connexion est sécurisée.";
        readonly solving: "Analyse en cours...";
        readonly done: "Vérification terminée";
        readonly blocked: "Accès bloqué";
        readonly blockmsg: "Accès refusé. Votre requête a été identifiée comme automatisée.";
        readonly footer: "Protection automatique";
        readonly errorTitle: "Erreur de vérification";
        readonly errorMsg: "Le contrôle de sécurité a échoué. Veuillez réessayer.";
        readonly errorRetry: "Réessayer";
        readonly rateLimited: "Trop de tentatives. Veuillez patienter quelques instants.";
    };
    readonly en: {
        readonly title: "Security check";
        readonly message: "We are verifying that your connection is secure.";
        readonly solving: "Analyzing...";
        readonly done: "Verification complete";
        readonly blocked: "Access blocked";
        readonly blockmsg: "Access denied. Your request has been identified as automated.";
        readonly footer: "Automatic protection";
        readonly errorTitle: "Verification error";
        readonly errorMsg: "The security check failed. Please try again.";
        readonly errorRetry: "Retry";
        readonly rateLimited: "Too many attempts. Please wait a moment.";
    };
    readonly es: {
        readonly title: "Verificación de seguridad";
        readonly message: "Estamos verificando que su conexión es segura.";
        readonly solving: "Analizando...";
        readonly done: "Verificación completada";
        readonly blocked: "Acceso bloqueado";
        readonly blockmsg: "Acceso denegado. Su solicitud ha sido identificada como automatizada.";
        readonly footer: "Protección automática";
        readonly errorTitle: "Error de verificación";
        readonly errorMsg: "La verificación de seguridad falló. Inténtelo de nuevo.";
        readonly errorRetry: "Reintentar";
        readonly rateLimited: "Demasiados intentos. Espere un momento.";
    };
    readonly de: {
        readonly title: "Sicherheitsprüfung";
        readonly message: "Wir überprüfen, dass Ihre Verbindung sicher ist.";
        readonly solving: "Analyse läuft...";
        readonly done: "Überprüfung abgeschlossen";
        readonly blocked: "Zugang blockiert";
        readonly blockmsg: "Zugang verweigert. Ihre Anfrage wurde als automatisiert identifiziert.";
        readonly footer: "Automatischer Schutz";
        readonly errorTitle: "Überprüfungsfehler";
        readonly errorMsg: "Die Sicherheitsüberprüfung ist fehlgeschlagen. Bitte versuchen Sie es erneut.";
        readonly errorRetry: "Erneut versuchen";
        readonly rateLimited: "Zu viele Versuche. Bitte warten Sie einen Moment.";
    };
};
export type ShieldLanguage = keyof typeof DEFAULT_TEXTS;
