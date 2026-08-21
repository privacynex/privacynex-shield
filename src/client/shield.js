/**
 * Privacynex Shield
 * Copyright (c) 2026 Slym B.
 * Licensed under the Apache License, Version 2.0
 */

/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield: Proof-of-Work page gate + bot detection
   Client-side SHA-256 challenge, zero external dependency.
   Works alongside any WAF as a second layer of defense.

   How it works:
   1. Check clearance cookie -> if valid, skip (zero overhead)
   2. Detect automation signals, escalate the visible challenge
   3. Server signs the SHA-256 challenge (embedded in page or via API)
   4. Web Worker brute-forces the solution
   5. On solve -> POST solution to /api/shield-verify
   6. Server re-verifies PoW + returns HMAC-SHA-256 signed cookie
   7. Set a cookie authenticated with the server secret
   8. Fail closed: if server unreachable -> error state, no cookie
   9. Next visit -> cookie valid -> instant pass

   Configuration (all optional):
   <script>
     window.PNX_SHIELD = {
       workerPath:  '/js/pow-worker.js',
       brandName:   'My Site',
       logoDark:    '/img/logo-dark.svg',
       logoLight:   '/img/logo-light.svg',
       texts: { ... } // custom i18n
     };
   </script>
   <script src="/js/pnx-shield.js"></script>
   ═══════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  // ---- Bounded presentation config. Security invariants stay server-side. ----
  var cfg = window.PNX_SHIELD && typeof window.PNX_SHIELD === 'object' ? window.PNX_SHIELD : {};
  var root = document.documentElement;

  function boundedNumber(value, fallback, min, max) {
    return Number.isFinite(value) ? Math.min(max, Math.max(min, Math.floor(value))) : fallback;
  }

  function boundedText(value, fallback, maxLength) {
    return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maxLength) : fallback;
  }

  function sameOriginPath(value, fallback) {
    if (typeof value !== 'string' || value.length > 200 || !value.startsWith('/')) return fallback;
    try {
      var resolved = new URL(value, location.origin);
      return resolved.origin === location.origin ? resolved.pathname : fallback;
    } catch (e) {
      return fallback;
    }
  }

  var FLAG_NAME = '__pnx_shield_ok';
  var COOKIE_TTL = 86400;
  var MAX_NUMBER = 100000;
  var POW_MAX_NORMAL = 100000;
  var POW_MAX_HARD = 400000;
  var OVERLAY_DELAY_EASY_MS = boundedNumber(cfg.overlayDelayEasy, 1500, 0, 5000);
  var OVERLAY_DELAY_NORMAL_MS = boundedNumber(cfg.overlayDelayNormal, 600, 0, 5000);
  var LOOP_GUARD_KEY = 'pnx_shield_loop_guard';
  var LOOP_GUARD_WINDOW_MS = 20000;
  var LOOP_GUARD_MAX_RELOADS = 3;
  var RELOAD_DEBOUNCE_KEY = 'pnx_shield_last_reload';
  var RELOAD_DEBOUNCE_MS = 3000;
  var WORKER_PATH = sameOriginPath(root.getAttribute('data-shield-worker') || cfg.workerPath, '/pnx-shield/pow-worker.js');
  var MASCOT_PATH = sameOriginPath(cfg.mascotPath, '');
  var LOGO_DARK = sameOriginPath(root.getAttribute('data-shield-logo') || cfg.logoDark, '');
  var LOGO_LIGHT = sameOriginPath(cfg.logoLight, LOGO_DARK);
  var BRAND_NAME = boundedText(root.getAttribute('data-shield-brand') || cfg.brandName, 'Protected site', 80);
  var CHALLENGE_ENDPOINT = '/api/shield-challenge';
  var VERIFY_ENDPOINT = '/api/shield-verify';

  // ---- Cookie helpers ----

  function getCookie(name) {
    var cookies = document.cookie.split(';');
    for (var i = 0; i < cookies.length; i++) {
      var c = cookies[i].trim();
      if (c.indexOf(name + '=') === 0) return c.substring(name.length + 1);
    }
    return null;
  }

  function clearCookie(name) {
    document.cookie = name + '=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax';
  }

  function isCleared() {
    var raw = getCookie(FLAG_NAME);
    if (!raw) return false;
    var ts = parseInt(raw, 10);
    if (isNaN(ts)) return false;
    return (Date.now() / 1000 - ts) < COOKIE_TTL;
  }

  // ---- Loop guard (prevents infinite reloads) ----

  function readLoopGuard() {
    try {
      var raw = sessionStorage.getItem(LOOP_GUARD_KEY);
      if (!raw) return { count: 0, firstTs: 0 };
      var parsed = JSON.parse(raw);
      if (!parsed || typeof parsed.count !== 'number' || typeof parsed.firstTs !== 'number') {
        return { count: 0, firstTs: 0 };
      }
      if (Date.now() - parsed.firstTs > LOOP_GUARD_WINDOW_MS) {
        return { count: 0, firstTs: 0 };
      }
      return parsed;
    } catch (e) {
      return { count: 0, firstTs: 0 };
    }
  }

  function writeLoopGuard(state) {
    try { sessionStorage.setItem(LOOP_GUARD_KEY, JSON.stringify(state)); } catch (e) {}
  }

  function clearLoopGuard() {
    try { sessionStorage.removeItem(LOOP_GUARD_KEY); } catch (e) {}
  }

  function reloadDebounced() {
    try {
      var raw = sessionStorage.getItem(RELOAD_DEBOUNCE_KEY);
      var lastTs = raw ? parseInt(raw, 10) : 0;
      if (!isNaN(lastTs) && Date.now() - lastTs < RELOAD_DEBOUNCE_MS) return false;
      sessionStorage.setItem(RELOAD_DEBOUNCE_KEY, String(Date.now()));
    } catch (e) {}
    location.reload();
    return true;
  }

  function hasLoopGuardLock() {
    var state = readLoopGuard();
    return state.count >= LOOP_GUARD_MAX_RELOADS;
  }

  function markShieldReload() {
    var state = readLoopGuard();
    var now = Date.now();
    if (!state.firstTs) {
      writeLoopGuard({ count: 1, firstTs: now });
      return;
    }
    writeLoopGuard({ count: state.count + 1, firstTs: state.firstTs });
  }

  // ---- Skip on static localhost, but run under Wrangler dev ----

  var h = location.hostname;
  var localShieldActive = document.documentElement.getAttribute('data-shield-active') === 'true';
  if ((h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0') && !localShieldActive) return;

  if (!localShieldActive) {
    clearLoopGuard();
    return;
  }
  clearCookie(FLAG_NAME);

  // ---- Bot detection signals (client-side, zero false positives) ----

  var ALLOWED_SEARCH_BOT_PATTERNS = [
    'OAI-SearchBot', 'Claude-SearchBot', 'PerplexityBot',
    'archive.org_bot', 'ia_archiver', 'Wayback', 'archive.org',
    'bnf.fr_bot'
  ];

  var BOT_UA_PATTERNS = [
    'GPTBot', 'ChatGPT-User',
    'ClaudeBot', 'Claude-Web', 'anthropic-ai',
    'CCBot', 'Bytespider', 'Google-Extended', 'Applebot-Extended',
    'Meta-ExternalAgent', 'meta-externalfetcher',
    'PetalBot', 'Amazonbot', 'cohere-ai', 'Diffbot',
    'Perplexity-User', 'DeepSeekBot',
    'TikTokSpider', 'SBIntuitionsBot', 'WRTNBot',
    'DataForSeoBot', 'Omgilibot', 'Brightbot',
    'PhindBot', 'YouBot', 'DuckAssistBot',
    'Crawl4AI', 'FirecrawlAgent', 'NovaAct',
    'python-requests/', 'python-urllib/', 'aiohttp/', 'httpx/',
    'curl/', 'wget/', 'libcurl/',
    'Go-http-client/', 'Java/', 'Apache-HttpClient/',
    'node-fetch/', 'axios/', 'got/',
    'Scrapy/', 'colly/', 'scraperapi',
    'HeadlessChrome', 'PhantomJS'
  ];
  function detectBot() {
    var ua = navigator.userAgent || '';

    for (var j = 0; j < ALLOWED_SEARCH_BOT_PATTERNS.length; j++) {
      if (ua.indexOf(ALLOWED_SEARCH_BOT_PATTERNS[j]) !== -1) return false;
    }

    // 1. WebDriver flag
    if (navigator.webdriver === true) return 'webdriver';

    // 2. Known bot UA patterns
    for (var i = 0; i < BOT_UA_PATTERNS.length; i++) {
      if (ua.indexOf(BOT_UA_PATTERNS[i]) !== -1) return 'ua:' + BOT_UA_PATTERNS[i];
    }

    // 3. Selenium globals (cdc_ prefixed vars)
    var keys = Object.keys(window);
    for (var k = 0; k < keys.length; k++) {
      if (/^(\$)?cdc_/.test(keys[k])) return 'selenium:cdc';
    }

    // 4. Selenium/WebDriver document-level artifacts
    var w = window;
    var d = document;
    if (w.__selenium_unwrapped || w.__webdriver_evaluate || w.__driver_evaluate ||
        w.__webdriver_unwrapped || w.__driver_unwrapped || w.__fxdriver_evaluate ||
        w.__fxdriver_unwrapped || d.__selenium_evaluate || d.__webdriver_evaluate) return 'selenium:globals';

    // 5. Puppeteer globals
    if (w.__puppeteer_evaluation_script__ || w.__pptr_evaluation ||
        w.__puppeteer_page_proxy__) return 'puppeteer';

    // 6. Playwright globals
    if (w.__playwright || w.__pw_manual || w.__playwright__binding__ ||
        w.__pwInitScripts || w.__playwright_target__ || w._playwrightGlobal ||
        w.__pw_api) return 'playwright';

    // 7. PhantomJS globals
    if (w.callPhantom || w._phantom || w.phantom) return 'phantomjs';

    // 8. Chrome DevTools Protocol automation
    if (w.domAutomation !== undefined || w.domAutomationController !== undefined) return 'cdp:automation';

    // 9. Headless dimensions
    if (window.outerWidth === 0 && window.outerHeight === 0) return 'headless:dims';

    return false;
  }

  // ---- Hex helper ----

  function toHex(buffer) {
    var arr = new Uint8Array(buffer);
    var hex = '';
    for (var i = 0; i < arr.length; i++) {
      hex += (arr[i] < 16 ? '0' : '') + arr[i].toString(16);
    }
    return hex;
  }

  // ---- Challenge reading ----

  function readEmbeddedChallenge() {
    var root = document.documentElement;
    if (!root || !root.getAttribute) return null;

    var token = root.getAttribute('data-shield-challenge-token');
    if (!token) return null;

    try {
      var data = {
        challengeToken: token,
        salt: root.getAttribute('data-shield-salt'),
        target: root.getAttribute('data-shield-target'),
        max: Number(root.getAttribute('data-shield-max'))
      };
      if (typeof data.challengeToken !== 'string' || data.challengeToken.length < 128 ||
          data.challengeToken.length > 1024 ||
          !/^[0-9a-f]{32}$/i.test(data.salt || '') ||
          !/^[0-9a-f]{64}$/i.test(data.target || '') ||
          !Number.isInteger(data.max) || data.max < 1000 || data.max > 1000000) {
        return null;
      }
      return data;
    } catch (e) {
      return null;
    }
  }

  function normalizeChallenge(data) {
    if (!data || typeof data.challengeToken !== 'string' || data.challengeToken.length < 128 ||
        data.challengeToken.length > 1024 || !/^[0-9a-f]{32}$/i.test(data.salt || '') ||
        !/^[0-9a-f]{64}$/i.test(data.target || '') || !Number.isInteger(data.max) ||
        data.max < 1000 || data.max > 1000000) {
      throw new Error('invalid-challenge');
    }
    return data;
  }

  function getOverlayDelay(maxNumber) {
    if (maxNumber >= POW_MAX_HARD) return 0;
    if (maxNumber >= POW_MAX_NORMAL) return OVERLAY_DELAY_NORMAL_MS;
    return OVERLAY_DELAY_EASY_MS;
  }

  // ---- Server-side verification ----

  var VERIFY_TIMEOUT = 5000;
  var RETRYABLE_CODES = [502, 503, 504];

  function fetchWithTimeout(url, options, timeout) {
    return new Promise(function(resolve, reject) {
      var controller = new AbortController();
      options.signal = controller.signal;
      var timer = setTimeout(function() { controller.abort(); reject(new Error('timeout')); }, timeout);
      fetch(url, options).then(function(res) { clearTimeout(timer); resolve(res); })
        .catch(function(err) { clearTimeout(timer); reject(err); });
    });
  }

  function doChallenge() {
    return fetchWithTimeout(CHALLENGE_ENDPOINT, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    }, VERIFY_TIMEOUT).then(function(res) {
      if (!res.ok) { var err = new Error('http-' + res.status); err.status = res.status; throw err; }
      return res.json();
    }).then(function(data) {
      if (!data.ok) throw new Error('challenge-failed');
      return normalizeChallenge(data);
    });
  }

  function tryServerChallenge() {
    return doChallenge().catch(function(err) {
      var isRetryable = !err.status || RETRYABLE_CODES.indexOf(err.status) !== -1;
      if (isRetryable) return doChallenge();
      throw err;
    });
  }

  function doVerify(challengeToken, nonce) {
    return fetchWithTimeout(VERIFY_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeToken: challengeToken, nonce: nonce })
    }, VERIFY_TIMEOUT).then(function(res) {
      if (!res.ok) { var err = new Error('http-' + res.status); err.status = res.status; throw err; }
      return res.json();
    }).then(function(data) {
      if (!data.ok) throw new Error('verify-failed');
      return data;
    });
  }

  function tryServerVerify(challengeToken, nonce) {
    return doVerify(challengeToken, nonce).catch(function(err) {
      var isRetryable = !err.status || RETRYABLE_CODES.indexOf(err.status) !== -1;
      if (isRetryable) {
        return doVerify(challengeToken, nonce).catch(function(retryErr) {
          if (retryErr.status === 403) retryErr.challengeConsumed = true;
          throw retryErr;
        });
      }
      throw err;
    });
  }

  // ---- i18n (FR/EN/ES/DE built-in, merge with user texts) ----

  var DEFAULT_TEXTS = {
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
      rateLimited: 'Trop de tentatives. Veuillez patienter quelques instants.'
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
      rateLimited: 'Too many attempts. Please wait a moment.'
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
      rateLimited: 'Demasiados intentos. Espere un momento.'
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
      rateLimited: 'Zu viele Versuche. Bitte warten Sie einen Moment.'
    }
  };

  var TEXTS = JSON.parse(JSON.stringify(DEFAULT_TEXTS));
  var SUPPORTED_LANGS = ['fr', 'en', 'es', 'de'];
  var SUPPORTED_TEXT_KEYS = ['title', 'message', 'solving', 'done', 'blocked', 'blockmsg', 'footer', 'errorTitle', 'errorMsg', 'errorRetry', 'rateLimited'];
  if (cfg.texts && typeof cfg.texts === 'object') {
    SUPPORTED_LANGS.forEach(function(lang) {
      var overrides = cfg.texts[lang];
      if (!overrides || typeof overrides !== 'object') return;
      SUPPORTED_TEXT_KEYS.forEach(function(key) {
        if (typeof overrides[key] === 'string') TEXTS[lang][key] = boundedText(overrides[key], TEXTS[lang][key], 240);
      });
    });
  }

  // ---- Styles (embedded, zero external dependency) ----

  var CSS = [
    'html.pnx-shield-active, body.pnx-shield-active {',
    '  height: 100%; overflow: hidden;',
    '}',
    'body.pnx-shield-active {',
    '  box-sizing: border-box; margin: 0; min-height: 100vh; min-height: 100dvh;',
    '  padding: 1rem; display: grid; place-items: center;',
    '  overflow: hidden; overscroll-behavior: none;',
    '  background: rgba(9,9,9,.92);',
    '  backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);',
    '  font-family: system-ui, -apple-system, sans-serif;',
    '  animation: pnxShieldIn .3s ease both;',
    '}',
    'html[data-theme="light"] body.pnx-shield-active { background: rgba(250,250,250,.92); }',
    '#pnx-shield { width: 100%; display: grid; place-items: center; }',
    '@keyframes pnxShieldIn { from { opacity: 0 } to { opacity: 1 } }',
    '@keyframes pnxShieldOut { from { opacity: 1 } to { opacity: 0 } }',

    '.pnx-s-box { width: min(92vw, 24rem); text-align: center; }',

    '.pnx-s-logo { margin-bottom: .8rem; }',
    '.pnx-s-logo img { height: 34px; width: auto; display: block; margin: 0 auto; }',

    '.pnx-s-mascot:empty { display: none; }',
    '.pnx-s-mascot { margin-bottom: .8rem; }',
    '.pnx-s-mascot img { width: 128px; height: 128px; image-rendering: pixelated; border-radius: 8px; }',

    '.pnx-s-card { background: #0f0f0f; border: 1px solid #1e1e1e; border-radius: 8px; overflow: hidden; padding: 1rem 1rem 0; }',
    'html[data-theme="light"] .pnx-s-card { background: #fff; border-color: #e0e0e0; }',

    '.pnx-s-inner { border: 1px solid #2a2a2a; border-radius: 4px; overflow: hidden; background: #0a0a0a; }',
    'html[data-theme="light"] .pnx-s-inner { border-color: #e8e8e8; background: #fafafa; }',

    '.pnx-s-header { padding: 1.4rem 1.6rem 1rem; }',
    '.pnx-s-header h2 { font-size: 1.1rem; font-weight: 700; letter-spacing: -.02em; color: #f0f0f0; margin: 0 0 .4rem; }',
    'html[data-theme="light"] .pnx-s-header h2 { color: #1a1a1a; }',
    '.pnx-s-header p { font-size: .75rem; color: #777; line-height: 1.5; margin: 0; }',

    '.pnx-s-progress-wrap { padding: 1.2rem 1.6rem 1.4rem; border-top: 1px solid #1e1e1e; }',
    'html[data-theme="light"] .pnx-s-progress-wrap { border-color: #e8e8e8; }',

    '.pnx-s-status { font-size: .65rem; color: #2ec4b6; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; margin-bottom: .6rem; display: flex; align-items: center; justify-content: center; gap: .4rem; }',
    '.pnx-s-status::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: #2ec4b6; animation: pnxPulse 1.4s infinite; }',
    '@keyframes pnxPulse { 0%,100% { opacity:1 } 50% { opacity:.3 } }',
    '.pnx-s-status.done { color: #2ec4b6; }',
    '.pnx-s-status.done::before { animation: none; opacity: 1; }',
    '.pnx-s-status.blocked { color: #e63946; }',
    '.pnx-s-status.blocked::before { background: #e63946; animation: none; }',

    '.pnx-s-bar-bg { height: 3px; background: #1a1a1a; border-radius: 2px; overflow: hidden; }',
    'html[data-theme="light"] .pnx-s-bar-bg { background: #e0e0e0; }',
    '.pnx-s-bar { height: 100%; width: 0%; background: #2ec4b6; border-radius: 2px; transition: width .3s ease; }',
    '.pnx-s-bar.blocked { background: #e63946; }',

    '.pnx-s-blocked-msg { padding: .8rem 1.6rem 1rem; font-size: .7rem; color: #999; line-height: 1.5; border-top: 1px solid #1e1e1e; text-align: center; }',
    'html[data-theme="light"] .pnx-s-blocked-msg { border-color: #e8e8e8; }',

    '.pnx-s-footer { padding: .8rem 1.6rem; display: flex; justify-content: space-between; align-items: center; font-size: .6rem; color: #444; }',
    '.pnx-s-lock { display: inline-flex; align-items: center; gap: .3rem; }',
    '.pnx-s-lock svg { width: 10px; height: 10px; fill: #444; display: block; }',

    '.pnx-s-status.error { color: #e6a23c; }',
    '.pnx-s-status.error::before { background: #e6a23c; animation: none; }',
    '.pnx-s-bar.error { background: #e6a23c; }',
    '.pnx-s-retry-btn { display: inline-block; margin-top: .6rem; padding: .4rem 1.2rem; font-size: .7rem; font-weight: 600; color: #fff; background: #2ec4b6; border: none; border-radius: 4px; cursor: pointer; font-family: inherit; letter-spacing: .02em; }',
    '.pnx-s-retry-btn:hover { background: #28b0a3; }'
  ].join('\n');

  // ---- Shield page guard (prevents DOM manipulation of the overlay) ----

  var shieldGuardTimer = null;
  var shieldGuardRoot = null;
  var shieldGuardObserver = null;

  function forceShieldVisible(root) {
    if (!root) return;
    root.hidden = false;
    root.style.setProperty('display', 'grid', 'important');
    root.style.setProperty('position', 'fixed', 'important');
    root.style.setProperty('inset', '0', 'important');
    root.style.setProperty('visibility', 'visible', 'important');
    root.style.setProperty('opacity', '1', 'important');
    root.style.setProperty('pointer-events', 'auto', 'important');
    root.style.setProperty('width', '100%', 'important');
    root.style.setProperty('height', '100%', 'important');
    root.style.setProperty('place-items', 'center', 'important');
  }

  function restoreShieldPage() {
    if (!shieldGuardRoot || !document.body) return;
    document.documentElement.classList.add('pnx-shield-active');
    document.body.classList.add('pnx-shield-active');
    if (document.body.firstElementChild !== shieldGuardRoot || document.body.childElementCount !== 1) {
      document.body.replaceChildren(shieldGuardRoot);
    }
    forceShieldVisible(shieldGuardRoot);
  }

  function hardenShieldPage(root) {
    shieldGuardRoot = root;
    restoreShieldPage();
    if (shieldGuardObserver) { shieldGuardObserver.disconnect(); }
    shieldGuardObserver = new MutationObserver(function() { forceShieldVisible(root); });
    shieldGuardObserver.observe(root, { attributes: true, attributeFilter: ['style', 'class', 'hidden'] });
    if (!shieldGuardTimer) { shieldGuardTimer = setInterval(restoreShieldPage, 250); }
  }

  // ---- Shield page creation ----

  function makeElement(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (typeof text === 'string') node.textContent = text;
    return node;
  }

  function createImage(src, alt, width, height) {
    var image = document.createElement('img');
    image.src = src;
    image.alt = alt;
    image.width = width;
    image.height = height;
    return image;
  }

  function createShieldPage(isBlocked) {
    var lang = document.documentElement.getAttribute('data-lang') || 'en';
    var t = TEXTS[lang] || TEXTS.en;

    if (!document.getElementById('pnx-shield-css')) {
      var style = document.createElement('style');
      style.id = 'pnx-shield-css';
      style.textContent = CSS;
      document.head.appendChild(style);
    }

    var overlay = makeElement('div');
    overlay.id = 'pnx-shield';
    overlay.style.cssText = 'position:fixed;inset:0;display:grid;place-items:center;width:100%;height:100%;';

    var box = makeElement('div', 'pnx-s-box');
    var logo = makeElement('div', 'pnx-s-logo');
    var isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    var logoSrc = isDark ? LOGO_DARK : LOGO_LIGHT;
    if (logoSrc) logo.appendChild(createImage(logoSrc, BRAND_NAME, 120, 34));
    box.appendChild(logo);

    var mascot = makeElement('div', 'pnx-s-mascot');
    if (MASCOT_PATH) mascot.appendChild(createImage(MASCOT_PATH, '', 128, 128));
    box.appendChild(mascot);

    var card = makeElement('div', 'pnx-s-card');
    var inner = makeElement('div', 'pnx-s-inner');
    var header = makeElement('div', 'pnx-s-header');
    header.appendChild(makeElement('h2', '', t.title));
    header.appendChild(makeElement('p', '', t.message));
    inner.appendChild(header);

    var progress = makeElement('div', 'pnx-s-progress-wrap');
    var status = makeElement('div', 'pnx-s-status' + (isBlocked ? ' blocked' : ''));
    if (!isBlocked) status.id = 'pnx-s-status';
    status.appendChild(makeElement('span', '', isBlocked ? t.blocked : t.solving));
    progress.appendChild(status);

    var barBackground = makeElement('div', 'pnx-s-bar-bg');
    var bar = makeElement('div', 'pnx-s-bar' + (isBlocked ? ' blocked' : ''));
    if (isBlocked) bar.style.width = '100%';
    else bar.id = 'pnx-s-bar';
    barBackground.appendChild(bar);
    progress.appendChild(barBackground);
    inner.appendChild(progress);

    if (isBlocked) inner.appendChild(makeElement('div', 'pnx-s-blocked-msg', t.blockmsg));
    card.appendChild(inner);

    var footer = makeElement('div', 'pnx-s-footer');
    footer.appendChild(makeElement('span', 'pnx-s-lock', t.footer));
    footer.appendChild(makeElement('span', '', BRAND_NAME));
    card.appendChild(footer);
    box.appendChild(card);
    overlay.appendChild(box);

    hardenShieldPage(overlay);
    return overlay;
  }

  // ---- Error + solved states ----

  function showErrorState(overlay, errorType) {
    var lang = document.documentElement.getAttribute('data-lang') || 'en';
    var t = TEXTS[lang] || TEXTS.en;

    var status = document.getElementById('pnx-s-status');
    var bar = document.getElementById('pnx-s-bar');

    if (status) {
      status.className = 'pnx-s-status error';
      status.querySelector('span').textContent = errorType === 'rate-limited' ? t.rateLimited : t.errorTitle;
    }
    if (bar) {
      bar.className = 'pnx-s-bar error';
      bar.style.width = '100%';
    }

    var progressWrap = overlay.querySelector('.pnx-s-progress-wrap');
    if (progressWrap) {
      var existing = overlay.querySelector('.pnx-s-error-wrap');
      if (existing) existing.remove();

      var errorWrap = document.createElement('div');
      errorWrap.className = 'pnx-s-error-wrap';
      errorWrap.style.cssText = 'padding:.6rem 1.6rem 1rem;border-top:1px solid #1e1e1e;text-align:center;';

      var errorMsg = document.createElement('p');
      errorMsg.style.cssText = 'font-size:.7rem;color:#999;line-height:1.5;margin:0 0 .4rem;';
      errorMsg.textContent = t.errorMsg;

      var retryBtn = document.createElement('button');
      retryBtn.className = 'pnx-s-retry-btn';
      retryBtn.textContent = t.errorRetry;
      retryBtn.addEventListener('click', function() {
        clearLoopGuard();
        clearCookie(FLAG_NAME);
        location.reload();
      });

      errorWrap.appendChild(errorMsg);
      errorWrap.appendChild(retryBtn);
      progressWrap.parentNode.insertBefore(errorWrap, progressWrap.nextSibling);
    }
  }

  function showSolvedState(overlay) {
    if (!overlay) return;
    var lang = document.documentElement.getAttribute('data-lang') || 'en';
    var t = TEXTS[lang] || TEXTS.en;
    var bar = document.getElementById('pnx-s-bar');
    var status = document.getElementById('pnx-s-status');
    if (bar) bar.style.width = '100%';
    if (status) {
      status.classList.add('done');
      status.querySelector('span').textContent = t.done;
    }
  }

  function onSolved(challenge, result, getOverlay, showOverlay, cancelScheduledOverlay) {
    var visibleOverlay = getOverlay();
    if (visibleOverlay) {
      var visibleBar = document.getElementById('pnx-s-bar');
      if (visibleBar) visibleBar.style.width = '100%';
    }

    if (!challenge.challengeToken) {
      cancelScheduledOverlay();
      showErrorState(showOverlay(), 'server-error');
      return;
    }

    tryServerVerify(challenge.challengeToken, result.n)
      .then(function() {
        cancelScheduledOverlay();
        var solvedOverlay = getOverlay();
        showSolvedState(solvedOverlay);
        markShieldReload();
        setTimeout(function() { location.reload(); }, solvedOverlay ? 350 : 0);
      })
      .catch(function(err) {
        cancelScheduledOverlay();
        if (err.challengeConsumed) {
          markShieldReload();
          reloadDebounced();
          return;
        }
        showErrorState(showOverlay(), err.status === 429 ? 'rate-limited' : 'server-error');
      });
  }

  // Some browsers or privacy extensions can abort a same-origin Worker without
  // a useful error. Continue in bounded asynchronous batches on the page. The
  // server still verifies the nonce and signed challenge before issuing access.
  function solveWithoutWorker(challenge, onProgress) {
    var batchSize = 128;
    var encoder = new TextEncoder();

    function solveBatch(start) {
      if (start > challenge.max) return Promise.resolve({ solved: false });
      var end = Math.min(start + batchSize, challenge.max + 1);
      var attempts = [];
      for (var nonce = start; nonce < end; nonce++) {
        (function(candidate) {
          attempts.push(
            crypto.subtle.digest('SHA-256', encoder.encode(challenge.salt + ':' + candidate))
              .then(function(buffer) { return { n: candidate, hash: toHex(buffer) }; })
          );
        }(nonce));
      }

      return Promise.all(attempts).then(function(results) {
        for (var index = 0; index < results.length; index++) {
          if (results[index].hash === challenge.target) {
            return { solved: true, n: results[index].n, hash: results[index].hash };
          }
        }
        onProgress(Math.min(end / challenge.max, 1));
        return new Promise(function(resolve) { setTimeout(resolve, 0); })
          .then(function() { return solveBatch(end); });
      });
    }

    return solveBatch(0);
  }

  // ---- Main init ----

  function init() {
    if (hasLoopGuardLock()) {
      clearCookie(FLAG_NAME);
      var lockedOverlay = createShieldPage(false);
      showErrorState(lockedOverlay, 'server-error');
      return;
    }

    if (typeof crypto === 'undefined' || !crypto.subtle) {
      var capabilityOverlay = createShieldPage(false);
      showErrorState(capabilityOverlay, 'server-error');
      return;
    }

    var botSignal = detectBot();
    var overlay = null;
    var overlayTimer = null;

    function getOverlay() { return overlay; }
    function showOverlay() { if (!overlay) overlay = createShieldPage(false); return overlay; }
    function cancelScheduledOverlay() { if (overlayTimer) { clearTimeout(overlayTimer); overlayTimer = null; } }

    function scheduleOverlay(delay) {
      cancelScheduledOverlay();
      if (delay <= 0) { showOverlay(); return; }
      overlayTimer = setTimeout(function() { overlayTimer = null; showOverlay(); }, delay);
    }

    function failClosed(errorType) {
      cancelScheduledOverlay();
      showErrorState(showOverlay(), errorType || 'server-error');
    }

    var challengeStartedAt = Date.now();
    scheduleOverlay(botSignal ? 0 : OVERLAY_DELAY_EASY_MS);

    // Prefer an embedded signed challenge, otherwise request one from the
    // same-origin endpoint shipped with the package.
    var embedded = readEmbeddedChallenge();
    var challengePromise = embedded ? Promise.resolve(embedded) : tryServerChallenge();

    challengePromise.then(function(challenge) {
      var worker = null;
      var fallbackStarted = false;
      var solved = false;
      var targetDelay = botSignal ? 0 : getOverlayDelay(challenge.max);
      var elapsed = Date.now() - challengeStartedAt;
      scheduleOverlay(Math.max(0, targetDelay - elapsed));

      function updateProgress(progress) {
        var bar = overlay ? document.getElementById('pnx-s-bar') : null;
        if (bar) bar.style.width = Math.round(progress * 100) + '%';
      }

      function handleSolverMessage(msg) {
        if (solved) return;
        if (msg.solved) {
          solved = true;
          if (worker) worker.terminate();
          onSolved(challenge, msg, getOverlay, showOverlay, cancelScheduledOverlay);
        } else if (typeof msg.progress === 'number') {
          updateProgress(msg.progress);
        } else if (msg.solved === false) {
          failClosed('server-error');
        }
      }

      function startFallback() {
        if (fallbackStarted || solved) return;
        fallbackStarted = true;
        solveWithoutWorker(challenge, updateProgress)
          .then(handleSolverMessage)
          .catch(function() { failClosed('server-error'); });
      }

      if (typeof Worker === 'undefined') {
        startFallback();
        return;
      }

      try {
        worker = new Worker(WORKER_PATH);
      } catch (e) {
        startFallback();
        return;
      }

      worker.onmessage = function(e) {
        handleSolverMessage(e.data);
      };

      worker.onerror = function() {
        if (worker) worker.terminate();
        worker = null;
        startFallback();
      };
      worker.postMessage({ salt: challenge.salt, target: challenge.target, max: challenge.max });
    }).catch(function() {
      failClosed('server-error');
    });
  }

  // ---- Boot ----

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.addEventListener('pageshow', function(e) {
    if (!e.persisted) return;
    if (!isCleared()) reloadDebounced();
  });

  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState !== 'visible') return;
    if (isCleared()) return;
    reloadDebounced();
  });
})();
