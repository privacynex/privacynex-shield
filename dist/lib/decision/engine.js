/* ═══════════════════════════════════════════════════════════════
   Privacynex Shield : Multi-level decision engine
   Pure function, no side effects, no environment access.

   5 levels: allow / log / soft-challenge / hard-challenge / deny

   Order of priority (first match wins):
    1. Sensitive path    -> deny
    2. Deny signal       -> deny
    3. Admin path        -> hard-challenge
    4. Hard signal       -> hard-challenge
    5. Score >= 40       -> hard-challenge
    6. Soft signal       -> soft-challenge
    7. Score >= 30       -> soft-challenge
    8. Log signal        -> log
    9. Score >= 15       -> log
   10. Otherwise         -> allow

   Mode control via SHIELD_DECISION_MODE env var:
   - "legacy" (default) : binary challenge/not, difficulty by score
   - "shadow"           : multi calculated without persistence, legacy applied
   - "multi"            : multi applied (5 levels active)
   ═══════════════════════════════════════════════════════════════ */
import { DENY_SIGNALS, HARD_CHALLENGE_SIGNALS, SOFT_CHALLENGE_SIGNALS, LOG_ONLY_SIGNALS, SENSITIVE_PATHS, ADMIN_PATHS, } from "../detection/bot-policy.js";
import { DECISION_SCORE_HARD, DECISION_SCORE_SOFT, DECISION_SCORE_LOG, SHIELD_DECISION_MODE_DEFAULT, } from "../config/defaults.js";
// ─── Mode resolution ───
const VALID_MODES = ['legacy', 'shadow', 'multi'];
export function getDecisionMode(env) {
    if (!env || typeof env.SHIELD_DECISION_MODE !== 'string')
        return SHIELD_DECISION_MODE_DEFAULT;
    const raw = env.SHIELD_DECISION_MODE.trim().toLowerCase();
    for (let i = 0; i < VALID_MODES.length; i++) {
        if (VALID_MODES[i] === raw)
            return VALID_MODES[i];
    }
    return SHIELD_DECISION_MODE_DEFAULT;
}
// ─── Helpers ───
function pathStartsWithAny(path, prefixes) {
    for (let i = 0; i < prefixes.length; i++) {
        if (path.startsWith(prefixes[i]))
            return true;
    }
    return false;
}
function signalsContainAny(signals, targets) {
    for (let i = 0; i < signals.length; i++) {
        const s = signals[i];
        for (let j = 0; j < targets.length; j++) {
            if (s === targets[j] || s.startsWith(targets[j]))
                return true;
        }
    }
    return false;
}
// ─── Main decision function ───
export function decideMultiLevel(input) {
    const { score, signals, path } = input;
    // 1. Sensitive path: deny directly
    if (pathStartsWithAny(path, SENSITIVE_PATHS)) {
        return { action: 'deny', reason: 'sensitive-path' };
    }
    // 2. Deny signal: deny directly
    if (signalsContainAny(signals, DENY_SIGNALS)) {
        return { action: 'deny', reason: 'deny-signal' };
    }
    // 3. Admin path: hard challenge
    if (pathStartsWithAny(path, ADMIN_PATHS)) {
        return { action: 'hard-challenge', reason: 'admin-path' };
    }
    // 4. Hard signal: hard challenge
    if (signalsContainAny(signals, HARD_CHALLENGE_SIGNALS)) {
        return { action: 'hard-challenge', reason: 'hard-signal' };
    }
    // 5. Score >= 40: hard challenge
    if (score >= DECISION_SCORE_HARD) {
        return { action: 'hard-challenge', reason: 'score-hard' };
    }
    // 6. Soft signal: soft challenge
    if (signalsContainAny(signals, SOFT_CHALLENGE_SIGNALS)) {
        return { action: 'soft-challenge', reason: 'soft-signal' };
    }
    // 7. Score >= 30: soft challenge
    if (score >= DECISION_SCORE_SOFT) {
        return { action: 'soft-challenge', reason: 'score-soft' };
    }
    // 8. Log signal: log only
    if (signalsContainAny(signals, LOG_ONLY_SIGNALS)) {
        return { action: 'log', reason: 'log-signal' };
    }
    // 9. Score >= 15: log
    if (score >= DECISION_SCORE_LOG) {
        return { action: 'log', reason: 'score-log' };
    }
    // 10. Default: allow
    return { action: 'allow', reason: 'clean' };
}
//# sourceMappingURL=engine.js.map