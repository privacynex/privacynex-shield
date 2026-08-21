export interface ShieldScoreResult {
    weight: number;
    signals: string[];
}
export declare function buildBadAsns(extraRaw?: string): ReadonlySet<number>;
export interface ScoreOptions {
    badAsns?: ReadonlySet<number>;
}
export declare function scoreRequest(request: Request, options?: ScoreOptions): ShieldScoreResult;
import { THRESHOLD_PASS, THRESHOLD_CHALLENGE, THRESHOLD_HARD, POW_MAX_EASY, POW_MAX_NORMAL, POW_MAX_HARD } from '../config/defaults.ts';
export { THRESHOLD_PASS, THRESHOLD_CHALLENGE, THRESHOLD_HARD, POW_MAX_EASY, POW_MAX_NORMAL, POW_MAX_HARD, };
/** Pick adaptive PoW max based on weight. */
export declare function pickPowMax(weight: number): number;
export declare function isHighRiskScore(weight: number): boolean;
