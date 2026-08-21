export interface CoherenceResult {
    weight: number;
    signals: string[];
}
/**
 * Run all coherence checks against the request.
 * Returns signals and their combined weight.
 * Callers decide whether to add these weights to the main score.
 */
export declare function scoreCoherence(request: Request): CoherenceResult;
