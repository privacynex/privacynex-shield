export type ShieldDecisionMode = 'legacy' | 'shadow' | 'multi';
export type ShieldAction = 'allow' | 'log' | 'soft-challenge' | 'hard-challenge' | 'deny';
export interface DecisionInput {
    readonly score: number;
    readonly signals: readonly string[];
    readonly path: string;
}
export interface DecisionEnv {
    readonly SHIELD_DECISION_MODE?: string;
}
export declare function getDecisionMode(env: DecisionEnv | undefined): ShieldDecisionMode;
export declare function decideMultiLevel(input: DecisionInput): {
    action: ShieldAction;
    reason: string;
};
