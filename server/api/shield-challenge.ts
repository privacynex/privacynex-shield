import { handleShieldChallenge, handleShieldChallengeOptions, type ChallengeEnv } from 'privacynex-shield/challenge';
import { returnInternal404 } from 'privacynex-shield/internal-api';

interface Context {
  request: Request;
  env: ChallengeEnv;
}

export const onRequest = (context: Context): Response => returnInternal404(context.request);
export const onRequestOptions = (context: Context): Response => handleShieldChallengeOptions(context.request);
export const onRequestGet = (context: Context): Promise<Response> => handleShieldChallenge(context.request, context.env);
