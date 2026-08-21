import { returnInternal404 } from 'privacynex-shield/internal-api';
import { handleShieldVerify, handleShieldVerifyOptions, type VerifyEnv } from 'privacynex-shield/verify';

interface Context {
  request: Request;
  env: VerifyEnv;
}

export const onRequest = (context: Context): Response => returnInternal404(context.request);
export const onRequestOptions = (context: Context): Response => handleShieldVerifyOptions(context.request);
export const onRequestPost = (context: Context): Promise<Response> => handleShieldVerify(context.request, context.env);
