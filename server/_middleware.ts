/**
 * Privacynex Shield
 * Copyright (c) 2026 Slym B.
 * Licensed under the Apache License, Version 2.0
 */

import { shieldFetch, type ShieldEnv } from 'privacynex-shield/middleware';

interface PagesContext {
  request: Request;
  env: ShieldEnv;
  next: () => Promise<Response>;
}

/** Cloudflare Pages Functions entry point. Thin wrapper around `shieldFetch`,
    the runtime-agnostic gate exported by `privacynex-shield/middleware`. */
export async function onRequest(context: PagesContext): Promise<Response> {
  return shieldFetch(context.request, context.env, context.next);
}
