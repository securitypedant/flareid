import type { Env } from "../env.js";
import { getSetting } from "./settings.js";

/**
 * The issuer FlareID identifies itself as, when the ISSUER_URL var is empty.
 *
 * A Deploy to Cloudflare deployment cannot know its hostname in advance - it is
 * a workers.dev name chosen in the dashboard, or a custom domain added later -
 * so the issuer is worked out at runtime, in this order:
 *
 *   1. the ISSUER_URL var, when it is set: pinned, always wins;
 *   2. the issuer stored when first-run setup completed (idp_settings
 *      `issuer_url`, written by markSetupCompleted from the origin the
 *      administrator used), so it never drifts afterwards;
 *   3. before setup, the origin of the request itself.
 *
 * (3) reads the Host the request arrived on. On Workers only hostnames routed
 * to this Worker (its workers.dev name, its custom domains and routes) arrive
 * at all, so it cannot be pointed at an attacker's name, but it is still only
 * accepted over https - plus plain http for localhost, for `wrangler dev`.
 *
 * The rule for deployers: add the custom domain BEFORE running setup (and open
 * /setup on it), or set the ISSUER_URL var to pin it.
 */
export const ISSUER_SETTING = "issuer_url";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** The request's origin, if it is acceptable as an issuer: https, or http on localhost. */
export function acceptableOrigin(url: string | URL): string | null {
  let u: URL;
  try {
    u = typeof url === "string" ? new URL(url) : url;
  } catch {
    return null;
  }
  if (u.protocol === "https:") return u.origin;
  if (u.protocol === "http:" && LOCAL_HOSTS.has(u.hostname)) return u.origin;
  return null;
}

/**
 * The stored issuer. It is written once (setup completion) and never changed,
 * so an isolate can keep it once it has seen it; a null answer is not kept,
 * because setup may complete on another isolate at any moment.
 */
let cachedStoredIssuer: string | null = null;

export async function storedIssuer(env: Env): Promise<string | null> {
  if (cachedStoredIssuer) return cachedStoredIssuer;
  const value = await getSetting(env, ISSUER_SETTING).catch(() => null);
  if (value) cachedStoredIssuer = value;
  return value || null;
}

/** For tests, which reset the database between cases. */
export function forgetStoredIssuer(): void {
  cachedStoredIssuer = null;
}

/**
 * The env the app runs with: ISSUER_URL filled in. Returns a Response instead
 * when there is no issuer to be had - a plain-http request to an instance that
 * has neither a pinned nor a stored issuer.
 */
export async function withResolvedIssuer(env: Env, request: Request): Promise<Env | Response> {
  if (env.ISSUER_URL) return env;
  const issuer = (await storedIssuer(env)) ?? acceptableOrigin(request.url);
  if (!issuer) {
    return new Response("FlareID only answers over HTTPS. Open this address with https:// instead.", {
      status: 400,
      headers: { "Content-Type": "text/plain; charset=UTF-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'" },
    });
  }
  return { ...env, ISSUER_URL: issuer };
}

/** For the Cron Trigger: the pinned or stored issuer, or "" when setup has not happened (no request to take one from). */
export async function scheduledEnv(env: Env): Promise<Env> {
  if (env.ISSUER_URL) return env;
  return { ...env, ISSUER_URL: (await storedIssuer(env)) ?? "" };
}
