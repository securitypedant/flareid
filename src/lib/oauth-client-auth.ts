import type { Env } from "../env.js";
import { getClientByClientId } from "./db.js";
import { sha256Hex } from "./tokens.js";
import type { OAuthClientRow } from "./types.js";

function parseBasicAuth(header: string | undefined): { clientId: string; clientSecret: string } | null {
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice("Basic ".length));
    const separatorIndex = decoded.indexOf(":");
    if (separatorIndex === -1) return null;
    return { clientId: decodeURIComponent(decoded.slice(0, separatorIndex)), clientSecret: decodeURIComponent(decoded.slice(separatorIndex + 1)) };
  } catch {
    return null;
  }
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

/**
 * Authenticates an OAuth client at the token, introspection and revocation
 * endpoints.
 *
 * Confidential clients: HTTP Basic or client_id/client_secret in the body.
 * Public clients (token_endpoint_auth_method "none"): client_id alone, and
 * only where `allowPublic` - at /token, where PKCE binds the code to the app
 * that started the flow instead of a secret. A public client presenting a
 * secret is refused rather than ignored: it is misconfigured, and silently
 * accepting would hide that.
 */
export async function authenticateClient(
  env: Env,
  body: Record<string, unknown>,
  authHeader: string | undefined,
  opts: { allowPublic?: boolean } = {}
): Promise<OAuthClientRow | null> {
  const basic = parseBasicAuth(authHeader);
  const clientId = basic?.clientId ?? String(body.client_id ?? "");
  const clientSecret = basic?.clientSecret ?? String(body.client_secret ?? "");
  if (!clientId) return null;

  const client = await getClientByClientId(env, clientId);
  if (!client) return null;

  if (client.client_type === "public") return opts.allowPublic && !clientSecret ? client : null;
  if (!clientSecret || !client.client_secret_hash) return null;
  return timingSafeEqualHex(await sha256Hex(clientSecret), client.client_secret_hash) ? client : null;
}
