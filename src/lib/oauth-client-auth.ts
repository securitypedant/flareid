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
    return { clientId: decoded.slice(0, separatorIndex), clientSecret: decoded.slice(separatorIndex + 1) };
  } catch {
    return null;
  }
}

/** Authenticates a confidential OAuth client via HTTP Basic or client_id/client_secret in the request body. */
export async function authenticateClient(
  env: Env,
  body: Record<string, unknown>,
  authHeader: string | undefined
): Promise<OAuthClientRow | null> {
  const basic = parseBasicAuth(authHeader);
  const clientId = basic?.clientId ?? String(body.client_id ?? "");
  const clientSecret = basic?.clientSecret ?? String(body.client_secret ?? "");
  if (!clientId || !clientSecret) return null;

  const client = await getClientByClientId(env, clientId);
  if (!client) return null;

  const providedHash = await sha256Hex(clientSecret);
  return providedHash === client.client_secret_hash ? client : null;
}
