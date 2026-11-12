import type { Context, Next } from "hono";
import type { Env } from "../env.js";
import { isSetupCompleted } from "./settings.js";
import { hasScope, KEY_PREFIX, keyDisplayPrefix, parseScopes, touchApiKey, verifyApiKey, type ApiScope } from "./api-keys.js";
import { expand, grants, LEGACY_SCOPES } from "./permissions.js";
import { sha256Hex } from "./tokens.js";
import { logAudit } from "./audit.js";

declare module "hono" {
  interface ContextVariableMap {
    /** Who is making an /api/v1 call - either the one-shot bootstrap secret, or a minted key. */
    apiActor: ApiActor;
  }
}

export interface ApiActor {
  kind: "bootstrap" | "key";
  /** Name recorded in the audit log. Keys use their own name; the bootstrap secret has a fixed one. */
  label: string;
  scopes: ApiScope[];
  keyId?: number;
}

/**
 * Compares two hex digests without leaking where they first differ.
 *
 * Needed only for the bootstrap token: API keys are found by hashing the
 * presented value and looking the hash up, so there is nothing to compare, but
 * the bootstrap secret lives in an environment variable and is compared
 * directly.
 */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

function bearerToken(c: Context<{ Bindings: Env }>): string | null {
  const header = c.req.header("Authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) return null;
  const token = header.slice(7).trim();
  return token === "" ? null : token;
}

/**
 * The bootstrap secret, and the one thing worth understanding about it.
 *
 * A freshly deployed FlareID has no users at all - the migrations no longer
 * ship an administrator, because publishing a known password hash in an
 * open-source repository is not a thing we are willing to do. So there has to
 * be some way in that is not "log in", and that is this: a secret set at deploy
 * time which can configure the instance exactly once.
 *
 * It stops working the moment setup completes. After that it is accepted only
 * by POST /api/v1/recovery/admin-reset, the deliberate break-glass path, which
 * is loudly audited. Removing the secret from the Worker disables even that.
 */
export async function bootstrapTokenValid(env: Env, token: string): Promise<boolean> {
  if (!env.BOOTSTRAP_TOKEN || isPlaceholderSecret(env.BOOTSTRAP_TOKEN)) return false;
  const [presented, expected] = await Promise.all([sha256Hex(token), sha256Hex(env.BOOTSTRAP_TOKEN)]);
  return timingSafeEqualHex(presented, expected);
}

/**
 * The values .dev.vars.example ships with all start "replace-me". The Deploy
 * to Cloudflare flow offers them as defaults, so a deployer who clicks through
 * would otherwise have a bootstrap token printed in a public repository.
 */
export function isPlaceholderSecret(value: string): boolean {
  return value.trim().toLowerCase().startsWith("replace-me");
}

/**
 * Authenticates an /api/v1 request. Does not authorize it - routes declare what
 * they need with requireScope().
 */
export async function requireApiAuth(c: Context<{ Bindings: Env }>, next: Next) {
  const token = bearerToken(c);
  if (!token) {
    return c.json({ error: "unauthorized", message: "Expected an Authorization: Bearer <token> header." }, 401, {
      "WWW-Authenticate": 'Bearer realm="flareid"',
    });
  }

  if (await bootstrapTokenValid(c.env, token)) {
    // Pre-setup it can do anything; post-setup only the recovery route accepts
    // it, which that route checks for itself (this middleware deliberately does
    // not know about individual paths).
    const setupDone = await isSetupCompleted(c.env);
    c.set("apiActor", {
      kind: "bootstrap",
      label: "bootstrap-token",
      scopes: setupDone ? [] : ["admin"],
    });
    await next();
    await logApiRequest(c);
    return;
  }

  const key = await verifyApiKey(c.env, token);
  if (!key) {
    // Only tokens shaped like a FlareID key are recorded - someone presenting a
    // revoked or expired key is worth seeing; arbitrary scanner noise is not.
    // The stored, non-secret prefix is all that is logged, never the token.
    if (token.startsWith(KEY_PREFIX)) {
      await logAudit(c.env, null, "api.auth_failed", `${c.req.method} ${new URL(c.req.url).pathname}`, { key_prefix: keyDisplayPrefix(token) }, c.req.raw);
    }
    return c.json({ error: "unauthorized", message: "Unknown, revoked or expired token." }, 401);
  }

  c.set("apiActor", { kind: "key", label: `api-key:${key.name}`, scopes: parseScopes(key.scopes), keyId: key.id });
  await touchApiKey(c.env, key.id);
  await next();
  await logApiRequest(c);
}

/**
 * One log entry per authenticated API call, reads included - the routes log
 * what they changed, this logs that the key was used at all, and with what
 * result (a 403 here is a key reaching beyond its scopes).
 */
async function logApiRequest(c: Context<{ Bindings: Env }>): Promise<void> {
  const actor = c.get("apiActor");
  await logAudit(
    c.env,
    auditActor(actor),
    "api.request",
    `${c.req.method} ${new URL(c.req.url).pathname}`,
    { status: c.res.status, ...(actor.keyId !== undefined ? { key_id: actor.keyId } : {}) },
    c.req.raw
  );
}

/** Route-level authorization. Returns a 403 JSON body rather than throwing. */
export function requireScope(scope: ApiScope) {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    const actor = c.get("apiActor");
    if (!actor || !hasScope(actor.scopes, scope)) {
      const setupDone = await isSetupCompleted(c.env);
      const hint =
        actor?.kind === "bootstrap" && setupDone
          ? " The bootstrap token only works until initial setup is complete; use an API key minted from /admin/integrations/api-keys."
          : "";
      // A permission is also named by the legacy scopes that grant it, so a
      // caller holding those names knows which one the key is missing.
      const via = Object.keys(LEGACY_SCOPES).filter((s) => s !== "admin" && s !== scope && grants(expand([s]), scope));
      const also = via.length ? ` (granted by ${via.map((s) => `"${s}"`).join(" or ")})` : "";
      return c.json({ error: "forbidden", message: `This token lacks the "${scope}" scope${also}.${hint}` }, 403);
    }
    await next();
  };
}

/** The shape logAudit() wants for a non-human actor. */
export function auditActor(actor: ApiActor): { id: null; upn: string } {
  return { id: null, upn: actor.label };
}
