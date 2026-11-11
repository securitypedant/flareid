import type { Env } from "../env.js";
import type { OAuthClientRow } from "./types.js";

/**
 * Claims are released in groups. A client receives a group only when it is
 * both requested (by scope) and allowed (by the client's allowlist):
 *
 *   email   - email, email_verified                     (scope: email)
 *   profile - id, name, given_name, family_name,
 *             preferred_username                        (scope: profile)
 *   hr      - job_title, department, manager            (scope: profile)
 *   custom  - the nested "custom" object                (scope: profile)
 *   groups  - groups                                    (scope: groups)
 *
 * sub, amr, acr, auth_time, sid and nonce are protocol claims and always go.
 * A client with no allowlist (allowed_claims NULL - every client created
 * before v3) is allowed every group, so existing integrations see no change
 * as long as they ask for the scopes they use.
 */
export const CLAIM_GROUPS = ["email", "profile", "hr", "custom", "groups"] as const;
export type ClaimGroup = (typeof CLAIM_GROUPS)[number];

export const CLAIM_GROUP_LABELS: Record<ClaimGroup, string> = {
  email: "Email address",
  profile: "Name and username",
  hr: "Job title, department and manager",
  custom: "Custom attributes (the nested custom claim)",
  groups: "Group memberships",
};

const SCOPE_GROUPS: Record<string, ClaimGroup[]> = {
  email: ["email"],
  profile: ["profile", "hr", "custom"],
  groups: ["groups"],
};

export const SUPPORTED_SCOPES = ["openid", "email", "profile", "groups", "offline_access"];

export function parseAllowedClaims(client: Pick<OAuthClientRow, "allowed_claims">): ClaimGroup[] {
  if (client.allowed_claims === null || client.allowed_claims === undefined) return [...CLAIM_GROUPS];
  try {
    const parsed: unknown = JSON.parse(client.allowed_claims);
    return Array.isArray(parsed) ? CLAIM_GROUPS.filter((g) => parsed.includes(g)) : [];
  } catch {
    return [];
  }
}

/** The claim groups a token for this scope, issued to this client, may carry. */
/**
 * What a client receives: groups asked for by scope or by the `claims`
 * parameter, limited to the client's allowlist.
 */
export function effectiveClaimGroups(client: Pick<OAuthClientRow, "allowed_claims">, scope: string, claimGroups: string[] = []): Set<ClaimGroup> {
  const allowed = new Set(parseAllowedClaims(client));
  const requested = new Set<string>([...scope.split(/\s+/).flatMap((s) => SCOPE_GROUPS[s] ?? []), ...claimGroups]);
  return new Set([...requested].filter((g): g is ClaimGroup => allowed.has(g as ClaimGroup)));
}

/** Which claim group releases each individual claim name (for the `claims` parameter). */
const CLAIM_NAME_GROUPS: Record<string, ClaimGroup> = {
  email: "email", email_verified: "email",
  name: "profile", given_name: "profile", family_name: "profile", preferred_username: "profile",
  groups: "groups",
  job_title: "hr", department: "hr", manager: "hr", employee_number: "hr",
  custom: "custom",
};

/**
 * Parses the OIDC `claims` request parameter (Core 5.5) into claim groups.
 * Both the id_token and userinfo members count: FlareID releases the same
 * groups in both. Unknown claims are ignored, as the spec allows; malformed
 * JSON is reported so /authorize can refuse it.
 */
export function claimGroupsFromParameter(raw: string | null): string[] | "invalid" {
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.slice(0, 4096));
  } catch {
    return "invalid";
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "invalid";
  const names = ["id_token", "userinfo"].flatMap((m) => {
    const member = (parsed as Record<string, unknown>)[m];
    return member && typeof member === "object" && !Array.isArray(member) ? Object.keys(member) : [];
  });
  return [...new Set(names.map((n) => CLAIM_NAME_GROUPS[n]).filter((g): g is ClaimGroup => Boolean(g)))];
}

/** The authentication context class, from how the user signed in. */
export function acrFor(amr: string[]): string {
  return amr.includes("mfa") ? "urn:flareid:acr:mfa" : "urn:flareid:acr:pwd";
}

export const ACR_VALUES = ["urn:flareid:acr:pwd", "urn:flareid:acr:mfa"];

function isLoopback(url: URL): boolean {
  return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost");
}

/**
 * Exact match against the client's registered redirect URIs - with one
 * exception RFC 8252 requires: a native (public) app listening on a loopback
 * address picks its port at runtime, so for public clients a registered
 * loopback URI matches the same URI on any port.
 */
/** A post-logout redirect URI must be an absolute https URL, or http on a loopback host (RFC 8252 native apps). */
export function isValidPostLogoutUri(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" || (u.protocol === "http:" && isLoopback(u));
  } catch {
    return false;
  }
}

export function redirectUriAllowed(client: Pick<OAuthClientRow, "redirect_uris" | "client_type">, redirectUri: string): boolean {
  const registered: string[] = JSON.parse(client.redirect_uris);
  if (registered.includes(redirectUri)) return true;
  if (client.client_type !== "public") return false;
  let asked: URL;
  try {
    asked = new URL(redirectUri);
  } catch {
    return false;
  }
  if (!isLoopback(asked)) return false;
  return registered.some((r) => {
    try {
      const reg = new URL(r);
      return isLoopback(reg) && reg.hostname === asked.hostname && reg.pathname === asked.pathname && reg.search === asked.search;
    } catch {
      return false;
    }
  });
}

/** Whether this user has already agreed to share these scopes with this client. */
export async function hasConsent(env: Env, userId: number, clientId: string, scope: string): Promise<boolean> {
  const row = await env.DB.prepare("SELECT scope FROM oauth_consents WHERE user_id = ? AND client_id = ?").bind(userId, clientId).first<{ scope: string }>();
  if (!row) return false;
  const granted = new Set(row.scope.split(/\s+/));
  return scope.split(/\s+/).filter(Boolean).every((s) => granted.has(s));
}

export async function recordConsent(env: Env, userId: number, clientId: string, scope: string): Promise<void> {
  const existing = await env.DB.prepare("SELECT scope FROM oauth_consents WHERE user_id = ? AND client_id = ?").bind(userId, clientId).first<{ scope: string }>();
  const merged = [...new Set([...(existing?.scope.split(/\s+/) ?? []), ...scope.split(/\s+/)].filter(Boolean))].join(" ");
  await env.DB.prepare(
    "INSERT INTO oauth_consents (user_id, client_id, scope, granted_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, client_id) DO UPDATE SET scope = excluded.scope, granted_at = excluded.granted_at"
  )
    .bind(userId, clientId, merged, new Date().toISOString())
    .run();
}

/** Builds an error redirect back to the client, per RFC 6749 section 4.1.2.1. */
export function authorizeErrorRedirect(redirectUri: string, error: string, state: string, description?: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  if (description) url.searchParams.set("error_description", description);
  if (state) url.searchParams.set("state", state);
  return url.toString();
}
