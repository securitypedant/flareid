import { errorResponse } from "./html.js";
import type { Context, MiddlewareHandler } from "hono";
import type { Env } from "../env.js";
import { getClientIp, rateLimitAddress, rateLimitAddress48 } from "./rate-limit.js";

/**
 * The first line of defence for every route anyone can reach without signing
 * in, ahead of the per-account login throttle in rate-limit.ts.
 *
 * That throttle counts in D1, so each attempt it counts is itself a write - as
 * are the audit entries for failed sign-ins and failed API keys. Without a gate
 * in front, a single client could turn requests into storage writes at line
 * rate. Workers Rate Limiting bindings count in memory at the edge and cost no
 * storage at all, so they bound that before any handler runs.
 *
 * Keyed on the client IP, which is the only identifier an anonymous request
 * has. The budgets are deliberately generous - this is not the brute-force
 * control (that is per account), it is the flood control - so an office behind
 * one address signing in at 9am does not trip it. Limits are per Cloudflare
 * location and approximate, which is the right trade for this job.
 *
 * Both bindings are optional: a deployment whose wrangler config predates them
 * simply runs without this gate.
 */
type Group = "auth" | "api";

function routeGroup(method: string, path: string): Group | null {
  // Every sign-in step: the password, the second steps (code, passkey, email code and its send).
  if (path === "/login" || path.startsWith("/login/") || path === "/authorize" || path === "/saml/sso" || path === "/saml/complete") return "auth";
  if (path.startsWith("/api/") || path === "/token" || path === "/introspect" || path === "/revoke" || path === "/userinfo" || path.startsWith("/connect/register")) return "api";
  if (path.startsWith("/scim/v2/")) return "api";
  if (path === "/setup") return "auth";
  if (method === "POST" && (path === "/forgot-password" || path.startsWith("/reset-password") || path.startsWith("/invite/"))) return "auth";
  if (path === "/forgot-password" || path.startsWith("/reset-password/") || path.startsWith("/invite/")) return "auth";
  if (path === "/logout" || path.startsWith("/oidc/logout") || path === "/saml/slo" || path.startsWith("/consent/")) return "auth";
  if (path === "/device_authorization" || path.startsWith("/device")) return "api";
  if (path === "/ssf/receive") return "api";
  if (path.startsWith("/federation/")) return "auth";
  // Everything else anonymous still carries a budget: a whitelist here means a
  // new public route silently runs uncharged, which is how this list drifted.
  return "api";
}

/**
 * OAuth back-channel endpoints are keyed on the client as well as the address:
 * relying parties that reach FlareID from a shared egress (other Workers,
 * Cloudflare Access) must not share one budget, so one cannot throttle another.
 * The dimension is honoured only for a client_id that exists - a made-up one
 * must not mint a fresh budget per spelling, or one address could rotate
 * through unlimited buckets.
 */
async function clientDimension(env: Env, request: Request, path: string): Promise<string> {
  if (path !== "/token" && path !== "/introspect" && path !== "/revoke") return "";
  const basic = /^Basic\s+(.+)$/i.exec(request.headers.get("Authorization") ?? "");
  let id = "";
  if (basic) {
    try {
      id = decodeURIComponent(atob(basic[1]!).split(":")[0] ?? "");
    } catch {
      id = "";
    }
  } else if ((request.headers.get("Content-Type") ?? "").includes("application/x-www-form-urlencoded")) {
    id = new URLSearchParams(await request.clone().text()).get("client_id") ?? "";
  }
  if (!id) return "";
  const exists = await env.DB.prepare("SELECT 1 FROM oauth_clients WHERE client_id = ?").bind(id).first();
  return exists ? `:client:${id.slice(0, 128)}` : "";
}

export const edgeRateLimit: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  // c.req.path is the decoded path Hono routes on: classifying the raw
  // pathname would let /log%69n reach /login unlimited.
  const path = c.req.path;
  const group = routeGroup(c.req.method, path);
  const limiter = group === "auth" ? c.env.AUTH_LIMITER : group === "api" ? c.env.API_LIMITER : undefined;
  if (!group || !limiter) return next();

  const ip = getClientIp(c.req.raw);
  const dimension = await clientDimension(c.env, c.req.raw, path);
  if (dimension) {
    // The per-client budget rides alongside the per-IP one, not instead of it:
    // an open registry can mint unlimited valid client_ids, so a keyed budget
    // alone is a fresh allowance per id.
    const { success } = await limiter.limit({ key: `${group}:${rateLimitAddress(ip)}${dimension}` });
    if (!success) return limited(c, group);
  }
  const { success } = await limiter.limit({ key: `${group}:${rateLimitAddress(ip)}` });
  if (!success) return limited(c, group);
  // The coarser aggregate for IPv6: one binding means one rate, so a /48
  // holder rotating /64s inside its allocation meets the same budget - while
  // co-located /64s still share that aggregate rather than each unlimited.
  if (ip.includes(":")) {
    const { success: within48 } = await limiter.limit({ key: `${group}:48:${rateLimitAddress48(ip)}` });
    if (!within48) return limited(c, group);
  }
  return next();

};

function limited(c: Context<{ Bindings: Env }>, group: Group): Response {
  // No audit entry here on purpose: logging every refusal would be the very
  // write amplification this exists to stop.
  c.header("Retry-After", "60");
  if (group === "api") return c.json({ error: "rate_limited", message: "Too many requests. Try again in a minute." }, 429);
  const res = errorResponse(c.req.raw, c.get("appName") ?? "FlareID", 429, "Too many requests from this network. Please wait a minute and try again.");
  res.headers.set("Retry-After", "60");
  return res;
}
