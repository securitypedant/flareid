import type { MiddlewareHandler } from "hono";
import type { Env } from "../env.js";
import { getClientIp, rateLimitAddress } from "./rate-limit.js";

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
  if (path.startsWith("/api/") || path === "/token" || path === "/introspect" || path === "/revoke" || path === "/userinfo") return "api";
  if (path.startsWith("/scim/v2/")) return "api";
  if (method === "POST" && (path === "/forgot-password" || path.startsWith("/reset-password") || path.startsWith("/invite/"))) return "auth";
  if (path === "/forgot-password" || path.startsWith("/reset-password/") || path.startsWith("/invite/")) return "auth";
  if (path === "/logout" || path.startsWith("/oidc/logout") || path === "/saml/slo" || path.startsWith("/consent/")) return "auth";
  return null;
}

/**
 * OAuth back-channel endpoints are keyed on the client as well as the address:
 * relying parties that reach FlareID from a shared egress (other Workers,
 * Cloudflare Access) must not share one budget, so one cannot throttle another.
 */
async function clientDimension(request: Request, path: string): Promise<string> {
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
  return id ? `:client:${id.slice(0, 128)}` : "";
}

export const edgeRateLimit: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  // c.req.path is the decoded path Hono routes on: classifying the raw
  // pathname would let /log%69n reach /login unlimited.
  const path = c.req.path;
  const group = routeGroup(c.req.method, path);
  const limiter = group === "auth" ? c.env.AUTH_LIMITER : group === "api" ? c.env.API_LIMITER : undefined;
  if (!group || !limiter) return next();

  const { success } = await limiter.limit({ key: `${group}:${rateLimitAddress(getClientIp(c.req.raw))}${await clientDimension(c.req.raw, path)}` });
  if (success) return next();

  // No audit entry here on purpose: logging every refusal would be the very
  // write amplification this exists to stop.
  c.header("Retry-After", "60");
  if (group === "api") return c.json({ error: "rate_limited", message: "Too many requests. Try again in a minute." }, 429);
  return c.text("Too many requests from this network. Please wait a minute and try again.", 429);
};
