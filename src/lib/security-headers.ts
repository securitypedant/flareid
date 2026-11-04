import type { MiddlewareHandler } from "hono";
import type { Env } from "../env.js";
import { hasSessionCookie } from "./sessions.js";

/**
 * Cross-site request forgery defence for every state-changing browser route.
 *
 * Verifies where the request came from using the headers the browser sets and
 * page script cannot forge: Origin first, then Fetch Metadata
 * (Sec-Fetch-Site), then Referer. Anything not from this origin is refused -
 * including a sibling subdomain, which SameSite=Lax alone lets through because
 * it counts as same-site. This is OWASP's "verify origin with standard
 * headers" defence; it needs no per-form token because there is nothing for
 * an attacker to steal.
 *
 * When none of the three headers is present, the request is refused if it
 * carries a session cookie (it could act as someone) and allowed if it does
 * not - a scripted client with no session cannot be a CSRF victim. Every
 * current browser sends Origin on a POST.
 *
 * Machine endpoints authenticate with client credentials or bearer tokens,
 * never cookies, and are exempt: /token, /introspect, /revoke, and /api/*
 * (mounted ahead of this middleware). POST /saml/sso only ever answers with a
 * refusal.
 */
const EXEMPT = new Set(["/token", "/introspect", "/revoke", "/saml/sso"]);

function originOf(value: string | null | undefined): string | null {
  if (!value || value === "null") return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

export const csrfProtection: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  const method = c.req.method;
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();
  const url = new URL(c.req.url);
  if (EXEMPT.has(url.pathname) || url.pathname.startsWith("/api/")) return next();

  // Our own origin, as configured and as actually requested (they differ in
  // local development, where ISSUER_URL is the deployed hostname).
  const allowed = new Set([url.origin, originOf(c.env.ISSUER_URL)].filter(Boolean));
  const origin = c.req.header("Origin");
  const fetchSite = c.req.header("Sec-Fetch-Site");
  const referer = c.req.header("Referer");

  let verdict: "ok" | "cross-site" | "unknown";
  if (origin !== undefined) verdict = allowed.has(originOf(origin) ?? "") ? "ok" : "cross-site";
  else if (fetchSite !== undefined) verdict = fetchSite === "same-origin" || fetchSite === "none" ? "ok" : "cross-site";
  else if (referer !== undefined) verdict = allowed.has(originOf(referer) ?? "") ? "ok" : "cross-site";
  else verdict = hasSessionCookie(c.req.raw) ? "unknown" : "ok";

  if (verdict !== "ok") {
    return c.text("This request did not come from this site, so it was refused. Reload the page and try again.", 403);
  }
  return next();
};

/**
 * Response headers that don't depend on page content. The Content-Security-
 * Policy is added per page (it carries a nonce) in html.ts.
 */
export const securityHeaders: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  await next();
  const h = c.res.headers;
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  // Nothing of ours is meant to be framed: login, MFA and admin are exactly
  // what clickjacking targets. frame-ancestors in the CSP says the same for
  // browsers that honour it; this covers the rest.
  h.set("X-Frame-Options", "DENY");
  // Full URLs only to ourselves. Authorization responses carry codes in
  // their query strings, and nothing outbound needs our paths.
  h.set("Referrer-Policy", "same-origin");
  h.set("Cross-Origin-Opener-Policy", "same-origin");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
};
