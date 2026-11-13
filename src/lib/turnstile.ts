import type { Context } from "hono";
import type { Env } from "../env.js";
import { escapeHtml, scriptTag } from "./html.js";
import { DEFAULT_LOCALE, t, type Locale } from "./i18n.js";
import { getClientIp } from "./rate-limit.js";
import { activeTurnstileSiteKey, getTurnstileConfig } from "./settings.js";

/**
 * Cloudflare Turnstile on the password sign-in and recovery-request forms.
 *
 * The widget is rendered explicitly (api.js?render=explicit, then
 * turnstile.render from a hashed inline script) inside the form, which makes
 * Turnstile add a hidden `cf-turnstile-response` field carrying the token. The
 * server redeems the token with Siteverify before it does anything costly -
 * hashing a password, looking up an account, sending an email - and checks
 * that Cloudflare saw the challenge on our hostname and for this form's
 * action, so a token solved on another site or another form is refused.
 *
 * Siteverify failing (timeout, network error, `internal-error`) refuses the
 * request: bot protection that an outage switches off is not protection.
 * Passkey sign-in never needs Turnstile, so it stays available throughout -
 * passkeys are phishing-resistant and a credential-stuffing bot has nothing
 * to stuff - and the administrator can switch Turnstile off.
 *
 * The external script and frame are allowed by the Content-Security-Policy
 * only on responses that render the widget: those set TURNSTILE_CSP_HEADER,
 * which securityHeaders() consumes (security-headers.ts).
 */

export const TURNSTILE_ORIGIN = "https://challenges.cloudflare.com";
export const TURNSTILE_SCRIPT_URL = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js?render=explicit&onload=flareidTurnstileReady`;
export const SITEVERIFY_URL = `${TURNSTILE_ORIGIN}/turnstile/v0/siteverify`;
/** Internal response header: "this page renders the widget". Removed before the response leaves. */
export const TURNSTILE_CSP_HEADER = "X-FlareID-Turnstile";

export type TurnstileAction = "login" | "recovery";

/** Shown whenever the check fails, whatever the reason (the English text of "turnstile.failed"). */
export const TURNSTILE_FAILED_MESSAGE = "Please complete the check and try again.";

const MAX_TOKEN_LENGTH = 2048;
const SITEVERIFY_TIMEOUT_MS = 5000;

const RENDER_SCRIPT = `
window.flareidTurnstileReady = function () {
  var el = document.getElementById("turnstile-widget");
  if (!el || !window.turnstile) return;
  window.turnstile.render(el, {
    sitekey: el.getAttribute("data-sitekey"),
    action: el.getAttribute("data-action"),
    theme: el.getAttribute("data-theme") || "light",
    language: el.getAttribute("data-language") || "auto"
  });
};
`;

/**
 * The widget container plus its scripts, for inside a <form>. Empty when no
 * site key. A labelled group, so a screen reader announces what the frame
 * inside it is for; the widget speaks the page's language.
 */
export function turnstileWidget(siteKey: string | null, action: TurnstileAction, locale: Locale = DEFAULT_LOCALE): string {
  if (!siteKey) return "";
  return `<div id="turnstile-widget" class="turnstile-widget" role="group" aria-label="${escapeHtml(t(locale, "turnstile.label"))}" data-sitekey="${escapeHtml(siteKey)}" data-action="${action}" data-theme="light" data-language="${escapeHtml(locale)}" style="margin-top:14px; min-height:65px;"></div>
      ${scriptTag(RENDER_SCRIPT)}
      <script src="${TURNSTILE_SCRIPT_URL}" async defer></script>`;
}

/** Marks the response as rendering the widget, so its CSP allows Turnstile's script and frame. */
export function allowTurnstileCsp(c: Context, siteKey: string | null): void {
  if (siteKey) c.header(TURNSTILE_CSP_HEADER, "1");
}

interface SiteverifyResult {
  success?: boolean;
  hostname?: string;
  action?: string;
  "error-codes"?: string[];
}

function expectedHostname(env: Env): string {
  try {
    return new URL(env.ISSUER_URL).hostname;
  } catch {
    return "";
  }
}

async function siteverify(secret: string, token: string, remoteip: string, idempotencyKey: string): Promise<SiteverifyResult> {
  const body = new URLSearchParams({ secret, response: token, idempotency_key: idempotencyKey });
  if (remoteip && remoteip !== "unknown") body.set("remoteip", remoteip);
  const res = await fetch(SITEVERIFY_URL, { method: "POST", body, signal: AbortSignal.timeout(SITEVERIFY_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as SiteverifyResult;
}

/**
 * Whether the token proves a solved challenge for this hostname and action.
 * Retried once, with the same idempotency key, on a network failure or
 * Cloudflare's `internal-error` - the key makes the retry safe for a token
 * that is otherwise single-use.
 */
export async function verifyTurnstileToken(env: Env, secret: string, token: string, remoteip: string, action: TurnstileAction): Promise<boolean> {
  if (!token || token.length > MAX_TOKEN_LENGTH) {
    console.log(JSON.stringify({ event: "turnstile_refused", action, reason: token ? "token_too_long" : "missing_token" }));
    return false;
  }
  const idempotencyKey = crypto.randomUUID();
  let result: SiteverifyResult | null = null;
  for (let attempt = 0; attempt < 2 && !result?.success; attempt++) {
    try {
      result = await siteverify(secret, token, remoteip, idempotencyKey);
      if (!result["error-codes"]?.includes("internal-error")) break;
    } catch (err) {
      result = null;
      console.warn(JSON.stringify({ event: "turnstile_siteverify_unavailable", error: err instanceof Error ? err.name : "error" }));
    }
  }
  const reason = !result
    ? "unavailable"
    : !result.success
      ? (result["error-codes"] ?? []).join(",") || "failed"
      : result.hostname !== expectedHostname(env)
        ? "hostname_mismatch"
        : result.action !== action
          ? "action_mismatch"
          : null;
  if (reason) console.log(JSON.stringify({ event: "turnstile_refused", action, reason }));
  return reason === null;
}

/**
 * The gate for a form POST: true when Turnstile is on and the submitted token
 * does not verify. Off (or not fully configured) is always a pass.
 */
export async function turnstileRefused(c: Context<{ Bindings: Env }>, body: Record<string, unknown>, action: TurnstileAction): Promise<boolean> {
  const config = await getTurnstileConfig(c.env);
  if (!activeTurnstileSiteKey(config)) return false;
  const token = typeof body["cf-turnstile-response"] === "string" ? body["cf-turnstile-response"] : "";
  return !(await verifyTurnstileToken(c.env, config.secret, token, getClientIp(c.req.raw), action));
}
