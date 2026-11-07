import type { Context } from "hono";
import type { Env } from "../env.js";
import { escapeHtml, page, scriptTag } from "./html.js";
import { getLoginAppearance, type CursorTrail, type LoginAppearance, type LoginGradient } from "./settings.js";

/** Inline <style> override for the auth-flow pages (login, MFA) - a full-bleed gradient behind the centered card. */
function gradientStyles(gradient: LoginGradient): string {
  return `
    body { min-height: 100vh; background: linear-gradient(45deg, ${gradient.from}, ${gradient.to}); }
    .center-wrap { margin-top: 11vh; position: relative; }
    .center-wrap .card { padding: 32px 32px 28px; }
    .auth-brand { display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 12px; }
    /* FlareID_Mark.png is FlareID_Icon.png cropped to the shield with its
       off-white field made transparent, so it sits on the card without a pale
       box; drawn at its own portrait aspect ratio rather than squeezed square. */
    .auth-brand img { height: 46px; width: auto; }
    .auth-brand span { font-size: 1.75rem; font-weight: 700; line-height: 1; color: var(--fi-ink); letter-spacing: -0.025em; }
    .center-wrap h1 { text-align: center; font-size: 1.25rem; margin: 0 0 6px 0; }
    .center-wrap p.sub { text-align: center; margin: 0 0 24px; font-size: 0.9375rem; }
    .center-wrap form .row { margin-top: 20px; }
    .center-wrap form .row button, .auth-actions button { width: 100%; padding: 10px 16px; font-size: 0.9375rem; }
    .auth-actions { margin-top: 4px; }
    .auth-alt { text-align: center; margin: 14px 0 0; font-size: 0.875rem; }
    .auth-foot { margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--fi-line); text-align: center; }
    #cursor-fx { position: fixed; inset: 0; width: 100%; height: 100%; pointer-events: none; }
  `;
}

/** The product mark above the sign-in form, as every IdP puts there. */
function authBrand(appName: string): string {
  return `<div class="auth-brand">
    <img src="/FlareID_Mark.png" alt="" data-hide-on-error />
    <span>${escapeHtml(appName)}</span>
  </div>`;
}

/**
 * A faint field of symbols that drift away from the cursor as it moves, similar
 * to the effect on Cloudflare's AI Playground - purely decorative, GPU-cheap
 * (canvas + a handful of short-lived particles), and inert on touch devices
 * (no pointermove without a pointer).
 */
const CURSOR_FX_SCRIPT = `
(function () {
  var canvas = document.getElementById("cursor-fx");
  if (!canvas) return;
  var ctx = canvas.getContext("2d");
  // Configured characters arrive as a data attribute rather than in this text,
  // because the CSP allows inline scripts by hash: the script stays constant.
  var custom = [];
  try { custom = JSON.parse(canvas.getAttribute("data-symbols") || "[]"); } catch (e) {}
  var cycle = custom.length > 0;
  var symbols = cycle ? custom : ["{ }", "0 1", "< />", "λ", "→", "*", "#", "::", "[ ]", "→→", "←←", "↑↑", "↓↓", "&", "|", "@", "%"];
  var next = 0;
  var particles = [];
  var dpr = window.devicePixelRatio || 1;

  function resize() {
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    canvas.style.width = window.innerWidth + "px";
    canvas.style.height = window.innerHeight + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  window.addEventListener("resize", resize);

  function spawn(x, y) {
    particles.push({
      x: x + (Math.random() - 0.5) * 30,
      y: y + (Math.random() - 0.5) * 30,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4 - 0.15,
      life: 0,
      maxLife: 70 + Math.random() * 40,
      size: 12 + Math.random() * 8,
      text: cycle ? symbols[next++ % symbols.length] : symbols[(Math.random() * symbols.length) | 0],
    });
    if (particles.length > 60) particles.shift();
  }

  var lastSpawn = 0;
  window.addEventListener("pointermove", function (e) {
    var now = performance.now();
    if (now - lastSpawn < 60) return;
    lastSpawn = now;
    spawn(e.clientX, e.clientY);
  });

  function tick() {
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    particles = particles.filter(function (p) {
      p.life++;
      p.x += p.vx;
      p.y += p.vy;
      var t = p.life / p.maxLife;
      if (t >= 1) return false;
      var alpha = t < 0.15 ? t / 0.15 : 1 - (t - 0.15) / 0.85;
      ctx.font = p.size + "px monospace";
      ctx.fillStyle = "rgba(255, 255, 255, " + (alpha * 0.45).toFixed(3) + ")";
      ctx.fillText(p.text, p.x, p.y);
      return true;
    });
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();
`;

/**
 * The canvas and script, or nothing when the trail is switched off. Custom
 * characters are split into individual characters (whitespace dropped), so
 * "Horizon Inc" cycles H, o, r, i, z, o, n, I, n, c.
 */
function cursorFx(trail: CursorTrail): string {
  if (!trail.enabled) return "";
  const symbols = Array.from(trail.characters).filter((ch) => ch.trim() !== "");
  const attr = symbols.length > 0 ? ` data-symbols="${escapeHtml(JSON.stringify(symbols))}"` : "";
  return `<canvas id="cursor-fx"${attr}></canvas>${scriptTag(CURSOR_FX_SCRIPT)}`;
}

/** Shared frame for the auth-flow pages: brand, gradient and cursor trail. */
export function authPage(title: string, appName: string, appearance: LoginAppearance, body: string): string {
  return page(title, `${authBrand(appName)}${body}`, appName, false, "", gradientStyles(appearance.gradient), cursorFx(appearance.cursorTrail));
}

export function loginForm(appName: string, flowId: string, appearance: LoginAppearance, error?: string): string {
  const { subtitle } = appearance;
  return authPage(
    "Sign in",
    appName,
    appearance,
    `
    ${subtitle ? `<p class="sub">${escapeHtml(subtitle)}</p>` : ""}
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST" action="/login">
      <input type="hidden" name="flow_id" value="${escapeHtml(flowId)}" />
      <label for="upn">Username</label>
      <input type="text" id="upn" name="upn" placeholder="username or username@domain" required autofocus autocapitalize="off" autocorrect="off" />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required />
      <div class="row"><button class="primary" type="submit">Sign in</button></div>
    </form>
    ${appearance.recoveryEnabled ? '<p class="auth-alt"><a href="/forgot-password">Forgot your password?</a></p>' : ""}
    <div class="auth-foot"><span class="muted">Protected by ${escapeHtml(appName)} single sign-on</span></div>
    `
  );
}

export function mfaForm(appName: string, mfaId: string, appearance: LoginAppearance, error?: string): string {
  return authPage(
    "Two-factor authentication",
    appName,
    appearance,
    `
    <h1>Two-step verification</h1>
    <p class="sub">Enter the 6-digit code from your authenticator app, or one of your backup codes if you've lost access to it.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST" action="/login/mfa">
      <input type="hidden" name="mfa_id" value="${escapeHtml(mfaId)}" />
      <label for="code">Authenticator code or backup code</label>
      <input type="text" id="code" name="code" maxlength="12" required autofocus />
      <label style="display:flex; align-items:center; gap:6px; font-weight:400;">
        <input type="checkbox" name="remember_device" value="1" style="width:auto;" /> Remember this device for 30 days
      </label>
      <div class="row"><button class="primary" type="submit">Verify</button></div>
    </form>
    `
  );
}

export interface AuthMessage {
  title: string;
  message: string;
  /** Defaults to a fresh direct sign-in; null for errors that retrying cannot fix (a misconfigured app). */
  action?: { href: string; label: string } | null;
}

/** The sign-in flow's error page: the same branded card as the form, not a bare text response. */
export function authMessagePage(appName: string, appearance: LoginAppearance, msg: AuthMessage): string {
  const action = msg.action === undefined ? { href: "/login", label: "Sign in again" } : msg.action;
  return authPage(
    msg.title,
    appName,
    appearance,
    `
    <h1>${escapeHtml(msg.title)}</h1>
    <p class="sub">${escapeHtml(msg.message)}</p>
    ${action ? `<div class="auth-actions"><a href="${escapeHtml(action.href)}"><button class="primary" type="button">${escapeHtml(action.label)}</button></a></div>` : ""}
    <div class="auth-foot"><span class="muted">Protected by ${escapeHtml(appName)} single sign-on</span></div>
    `
  );
}

/** The two messages the browser-facing auth routes need most, worded once. */
export const AUTH_MESSAGES = {
  expired: {
    title: "This sign-in has expired",
    message:
      "For your security, sign-in attempts time out after a few minutes. Go back to the app you were signing in to and start again, or sign in to your account below.",
  },
  notReady: {
    title: "Not ready yet",
    message: "This sign-in service hasn't finished its initial setup. An administrator needs to complete it before anyone can sign in to apps.",
    action: null,
  },
} satisfies Record<string, AuthMessage>;

/** A request from an app this IdP cannot honour: the reason is for the app's administrator, so it is shown as-is. */
export function appConfigError(reason: string): AuthMessage {
  return { title: "This app can't sign you in", message: `${reason} The app's administrator needs to check its sign-in configuration.`, action: null };
}

/** Renders an auth-flow error with the configured branding, for use straight from a route. */
export async function renderAuthMessage(c: Context<{ Bindings: Env }>, status: 200 | 400 | 403 | 503, msg: AuthMessage) {
  return c.html(authMessagePage(c.get("appName"), await getLoginAppearance(c.env), msg), status);
}
