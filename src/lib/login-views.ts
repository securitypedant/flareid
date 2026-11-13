import { PASSKEY_LOGIN_SCRIPT } from "./passkey-scripts.js";
import type { Context } from "hono";
import type { Env } from "../env.js";
import { escapeHtml, page, scriptTag } from "./html.js";
import { brandDomainForHost, brandFor, domainFromHint, type Brand } from "./brands.js";
import { getLoginAppearance, type CursorTrail, type LoginAppearance, type LoginGradient } from "./settings.js";
import { allowTurnstileCsp, turnstileWidget } from "./turnstile.js";

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
    .auth-brand img { height: 46px; width: auto; max-width: 220px; object-fit: contain; }
    .auth-brand span { font-size: 1.75rem; font-weight: 700; line-height: 1; color: var(--fi-ink); letter-spacing: -0.025em; }
    .center-wrap h1 { text-align: center; font-size: 1.25rem; margin: 0 0 6px 0; }
    .center-wrap p.sub { text-align: center; margin: 0 0 24px; font-size: 0.9375rem; }
    .center-wrap form .row { margin-top: 20px; }
    .center-wrap form .row button, .auth-actions button { width: 100%; padding: 10px 16px; font-size: 0.9375rem; }
    .auth-actions { margin-top: 4px; }
    .auth-alt { text-align: center; margin: 14px 0 0; font-size: 0.875rem; }
    .consent-list { margin: 0 0 18px; padding-left: 20px; line-height: 1.7; }
    .auth-foot { margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--fi-line); text-align: center; }
    #cursor-fx { position: fixed; inset: 0; width: 100%; height: 100%; pointer-events: none; }
  `;
}

/** The product mark above the sign-in form, as every IdP puts there: the brand's logo, else FlareID's. */
function authBrand(appearance: LoginAppearance): string {
  return `<div class="auth-brand">
    <img src="${escapeHtml(appearance.logoUrl ?? "/FlareID_Mark.png")}" alt="" data-hide-on-error />
    <span>${escapeHtml(appearance.appName)}</span>
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

/**
 * Shared frame for the auth-flow pages (sign-in, second step, consent,
 * recovery, setup, sign-out): logo, name, gradient, cursor trail, and the
 * brand's custom stylesheet - linked, never inlined, and only here: the admin
 * console and My account never load it, so a broken stylesheet cannot lock
 * an administrator out of fixing it.
 */
export function authPage(title: string, appearance: LoginAppearance, body: string): string {
  const head = appearance.cssUrl ? `<link rel="stylesheet" href="${escapeHtml(appearance.cssUrl)}" />` : "";
  return page(title, `${authBrand(appearance)}${body}`, appearance.appName, false, "", gradientStyles(appearance.gradient), cursorFx(appearance.cursorTrail), head);
}

export function loginForm(flowId: string, appearance: LoginAppearance, error?: string, notice?: string): string {
  const { subtitle, appName } = appearance;
  return authPage(
    "Sign in",
    appearance,
    `
    ${notice ? `<p class="muted brand-preview-note" style="text-align:center;">${escapeHtml(notice)}</p>` : ""}
    ${subtitle ? `<p class="sub">${escapeHtml(subtitle)}</p>` : ""}
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST" action="/login">
      <input type="hidden" name="flow_id" value="${escapeHtml(flowId)}" />
      <label for="upn">Username</label>
      <input type="text" id="upn" name="upn" placeholder="username or username@domain" required autofocus autocapitalize="off" autocorrect="off" />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required />
      ${turnstileWidget(appearance.turnstileSiteKey, "login")}
      <div class="row"><button class="primary" type="submit">Sign in</button></div>
    </form>
    <div class="auth-passkey">
      <button class="secondary" type="button" data-passkey-login data-flow="${escapeHtml(flowId)}" style="width:100%;">Sign in with a passkey</button>
      <p class="muted" id="passkey-login-status" style="margin:6px 0 0; font-size:0.8125rem;"></p>
    </div>
    ${scriptTag(PASSKEY_LOGIN_SCRIPT)}
    ${appearance.recoveryEnabled ? '<p class="auth-alt"><a href="/forgot-password">Forgot your password?</a></p>' : ""}
    <div class="auth-foot"><span class="muted">Protected by ${escapeHtml(appName)} single sign-on</span></div>
    `
  );
}

/**
 * Responds with the sign-in form - the way every route should send it, so the
 * Content-Security-Policy admits Turnstile exactly when the form renders it.
 */
export function sendLoginForm(c: Context<{ Bindings: Env }>, flowId: string, appearance: LoginAppearance, error?: string, notice?: string) {
  allowTurnstileCsp(c, appearance.turnstileSiteKey);
  return c.html(loginForm(flowId, appearance, error, notice));
}

/** The second-step methods a sign-in can offer. */
export interface MfaFactors {
  totp: boolean;
  passkey: boolean;
  emailOtp?: boolean;
  securityQuestions?: boolean;
}

/** State of the email-code option on the second step: whether a code was just sent, and where (masked). */
export interface EmailCodeState {
  sent: boolean;
  to?: string;
  minutes?: number;
}

/** The security questions this step asks, once picked (they stay the same for the step). */
export interface KbaChallenge {
  questions: { id: number; text: string }[];
}

export function mfaForm(
  mfaId: string,
  appearance: LoginAppearance,
  error?: string,
  factors: MfaFactors = { totp: true, passkey: false },
  email: EmailCodeState = { sent: false },
  kba?: KbaChallenge
): string {
  const id = escapeHtml(mfaId);
  const errorHtml = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  const passkey = factors.passkey
    ? `<div class="auth-passkey">
        <button class="${factors.totp || factors.emailOtp || factors.securityQuestions ? "secondary" : "primary"}" type="button" data-passkey-login data-param="mfa_id" data-flow="${id}" data-options="/login/mfa/passkey/options" data-post="/login/mfa/passkey" style="width:100%;">Use a passkey</button>
        <p class="muted" id="passkey-login-status" style="margin:6px 0 0; font-size:0.8125rem;"></p>
      </div>
      ${scriptTag(PASSKEY_LOGIN_SCRIPT)}`
    : "";
  const totpForm = (autofocus: boolean) => `<form method="POST" action="/login/mfa">
      <input type="hidden" name="mfa_id" value="${id}" />
      <label for="code">Authenticator code or backup code</label>
      <input type="text" id="code" name="code" maxlength="12" required ${autofocus ? "autofocus" : ""} autocomplete="one-time-code" />
      <label style="display:flex; align-items:center; gap:6px; font-weight:400;">
        <input type="checkbox" name="remember_device" value="1" style="width:auto;" /> Remember this device for 30 days
      </label>
      <div class="row"><button class="${autofocus ? "primary" : "secondary"}" type="submit">Verify</button></div>
    </form>`;
  const sendForm = (label: string, primary: boolean) => `<form method="POST" action="/login/mfa/email/send">
      <input type="hidden" name="mfa_id" value="${id}" />
      <div class="row"><button class="${primary ? "primary" : "secondary"}" type="submit">${escapeHtml(label)}</button></div>
    </form>`;
  const kbaButton = (primary: boolean) =>
    factors.securityQuestions
      ? `<form method="POST" action="/login/mfa/questions/start">
      <input type="hidden" name="mfa_id" value="${id}" />
      <div class="row"><button class="${primary ? "primary" : "secondary"}" type="submit">Answer security questions</button></div>
    </form>`
      : "";

  // A code is on its way: entering it is the main action.
  if (factors.emailOtp && email.sent) {
    return authPage("Two-factor authentication", appearance, `
    <h1>Check your email</h1>
    <p class="sub">We sent a 6-digit code${email.to ? ` to <strong>${escapeHtml(email.to)}</strong>` : ""}. It works once, for the next ${email.minutes ?? 10} minutes.</p>
    ${errorHtml}
    <form method="POST" action="/login/mfa/email">
      <input type="hidden" name="mfa_id" value="${id}" />
      <label for="email_code">Code from the email</label>
      <input type="text" id="email_code" name="code" inputmode="numeric" maxlength="6" pattern="[0-9 ]*" required autofocus autocomplete="one-time-code" />
      <div class="row"><button class="primary" type="submit">Verify</button></div>
    </form>
    ${sendForm("Send a new code", false)}
    ${factors.totp ? `<p class="auth-alt muted">Or use your authenticator app</p>${totpForm(false)}` : ""}
    ${kbaButton(false)}
    ${passkey}`);
  }

  // Security questions picked for this step: answering them is the main action.
  if (factors.securityQuestions && kba && kba.questions.length) {
    return authPage("Two-factor authentication", appearance, `
    <h1>Security questions</h1>
    <p class="sub">Answer ${kba.questions.length === 1 ? "your security question" : `these ${kba.questions.length} security questions`} to confirm it's you. Capitals and extra spaces don't matter.</p>
    ${errorHtml}
    <form method="POST" action="/login/mfa/questions">
      <input type="hidden" name="mfa_id" value="${id}" />
      ${kba.questions
        .map(
          (q, i) => `<label for="kba_${q.id}">${escapeHtml(q.text)}</label>
      <input type="text" id="kba_${q.id}" name="answer_${q.id}" maxlength="100" required ${i === 0 ? "autofocus" : ""} autocomplete="off" autocapitalize="off" spellcheck="false" />`
        )
        .join("")}
      <div class="row"><button class="primary" type="submit">Verify</button></div>
    </form>
    ${factors.totp ? `<p class="auth-alt muted">Or use your authenticator app</p>${totpForm(false)}` : ""}
    ${factors.emailOtp ? sendForm("Email me a code", false) : ""}
    ${passkey}`);
  }

  if (factors.totp) {
    return authPage(
      "Two-factor authentication",
      appearance,
      `
    <h1>Two-step verification</h1>
    <p class="sub">Enter the 6-digit code from your authenticator app, or one of your backup codes if you've lost access to it.</p>
    ${errorHtml}
    ${totpForm(true)}
    ${factors.emailOtp ? sendForm("Email me a code", false) : ""}
    ${kbaButton(false)}
    ${passkey}
    `
    );
  }

  if (factors.emailOtp) {
    return authPage("Two-factor authentication", appearance, `
    <h1>Two-step verification</h1>
    <p class="sub">We'll email you a 6-digit code to confirm it's you.</p>
    ${errorHtml}
    ${sendForm("Email me a code", true)}
    ${kbaButton(false)}
    ${passkey}`);
  }

  if (factors.securityQuestions) {
    return authPage("Two-factor authentication", appearance, `
    <h1>Two-step verification</h1>
    <p class="sub">Answer your security questions to confirm it's you.</p>
    ${errorHtml}
    ${kbaButton(true)}
    ${passkey}`);
  }

  return authPage("Two-factor authentication", appearance, `
    <h1>Two-step verification</h1>
    <p class="sub">Confirm it's you with one of your passkeys.</p>
    ${errorHtml}
    ${passkey}`);
}

export interface AuthMessage {
  title: string;
  message: string;
  /** Defaults to a fresh direct sign-in; null for errors that retrying cannot fix (a misconfigured app). */
  action?: { href: string; label: string } | null;
}

/** The sign-in flow's error page: the same branded card as the form, not a bare text response. */
export function authMessagePage(appearance: LoginAppearance, msg: AuthMessage): string {
  const action = msg.action === undefined ? { href: "/login", label: "Sign in again" } : msg.action;
  const { appName } = appearance;
  return authPage(
    msg.title,
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

/** Renders an auth-flow error with the brand in force, for use straight from a route. */
export async function renderAuthMessage(c: Context<{ Bindings: Env }>, status: 200 | 400 | 403 | 503, msg: AuthMessage, hint: AppearanceHint = {}) {
  return c.html(authMessagePage(await loginAppearance(c, hint), msg), status);
}

/** Who or what decides the brand of an auth-flow page (see brands.ts). */
export interface AppearanceHint {
  /** The person, once identified: their UPN's domain decides, and nothing else. */
  userId?: number | null;
  /** A domain hint carried by the sign-in flow (login_hint, ?domain=). */
  domain?: string | null;
  /** A brand already resolved (the preview). */
  brand?: Brand;
}

/**
 * The domain hint on this request: ?domain= or ?login_hint= (a UPN), else the
 * hostname when it is a branded domain or under one (never the issuer's).
 */
export async function requestBrandDomain(c: Context<{ Bindings: Env }>): Promise<string | null> {
  return domainFromHint(c.req.query("domain")) ?? domainFromHint(c.req.query("login_hint")) ?? (await brandDomainForHost(c.env, new URL(c.req.url).hostname));
}

const NOCUSTOM_COOKIE = "flareid_nocustom";

/**
 * The escape hatch for a custom stylesheet that broke the sign-in page:
 * ?nocustom=1 on any auth-flow page switches it off for this browser (a
 * session cookie, so the posts that follow stay unstyled too); ?nocustom=0
 * switches it back on. Harmless to offer anyone - it only removes styling.
 */
export function customCssDisabled(c: Context<{ Bindings: Env }>): boolean {
  const q = c.req.query("nocustom");
  if (q === "1") {
    c.header("Set-Cookie", `${NOCUSTOM_COOKIE}=1; Path=/; Secure; HttpOnly; SameSite=Lax`, { append: true });
    return true;
  }
  if (q === "0") {
    c.header("Set-Cookie", `${NOCUSTOM_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`, { append: true });
    return false;
  }
  return new RegExp(`(?:^|;\\s*)${NOCUSTOM_COOKIE}=1(?:;|$)`).test(c.req.header("Cookie") ?? "");
}

/** The appearance of an auth-flow page: the person's brand once known, else the flow's or the request's hint. */
export async function loginAppearance(c: Context<{ Bindings: Env }>, hint: AppearanceHint = {}): Promise<LoginAppearance> {
  const brand = hint.brand ?? (hint.userId ? await brandFor(c.env, { userId: hint.userId }) : await brandFor(c.env, { domain: hint.domain || (await requestBrandDomain(c)) }));
  return getLoginAppearance(c.env, brand, { customCss: !customCssDisabled(c) });
}
