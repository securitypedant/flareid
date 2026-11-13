import { PASSKEY_LOGIN_SCRIPT } from "./passkey-scripts.js";
import type { Context } from "hono";
import type { Env } from "../env.js";
import { escapeHtml, page, scriptTag } from "./html.js";
import { brandDomainForHost, brandFor, domainFromHint, type Brand } from "./brands.js";
import { DEFAULT_LOGIN_SUBTITLE, getDefaultLanguage, getLoginAppearance, type CursorTrail, type LoginAppearance, type LoginGradient } from "./settings.js";
import { allowTurnstileCsp, turnstileWidget } from "./turnstile.js";
import { allLocales, html, localeInfo, matchLocale, parseAcceptLanguage, t, tHtml, tPlural, type Locale, type MessageKey, type Vars } from "./i18n.js";

// ---------------------------------------------------------------------------
// Translatable text
// ---------------------------------------------------------------------------

/**
 * A message from the locale files. `field` says which input the message is
 * about, for an error: true for the form's main input(s), or an input's id -
 * that input is then marked aria-invalid and described by the message.
 */
export interface Msg {
  key: MessageKey;
  vars?: Vars;
  field?: boolean | string;
}

/** Text already worded (a technical reason, an admin-written text, a message worded elsewhere), about an input like Msg.field. */
export interface PlainText {
  text: string;
  field?: boolean | string;
}

/** A message key, or text shown as-is: a string, or PlainText to tie it to an input. */
export type Text = string | Msg | PlainText;

export function msg(key: MessageKey, vars?: Vars): Msg {
  return vars ? { key, vars } : { key };
}

/** A message about an input: see Msg.field. */
export function fieldMsg(key: MessageKey, vars?: Vars, field: boolean | string = true): Msg {
  return { key, ...(vars ? { vars } : {}), field };
}

/** Already-worded text about an input (see Msg.field). */
export function fieldText(text: string, field: boolean | string = true): PlainText {
  return { text, field };
}

export function textOf(locale: Locale, text: Text): string {
  return typeof text === "string" ? text : "key" in text ? t(locale, text.key, text.vars) : text.text;
}

/**
 * Error messages for a form, and the attributes that tie them to its inputs.
 * The messages are a live region (role="alert") so they are announced when
 * the page loads with them; each input a message is about gets
 * aria-invalid="true" and aria-describedby pointing at it.
 */
export interface FormErrors {
  /** The error block, for above the form; "" when there are none. */
  html: string;
  /**
   * The aria attributes for an input: `primary` marks the form's main inputs
   * (those a `field: true` message is about); `hint` is the id of help text
   * that describes the input either way.
   */
  attrs(id: string, opts?: { primary?: boolean; hint?: string }): string;
}

export function formErrors(locale: Locale, errors: Text | Text[] | undefined | null): FormErrors {
  const list = (Array.isArray(errors) ? errors : errors ? [errors] : []).filter((e) => e !== "");
  const ids = list.map((_, i) => `form-error-${i}`);
  const blocks = list.map((e, i) => `<p class="error" id="${ids[i]}"${list.length === 1 ? ' role="alert"' : ""}>${escapeHtml(textOf(locale, e))}</p>`);
  return {
    html: list.length > 1 ? `<div class="form-errors" role="alert">${blocks.join("")}</div>` : (blocks[0] ?? ""),
    attrs(id, opts = {}) {
      const about = list
        .map((e, i) => (typeof e !== "string" && (e.field === id || (e.field === true && opts.primary)) ? ids[i] : null))
        .filter(Boolean) as string[];
      const describedBy = [...about, ...(opts.hint ? [opts.hint] : [])];
      return `${about.length ? ' aria-invalid="true"' : ""}${describedBy.length ? ` aria-describedby="${describedBy.join(" ")}"` : ""}`;
    },
  };
}

// ---------------------------------------------------------------------------
// The page frame
// ---------------------------------------------------------------------------

/**
 * Inline <style> override for the auth-flow pages (login, MFA) - a full-bleed
 * gradient behind the centered card. Every piece of text sits on the white
 * card, never on the gradient, so a brand's colours cannot make it unreadable.
 * The accent is darkened here (Cloudflare orange is 2.6:1 on white): links and
 * the white text on primary buttons need 4.5:1 (WCAG 2.2 1.4.3), and #c2410c
 * is 5.2:1.
 */
function gradientStyles(gradient: LoginGradient): string {
  return `
    :root { --fi-accent: #c2410c; --fi-accent-dark: #9a3412; --fi-focus: #9a3412; }
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
    .center-wrap form .row button, .auth-actions button, .auth-actions a.button { width: 100%; padding: 10px 16px; font-size: 0.9375rem; }
    .auth-actions { margin-top: 4px; }
    a.button { display: block; box-sizing: border-box; text-align: center; border-radius: 8px; border: 1px solid transparent; font-weight: 550; }
    a.button:hover { text-decoration: none; }
    .auth-alt { text-align: center; margin: 14px 0 0; font-size: 0.875rem; }
    .consent-list { margin: 0 0 18px; padding-inline-start: 20px; line-height: 1.7; }
    .auth-foot { margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--fi-line); text-align: center; }
    .auth-lang ul { list-style: none; margin: 10px 0 0; padding: 0; display: flex; flex-wrap: wrap; justify-content: center; gap: 4px 14px; font-size: 0.8125rem; }
    .auth-lang a[aria-current] { color: var(--fi-ink); font-weight: 600; }
    .center-wrap input::placeholder { color: var(--fi-muted); }
    .center-wrap input[aria-invalid="true"] { border-color: var(--fi-red); }
    /* A visible focus ring on everything focusable (WCAG 2.2 2.4.7, 2.4.11). */
    .center-wrap a:focus-visible, .center-wrap button:focus-visible, .center-wrap input:focus-visible {
      outline: 2px solid var(--fi-focus); outline-offset: 2px;
    }
    .center-wrap input:focus { border-color: var(--fi-accent); box-shadow: 0 0 0 3px rgba(194, 65, 12, 0.22); }
    .visually-hidden { position: absolute !important; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
    #cursor-fx { position: fixed; inset: 0; width: 100%; height: 100%; pointer-events: none; }
    @media (prefers-reduced-motion: reduce) { #cursor-fx { display: none; } }
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
 * (no pointermove without a pointer). Off for anyone who asks the system for
 * reduced motion (and hidden by CSS for them too).
 */
const CURSOR_FX_SCRIPT = `
(function () {
  var canvas = document.getElementById("cursor-fx");
  if (!canvas) return;
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) { canvas.parentNode.removeChild(canvas); return; }
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
  return `<canvas id="cursor-fx" aria-hidden="true"${attr}></canvas>${scriptTag(CURSOR_FX_SCRIPT)}`;
}

/**
 * Shared frame for the auth-flow pages (sign-in, second step, consent,
 * recovery, setup, sign-out): logo, name, gradient, cursor trail, and the
 * brand's custom stylesheet - linked, never inlined, and only here: the admin
 * console and My account never load it, so a broken stylesheet cannot lock
 * an administrator out of fixing it. `title` is already in the page's language.
 */
export function authPage(title: string, appearance: LoginAppearance, body: string): string {
  const head = appearance.cssUrl ? `<link rel="stylesheet" href="${escapeHtml(appearance.cssUrl)}" />` : "";
  const { code, dir } = localeInfo(appearance.locale);
  return page(title, `${authBrand(appearance)}${body}`, appearance.appName, false, "", gradientStyles(appearance.gradient), cursorFx(appearance.cursorTrail), head, { code, dir });
}

/** "Protected by ... single sign-on", and the language links when there is somewhere to switch to. */
function authFoot(appearance: LoginAppearance, languageHref?: (code: Locale) => string): string {
  return `<footer class="auth-foot"><span class="muted">${escapeHtml(t(appearance.locale, "common.protectedBy", { appName: appearance.appName }))}</span>${languageHref ? languagePicker(appearance.locale, languageHref) : ""}</footer>`;
}

/** Links to the page in each language, each named in its own language (and marked so: lang/hreflang). */
export function languagePicker(current: Locale, href: (code: Locale) => string): string {
  const locales = allLocales();
  if (locales.length < 2) return "";
  const items = locales.map(
    (l) =>
      `<li><a href="${escapeHtml(href(l.code))}" lang="${escapeHtml(l.code)}" hreflang="${escapeHtml(l.code)}"${l.code === current ? ' aria-current="true"' : ""}>${escapeHtml(l.nativeName)}</a></li>`
  );
  return `<nav class="auth-lang" aria-label="${escapeHtml(t(current, "common.language"))}"><ul>${items.join("")}</ul></nav>`;
}

/** The passkey button and its status line (a live region, so a failure is announced). */
function passkeyButton(locale: Locale, label: string, cls: string, extraAttrs: string): string {
  return `<div class="auth-passkey">
        <button class="${cls}" type="button" data-passkey-login ${extraAttrs} data-failed="${escapeHtml(t(locale, "login.passkeyFailed"))}" style="width:100%;">${escapeHtml(label)}</button>
        <p class="muted" id="passkey-login-status" role="status" aria-live="polite" style="margin:6px 0 0; font-size:0.8125rem;"></p>
      </div>
      ${scriptTag(PASSKEY_LOGIN_SCRIPT)}`;
}

/** The brand's sign-in message: the built-in default is translated; one an administrator wrote is shown as written. */
function subtitleText(appearance: LoginAppearance): string {
  return appearance.subtitle === DEFAULT_LOGIN_SUBTITLE ? t(appearance.locale, "login.defaultSubtitle") : appearance.subtitle;
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

/** Where a language link on the sign-in form goes: the same flow, re-rendered in that language. */
export function loginLanguageHref(flowId: string): (code: Locale) => string {
  return (code) => `/login/language?lang=${encodeURIComponent(code)}&flow_id=${encodeURIComponent(flowId)}`;
}

export function loginForm(flowId: string, appearance: LoginAppearance, error?: Text, notice?: string): string {
  const { appName, locale } = appearance;
  const subtitle = subtitleText(appearance);
  const errors = formErrors(locale, error);
  return authPage(
    t(locale, "login.title"),
    appearance,
    `
    <h1 class="visually-hidden">${escapeHtml(t(locale, "login.heading", { appName }))}</h1>
    ${notice ? `<p class="muted brand-preview-note" style="text-align:center;">${escapeHtml(notice)}</p>` : ""}
    ${subtitle ? `<p class="sub">${escapeHtml(subtitle)}</p>` : ""}
    ${errors.html}
    <form method="POST" action="/login">
      <input type="hidden" name="flow_id" value="${escapeHtml(flowId)}" />
      <label for="upn">${escapeHtml(t(locale, "login.username"))}</label>
      <input type="text" id="upn" name="upn" placeholder="${escapeHtml(t(locale, "login.usernamePlaceholder"))}" required autofocus autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false"${errors.attrs("upn", { primary: true })} />
      <label for="password">${escapeHtml(t(locale, "login.password"))}</label>
      <input type="password" id="password" name="password" required autocomplete="current-password"${errors.attrs("password", { primary: true })} />
      ${turnstileWidget(appearance.turnstileSiteKey, "login", locale)}
      <div class="row"><button class="primary" type="submit">${escapeHtml(t(locale, "login.submit"))}</button></div>
    </form>
    ${passkeyButton(locale, t(locale, "login.passkey"), "secondary", `data-flow="${escapeHtml(flowId)}"`)}
    ${appearance.recoveryEnabled ? `<p class="auth-alt"><a href="/forgot-password">${escapeHtml(t(locale, "login.forgotPassword"))}</a></p>` : ""}
    ${authFoot(appearance, loginLanguageHref(flowId))}
    `
  );
}

/**
 * Responds with the sign-in form - the way every route should send it, so the
 * Content-Security-Policy admits Turnstile exactly when the form renders it.
 */
export function sendLoginForm(c: Context<{ Bindings: Env }>, flowId: string, appearance: LoginAppearance, error?: Text, notice?: string) {
  allowTurnstileCsp(c, appearance.turnstileSiteKey);
  return c.html(loginForm(flowId, appearance, error, notice));
}

// ---------------------------------------------------------------------------
// The second step
// ---------------------------------------------------------------------------

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

/** How long "Remember this device" lasts (trusted-devices.ts). */
const REMEMBER_DEVICE_DAYS = 30;

export function mfaForm(
  mfaId: string,
  appearance: LoginAppearance,
  error?: Text,
  factors: MfaFactors = { totp: true, passkey: false },
  email: EmailCodeState = { sent: false },
  kba?: KbaChallenge
): string {
  const { locale } = appearance;
  const tx = (key: MessageKey, vars?: Vars) => escapeHtml(t(locale, key, vars));
  const id = escapeHtml(mfaId);
  const errors = formErrors(locale, error);
  const title = (heading: MessageKey) => (heading === "mfa.heading" ? t(locale, "mfa.title") : t(locale, heading));
  const passkey = factors.passkey
    ? passkeyButton(
        locale,
        t(locale, "mfa.passkey.button"),
        factors.totp || factors.emailOtp || factors.securityQuestions ? "secondary" : "primary",
        `data-param="mfa_id" data-flow="${id}" data-options="/login/mfa/passkey/options" data-post="/login/mfa/passkey"`
      )
    : "";
  // The authenticator field takes a backup code too (letters and digits), so
  // no numeric keyboard here; the email code field is digits only.
  const totpForm = (main: boolean) => `<form method="POST" action="/login/mfa">
      <input type="hidden" name="mfa_id" value="${id}" />
      <label for="code">${tx("mfa.totp.label")}</label>
      <input type="text" id="code" name="code" maxlength="12" required ${main ? "autofocus" : ""} autocomplete="one-time-code" autocapitalize="off" autocorrect="off" spellcheck="false"${errors.attrs("code", { primary: main })} />
      <label for="remember_device" style="display:flex; align-items:center; gap:6px; font-weight:400;">
        <input type="checkbox" id="remember_device" name="remember_device" value="1" style="width:auto;" /> ${tx("mfa.rememberDevice", { days: REMEMBER_DEVICE_DAYS })}
      </label>
      <div class="row"><button class="${main ? "primary" : "secondary"}" type="submit">${tx("common.verify")}</button></div>
    </form>`;
  const sendForm = (label: MessageKey, primary: boolean) => `<form method="POST" action="/login/mfa/email/send">
      <input type="hidden" name="mfa_id" value="${id}" />
      <div class="row"><button class="${primary ? "primary" : "secondary"}" type="submit">${tx(label)}</button></div>
    </form>`;
  const kbaButton = (primary: boolean) =>
    factors.securityQuestions
      ? `<form method="POST" action="/login/mfa/questions/start">
      <input type="hidden" name="mfa_id" value="${id}" />
      <div class="row"><button class="${primary ? "primary" : "secondary"}" type="submit">${tx("mfa.kba.start")}</button></div>
    </form>`
      : "";
  const orTotp = factors.totp ? `<p class="auth-alt muted">${tx("mfa.totp.or")}</p>${totpForm(false)}` : "";

  // A code is on its way: entering it is the main action.
  if (factors.emailOtp && email.sent) {
    const minutes = email.minutes ?? 10;
    const sentLine = email.to
      ? tHtml(locale, "mfa.email.sentTo", { to: html(`<strong>${escapeHtml(email.to)}</strong>`), minutes })
      : tHtml(locale, "mfa.email.sent", { minutes });
    return authPage(title("mfa.email.heading"), appearance, `
    <h1>${tx("mfa.email.heading")}</h1>
    <p class="sub">${sentLine}</p>
    ${errors.html}
    <form method="POST" action="/login/mfa/email">
      <input type="hidden" name="mfa_id" value="${id}" />
      <label for="email_code">${tx("mfa.email.label")}</label>
      <input type="text" id="email_code" name="code" inputmode="numeric" maxlength="6" pattern="[0-9 ]*" required autofocus autocomplete="one-time-code"${errors.attrs("email_code", { primary: true })} />
      <div class="row"><button class="primary" type="submit">${tx("common.verify")}</button></div>
    </form>
    ${sendForm("mfa.email.resend", false)}
    ${orTotp}
    ${kbaButton(false)}
    ${passkey}`);
  }

  // Security questions picked for this step: answering them is the main action.
  if (factors.securityQuestions && kba && kba.questions.length) {
    const n = kba.questions.length;
    return authPage(title("mfa.kba.heading"), appearance, `
    <h1>${tx("mfa.kba.heading")}</h1>
    <p class="sub">${escapeHtml(tPlural(locale, "mfa.kba.intro", n))}</p>
    ${errors.html}
    <form method="POST" action="/login/mfa/questions">
      <input type="hidden" name="mfa_id" value="${id}" />
      ${kba.questions
        .map(
          (q, i) => `<label for="kba_${q.id}">${escapeHtml(q.text)}</label>
      <input type="text" id="kba_${q.id}" name="answer_${q.id}" maxlength="100" required ${i === 0 ? "autofocus" : ""} autocomplete="off" autocapitalize="off" spellcheck="false"${errors.attrs(`kba_${q.id}`, { primary: true })} />`
        )
        .join("")}
      <div class="row"><button class="primary" type="submit">${tx("common.verify")}</button></div>
    </form>
    ${orTotp}
    ${factors.emailOtp ? sendForm("mfa.email.send", false) : ""}
    ${passkey}`);
  }

  if (factors.totp) {
    return authPage(
      title("mfa.heading"),
      appearance,
      `
    <h1>${tx("mfa.heading")}</h1>
    <p class="sub">${tx("mfa.totp.intro")}</p>
    ${errors.html}
    ${totpForm(true)}
    ${factors.emailOtp ? sendForm("mfa.email.send", false) : ""}
    ${kbaButton(false)}
    ${passkey}
    `
    );
  }

  if (factors.emailOtp) {
    return authPage(title("mfa.heading"), appearance, `
    <h1>${tx("mfa.heading")}</h1>
    <p class="sub">${tx("mfa.email.intro")}</p>
    ${errors.html}
    ${sendForm("mfa.email.send", true)}
    ${kbaButton(false)}
    ${passkey}`);
  }

  if (factors.securityQuestions) {
    return authPage(title("mfa.heading"), appearance, `
    <h1>${tx("mfa.heading")}</h1>
    <p class="sub">${tx("mfa.kba.only")}</p>
    ${errors.html}
    ${kbaButton(true)}
    ${passkey}`);
  }

  return authPage(title("mfa.heading"), appearance, `
    <h1>${tx("mfa.heading")}</h1>
    <p class="sub">${tx("mfa.passkey.intro")}</p>
    ${errors.html}
    ${passkey}`);
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

export interface AuthMessage {
  title: Text;
  message: Text;
  /** Defaults to a fresh direct sign-in; null for errors that retrying cannot fix (a misconfigured app). */
  action?: { href: string; label: Text } | null;
}

/** The sign-in flow's error page: the same branded card as the form, not a bare text response. */
export function authMessagePage(appearance: LoginAppearance, message: AuthMessage): string {
  const { locale } = appearance;
  const action = message.action === undefined ? { href: "/login", label: msg("common.signInAgain") } : message.action;
  const title = textOf(locale, message.title);
  return authPage(
    title,
    appearance,
    `
    <h1>${escapeHtml(title)}</h1>
    <p class="sub">${escapeHtml(textOf(locale, message.message))}</p>
    ${action ? `<div class="auth-actions"><a class="button primary" href="${escapeHtml(action.href)}">${escapeHtml(textOf(locale, action.label))}</a></div>` : ""}
    ${authFoot(appearance)}
    `
  );
}

/** The two messages the browser-facing auth routes need most, worded once. */
export const AUTH_MESSAGES = {
  expired: { title: msg("msg.expired.title"), message: msg("msg.expired.message") },
  notReady: { title: msg("msg.notReady.title"), message: msg("msg.notReady.message"), action: null },
} satisfies Record<string, AuthMessage>;

/**
 * A request from an app this IdP cannot honour. The reason is for the app's
 * administrator, so it is shown as-is (in English), inside a translated sentence.
 */
export function appConfigError(reason: string): AuthMessage {
  return { title: msg("msg.appConfig.title"), message: msg("msg.appConfig.message", { reason }), action: null };
}

/** Renders an auth-flow error with the brand in force, for use straight from a route. */
export async function renderAuthMessage(c: Context<{ Bindings: Env }>, status: 200 | 400 | 403 | 503, message: AuthMessage, hint: AppearanceHint = {}) {
  return c.html(authMessagePage(await loginAppearance(c, hint), message), status);
}

// ---------------------------------------------------------------------------
// Brand and language of a request
// ---------------------------------------------------------------------------

/** Who or what decides the brand of an auth-flow page (see brands.ts), and a language the flow carries. */
export interface AppearanceHint {
  /** The person, once identified: their UPN's domain decides, and nothing else. */
  userId?: number | null;
  /** A domain hint carried by the sign-in flow (login_hint, ?domain=). */
  domain?: string | null;
  /** A brand already resolved (the preview). */
  brand?: Brand;
  /** The language the flow started in, or the app asked for (OIDC ui_locales). */
  locale?: string | null;
}

/**
 * The domain hint on this request: ?domain= or ?login_hint= (a UPN), else the
 * hostname when it is a branded domain or under one (never the issuer's).
 */
export async function requestBrandDomain(c: Context<{ Bindings: Env }>): Promise<string | null> {
  return domainFromHint(c.req.query("domain")) ?? domainFromHint(c.req.query("login_hint")) ?? (await brandDomainForHost(c.env, new URL(c.req.url).hostname));
}

function readCookie(c: Context<{ Bindings: Env }>, name: string): string | null {
  const m = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`).exec(c.req.header("Cookie") ?? "");
  return m ? m[1]! : null;
}

const NOCUSTOM_COOKIE = "flareid_nocustom";

/** The language a person picked (?lang=), remembered for a year in this browser. */
export const LANG_COOKIE = "flareid_lang";
const LANG_COOKIE_MAX_AGE = 365 * 24 * 3600;

/**
 * The language of an auth-flow page, first match wins:
 *   1. ?lang=<code> on this request - and remembered in the flareid_lang cookie;
 *   2. the flareid_lang cookie;
 *   3. the flow's language (`preferred`): the one the sign-in started in, or
 *      the first supported tag in the app's OIDC ui_locales;
 *   4. Accept-Language, by q-value (a region falls back to its language: fr-CA -> fr);
 *   5. the instance's default language (Admin -> Branding), English unless changed.
 */
export async function requestLocale(c: Context<{ Bindings: Env }>, preferred?: string | null): Promise<Locale> {
  const asked = matchLocale(c.req.query("lang"));
  if (asked) {
    // Only a preference, but HttpOnly all the same: no script needs to read it.
    c.header("Set-Cookie", `${LANG_COOKIE}=${asked}; Path=/; Max-Age=${LANG_COOKIE_MAX_AGE}; Secure; HttpOnly; SameSite=Lax`, { append: true });
    return asked;
  }
  const chosen = matchLocale(readCookie(c, LANG_COOKIE)) ?? matchLocale(preferred);
  if (chosen) return chosen;
  for (const tag of parseAcceptLanguage(c.req.header("Accept-Language"))) {
    const m = matchLocale(tag);
    if (m) return m;
  }
  return getDefaultLanguage(c.env);
}

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
  return readCookie(c, NOCUSTOM_COOKIE) === "1";
}

/** The appearance of an auth-flow page: the person's brand once known, else the flow's or the request's hint; and its language. */
export async function loginAppearance(c: Context<{ Bindings: Env }>, hint: AppearanceHint = {}): Promise<LoginAppearance> {
  const [brand, locale] = await Promise.all([
    hint.brand ?? (hint.userId ? brandFor(c.env, { userId: hint.userId }) : (async () => brandFor(c.env, { domain: hint.domain || (await requestBrandDomain(c)) }))()),
    requestLocale(c, hint.locale),
  ]);
  return getLoginAppearance(c.env, brand, { customCss: !customCssDisabled(c), locale });
}
