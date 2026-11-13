import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { bootstrapTokenValid, isPlaceholderSecret } from "../lib/api-auth.js";
import { logAudit } from "../lib/audit.js";
import { escapeHtml } from "../lib/html.js";
import { authPage, fieldMsg, formErrors, loginAppearance, msg, requestLocale, type Text } from "../lib/login-views.js";
import { html, t, tHtml, type Locale, type MessageKey } from "../lib/i18n.js";
import { getClientIp, rateLimitAddress, recordRateAttempt } from "../lib/rate-limit.js";
import { getPasswordPolicy, isSetupCompleted, passwordPolicySummary } from "../lib/settings.js";
import { ServiceError, type ServiceCtx } from "../services/context.js";
import { runSetup, SetupAdminError } from "../services/setup.js";

/**
 * First-run setup in a browser, for a deployment made with the Deploy to
 * Cloudflare button: there is no terminal to run the setup call from.
 *
 * It is POST /api/v1/setup behind a form - the same runSetup(), so the same
 * rules - authenticated the same way, by the BOOTSTRAP_TOKEN secret (typed in
 * rather than sent as a bearer token). Once setup is complete the page says so
 * and does nothing else, exactly as the bootstrap token stops working for the
 * API.
 *
 * Completing it also fixes the issuer to the origin it was opened on (see
 * lib/issuer.ts), which is why the page says which origin that is.
 */
export const setup = new Hono<{ Bindings: Env }>();

/** Per address: plenty for typos and a rejected password or two, nothing for guessing a 256-bit token. */
const SETUP_ATTEMPTS_PER_IP = 10;
const SETUP_WINDOW_MINUTES = 15;

type Status = 200 | 400 | 403 | 409 | 429 | 503;

/** A setup page in the request's language; the body is built for it. */
async function render(c: Context<{ Bindings: Env }>, title: MessageKey, body: (locale: Locale) => string, status: Status = 200) {
  const appearance = await loginAppearance(c);
  return c.html(authPage(t(appearance.locale, title), appearance, body(appearance.locale)), status);
}

function completePage(c: Context<{ Bindings: Env }>, status: Status = 200) {
  return render(
    c,
    "setup.complete.title",
    (locale) => `
    <h1>${escapeHtml(t(locale, "setup.complete.title"))}</h1>
    <p class="sub">${escapeHtml(t(locale, "setup.complete.message"))}</p>
    <div class="auth-actions"><a class="button primary" href="/login">${escapeHtml(t(locale, "common.signIn"))}</a></div>`,
    status
  );
}

const code = (s: string) => html(`<code>${escapeHtml(s)}</code>`);
const strong = (s: string) => html(`<strong>${escapeHtml(s)}</strong>`);

/** Why setup cannot run on this deployment yet (as a page body), or null when it can. */
function missingSecrets(env: Env): ((locale: Locale) => string) | null {
  const steps: ((locale: Locale) => string)[] = [];
  if (!env.BOOTSTRAP_TOKEN || isPlaceholderSecret(env.BOOTSTRAP_TOKEN)) {
    steps.push((locale) => `<li>${tHtml(locale, "setup.secrets.bootstrap", { name: code("BOOTSTRAP_TOKEN"), command: code("openssl rand -hex 32") })}</li>`);
  }
  if ((!env.KEY_ENCRYPTION_KEY && !env.SIGNING_KEY_PKCS8) || (env.KEY_ENCRYPTION_KEY && isPlaceholderSecret(env.KEY_ENCRYPTION_KEY))) {
    steps.push((locale) => `<li>${tHtml(locale, "setup.secrets.kek", { name: code("KEY_ENCRYPTION_KEY"), command: code("openssl rand -base64 48") })}</li>`);
  }
  if (!steps.length) return null;
  // The dashboard's own labels stay in English: that is what its menus say.
  return (locale) => `
    <h1>${escapeHtml(t(locale, "setup.secrets.title"))}</h1>
    <p class="sub">${escapeHtml(t(locale, "setup.secrets.intro"))}</p>
    <ul class="consent-list">${steps.map((s) => s(locale)).join("")}</ul>
    <p class="muted" style="font-size:0.875rem;">${tHtml(locale, "setup.secrets.where", {
      workers: strong("Workers & Pages"),
      settings: strong("Settings"),
      variables: strong("Variables and Secrets"),
      add: strong("Add"),
      secret: html("<em>Secret</em>"),
      command: code("npx wrangler secret put BOOTSTRAP_TOKEN"),
    })}</p>`;
}

interface FormValues {
  domain: string;
  username: string;
  display_name: string;
}

async function form(c: Context<{ Bindings: Env }>, values: FormValues, errors: Text[] = [], status: Status = 200) {
  const issuer = c.env.ISSUER_URL;
  const onWorkersDev = new URL(issuer).hostname.endsWith(".workers.dev");
  const policy = await getPasswordPolicy(c.env);
  const appName = c.get("appName");
  return render(
    c,
    "setup.form.title",
    (locale) => {
      const tx = (key: MessageKey) => escapeHtml(t(locale, key));
      const errs = formErrors(locale, errors);
      return `
    <h1>${escapeHtml(t(locale, "setup.form.heading", { appName }))}</h1>
    <p class="sub">${tHtml(locale, "setup.form.intro", { token: code("BOOTSTRAP_TOKEN") })}</p>
    ${errs.html}
    <form method="POST" action="/setup" autocomplete="off">
      <label for="bootstrap_token">${tx("setup.form.token")}</label>
      <input type="password" id="bootstrap_token" name="bootstrap_token" required autofocus autocomplete="off"${errs.attrs("bootstrap_token")} />
      <label for="domain">${tx("setup.form.domain")}</label>
      <input type="text" id="domain" name="domain" value="${escapeHtml(values.domain)}" placeholder="example.com" required autocapitalize="off" autocorrect="off" spellcheck="false"${errs.attrs("domain")} />
      <label for="username">${tx("setup.form.username")}</label>
      <input type="text" id="username" name="username" value="${escapeHtml(values.username)}" placeholder="admin" required autocapitalize="off" autocorrect="off" spellcheck="false" autocomplete="username"${errs.attrs("username")} />
      <label for="display_name">${tx("setup.form.displayName")}</label>
      <input type="text" id="display_name" name="display_name" value="${escapeHtml(values.display_name)}" placeholder="${tx("setup.form.displayNamePlaceholder")}" autocomplete="name" />
      <label for="password">${tx("setup.form.password")}</label>
      <input type="password" id="password" name="password" required autocomplete="new-password"${errs.attrs("password", { hint: "password-policy" })} />
      <label for="confirm">${tx("setup.form.confirm")}</label>
      <input type="password" id="confirm" name="confirm" required autocomplete="new-password"${errs.attrs("confirm")} />
      <p class="muted" id="password-policy" style="margin-top:-6px; font-size:0.8125rem;">${escapeHtml(passwordPolicySummary(policy, locale))}</p>
      <p class="muted" style="font-size:0.8125rem;">${tHtml(locale, "setup.form.issuer", { issuer: strong(issuer) })}${onWorkersDev ? ` ${tx("setup.form.customDomain")}` : ""}</p>
      <div class="row"><button class="primary" type="submit">${tx("setup.form.submit")}</button></div>
    </form>
    <p class="muted" style="text-align:center; margin:14px 0 0; font-size:0.8125rem;">${tx("setup.form.secondFactor")}</p>`;
    },
    status
  );
}

setup.get("/setup", async (c) => {
  if (await isSetupCompleted(c.env)) return completePage(c);
  const missing = missingSecrets(c.env);
  if (missing) return render(c, "setup.secrets.title", missing, 503);
  return form(c, { domain: "", username: "admin", display_name: "" });
});

setup.post("/setup", async (c) => {
  // Inert once setup is complete: nothing is read, counted or written.
  if (await isSetupCompleted(c.env)) return completePage(c, 409);
  const missing = missingSecrets(c.env);
  if (missing) return render(c, "setup.secrets.title", missing, 503);

  const body = await c.req.parseBody();
  const field = (name: string, max = 254) => String(body[name] ?? "").trim().slice(0, max);
  const values: FormValues = { domain: field("domain").toLowerCase(), username: field("username", 64).toLowerCase(), display_name: field("display_name", 128) };
  const token = String(body.bootstrap_token ?? "").trim();
  const password = String(body.password ?? "");
  const ip = getClientIp(c.req.raw);

  // Counted before the token is checked: the increment is the attempt.
  if (await recordRateAttempt(c.env, `setup:ip:${rateLimitAddress(ip)}`, SETUP_ATTEMPTS_PER_IP, SETUP_WINDOW_MINUTES)) {
    c.header("Retry-After", String(SETUP_WINDOW_MINUTES * 60));
    return form(c, values, [msg("setup.error.rateLimited", { minutes: SETUP_WINDOW_MINUTES })], 429);
  }
  if (!token || !(await bootstrapTokenValid(c.env, token))) {
    await logAudit(c.env, null, "idp.setup_token_rejected", undefined, { ip, via: "setup_page" }, c.req.raw);
    return form(c, values, [fieldMsg("setup.error.token", undefined, "bootstrap_token")], 403);
  }

  // Form-only checks; every rule about the account itself is runSetup's.
  const errors: Text[] = [];
  if (!values.domain) errors.push(fieldMsg("setup.error.domain", undefined, "domain"));
  if (!values.username) errors.push(fieldMsg("setup.error.username", undefined, "username"));
  if (!password) errors.push(fieldMsg("setup.error.password", undefined, "password"));
  else if (password !== String(body.confirm ?? "")) errors.push(fieldMsg("setup.error.mismatch", undefined, "confirm"));
  if (errors.length) return form(c, values, errors, 400);

  // The placeholder the form showed, in the language it showed it in.
  const displayName = values.display_name || t(await requestLocale(c), "setup.form.displayNamePlaceholder");
  const [given, ...family] = displayName.split(/\s+/);
  const ctx: ServiceCtx = { env: c.env, actor: { id: null, upn: "bootstrap-token" }, privileged: true, selfId: null, req: c.req.raw };
  try {
    await runSetup(
      ctx,
      {
        domain: values.domain,
        admin: { username: values.username, password, display_name: displayName, given_name: given || "Administrator", family_name: family.join(" ") },
        complete: true,
      },
      "setup_page"
    );
  } catch (err) {
    if (err instanceof SetupAdminError) return form(c, values, err.details.map((d) => d.message), 400);
    if (err instanceof ServiceError) return form(c, values, [err.message], err.status === 403 ? 403 : 400);
    throw err;
  }
  return c.redirect("/login", 303);
});
