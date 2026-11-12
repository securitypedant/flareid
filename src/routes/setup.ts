import { Hono, type Context } from "hono";
import type { Env } from "../env.js";
import { bootstrapTokenValid, isPlaceholderSecret } from "../lib/api-auth.js";
import { logAudit } from "../lib/audit.js";
import { escapeHtml } from "../lib/html.js";
import { authPage } from "../lib/login-views.js";
import { getClientIp, rateLimitAddress, recordRateAttempt } from "../lib/rate-limit.js";
import { getLoginAppearance, getPasswordPolicy, isSetupCompleted, passwordPolicySummary } from "../lib/settings.js";
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

async function render(c: Context<{ Bindings: Env }>, title: string, body: string, status: Status = 200) {
  return c.html(authPage(title, c.get("appName"), await getLoginAppearance(c.env), body), status);
}

function completePage(c: Context<{ Bindings: Env }>, status: Status = 200) {
  return render(
    c,
    "Setup is complete",
    `
    <h1>Setup is complete</h1>
    <p class="sub">This identity provider has already been set up. Sign in with the administrator account created then.</p>
    <div class="auth-actions"><a href="/login"><button class="primary" type="button">Sign in</button></a></div>`,
    status
  );
}

/** Why setup cannot run on this deployment yet, or null when it can. */
function missingSecrets(env: Env): string | null {
  const steps: string[] = [];
  if (!env.BOOTSTRAP_TOKEN || isPlaceholderSecret(env.BOOTSTRAP_TOKEN)) {
    steps.push("<li><code>BOOTSTRAP_TOKEN</code> - a long random string, e.g. the output of <code>openssl rand -hex 32</code>. You type it in on this page.</li>");
  }
  if ((!env.KEY_ENCRYPTION_KEY && !env.SIGNING_KEY_PKCS8) || (env.KEY_ENCRYPTION_KEY && isPlaceholderSecret(env.KEY_ENCRYPTION_KEY))) {
    steps.push("<li><code>KEY_ENCRYPTION_KEY</code> - e.g. the output of <code>openssl rand -base64 48</code>. It encrypts the token-signing keys; never change it afterwards.</li>");
  }
  if (!steps.length) return null;
  return `
    <h1>Setup needs a secret first</h1>
    <p class="sub">Set these as Worker secrets, then reload this page:</p>
    <ul class="consent-list">${steps.join("")}</ul>
    <p class="muted" style="font-size:0.875rem;">In the Cloudflare dashboard: <strong>Workers &amp; Pages</strong> &rarr; this Worker &rarr; <strong>Settings</strong> &rarr; <strong>Variables and Secrets</strong> &rarr; <strong>Add</strong>, type <em>Secret</em>. Or from a checkout: <code>npx wrangler secret put BOOTSTRAP_TOKEN</code>.</p>`;
}

interface FormValues {
  domain: string;
  username: string;
  display_name: string;
}

async function form(c: Context<{ Bindings: Env }>, values: FormValues, errors: string[] = [], status: Status = 200) {
  const issuer = c.env.ISSUER_URL;
  const onWorkersDev = new URL(issuer).hostname.endsWith(".workers.dev");
  const policy = passwordPolicySummary(await getPasswordPolicy(c.env));
  return render(
    c,
    "First-run setup",
    `
    <h1>Set up ${escapeHtml(c.get("appName"))}</h1>
    <p class="sub">Create the first administrator. You need the <code>BOOTSTRAP_TOKEN</code> secret you set when deploying.</p>
    ${errors.map((e) => `<p class="error">${escapeHtml(e)}</p>`).join("")}
    <form method="POST" action="/setup" autocomplete="off">
      <label for="bootstrap_token">Bootstrap token</label>
      <input type="password" id="bootstrap_token" name="bootstrap_token" required autofocus autocomplete="off" />
      <label for="domain">Primary domain for user accounts</label>
      <input type="text" id="domain" name="domain" value="${escapeHtml(values.domain)}" placeholder="example.com" required autocapitalize="off" autocorrect="off" />
      <label for="username">Administrator username</label>
      <input type="text" id="username" name="username" value="${escapeHtml(values.username)}" placeholder="admin" required autocapitalize="off" autocorrect="off" autocomplete="username" />
      <label for="display_name">Display name</label>
      <input type="text" id="display_name" name="display_name" value="${escapeHtml(values.display_name)}" placeholder="Administrator" />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="new-password" />
      <label for="confirm">Confirm password</label>
      <input type="password" id="confirm" name="confirm" required autocomplete="new-password" />
      <p class="muted" style="margin-top:-6px; font-size:0.8125rem;">${escapeHtml(policy)}</p>
      <p class="muted" style="font-size:0.8125rem;">This identity provider will identify itself (its OIDC issuer) as <strong>${escapeHtml(issuer)}</strong>, fixed when setup completes. Relying parties must use exactly this.${
        onWorkersDev ? " To use a custom domain instead, add it to the Worker first (Settings &rarr; Domains &amp; Routes) and open /setup there." : ""
      }</p>
      <div class="row"><button class="primary" type="submit">Create administrator and finish setup</button></div>
    </form>
    <p class="muted" style="text-align:center; margin:14px 0 0; font-size:0.8125rem;">You will be asked to set up a second factor when you first sign in.</p>`,
    status
  );
}

setup.get("/setup", async (c) => {
  if (await isSetupCompleted(c.env)) return completePage(c);
  const missing = missingSecrets(c.env);
  if (missing) return render(c, "Setup needs a secret first", missing, 503);
  return form(c, { domain: "", username: "admin", display_name: "" });
});

setup.post("/setup", async (c) => {
  // Inert once setup is complete: nothing is read, counted or written.
  if (await isSetupCompleted(c.env)) return completePage(c, 409);
  const missing = missingSecrets(c.env);
  if (missing) return render(c, "Setup needs a secret first", missing, 503);

  const body = await c.req.parseBody();
  const field = (name: string, max = 254) => String(body[name] ?? "").trim().slice(0, max);
  const values: FormValues = { domain: field("domain").toLowerCase(), username: field("username", 64).toLowerCase(), display_name: field("display_name", 128) };
  const token = String(body.bootstrap_token ?? "").trim();
  const password = String(body.password ?? "");
  const ip = getClientIp(c.req.raw);

  // Counted before the token is checked: the increment is the attempt.
  if (await recordRateAttempt(c.env, `setup:ip:${rateLimitAddress(ip)}`, SETUP_ATTEMPTS_PER_IP, SETUP_WINDOW_MINUTES)) {
    c.header("Retry-After", String(SETUP_WINDOW_MINUTES * 60));
    return form(c, values, [`Too many attempts from this network. Wait ${SETUP_WINDOW_MINUTES} minutes and try again.`], 429);
  }
  if (!token || !(await bootstrapTokenValid(c.env, token))) {
    await logAudit(c.env, null, "idp.setup_token_rejected", undefined, { ip, via: "setup_page" }, c.req.raw);
    return form(c, values, ["That bootstrap token is not correct. It is the BOOTSTRAP_TOKEN secret set on this Worker."], 403);
  }

  // Form-only checks; every rule about the account itself is runSetup's.
  const errors: string[] = [];
  if (!values.domain) errors.push("Enter the primary domain for user accounts.");
  if (!values.username) errors.push("Enter a username for the administrator.");
  if (!password) errors.push("Choose a password for the administrator.");
  else if (password !== String(body.confirm ?? "")) errors.push("The passwords do not match.");
  if (errors.length) return form(c, values, errors, 400);

  const displayName = values.display_name || "Administrator";
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
