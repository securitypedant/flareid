import { Hono } from "hono";
import type { Env } from "../env.js";
import { authPage, loginAppearance, msg, renderAuthMessage } from "../lib/login-views.js";
import { t, type MessageKey } from "../lib/i18n.js";
import { escapeHtml } from "../lib/html.js";
import { getClientByClientId, getUserById, getUserGroupIds } from "../lib/db.js";
import { appVisibleTo, parseAssignedGroupIds } from "../services/clients.js";
import { getSession } from "../lib/sessions.js";
import { authenticateClient } from "../lib/oauth-client-auth.js";
import { randomToken, sha256Hex } from "../lib/tokens.js";
import { logAudit } from "../lib/audit.js";

/**
 * RFC 8628 - Device Authorization Grant. A device with no keyboard (a TV, a
 * CLI, an appliance) asks for a device_code, shows the person a user_code and
 * verification_uri, and polls /token until they approve on another screen.
 */
export const device = new Hono<{ Bindings: Env }>();

export interface DeviceCodeRow {
  device_code_hash: string;
  user_code: string;
  client_id: string;
  scope: string;
  status: "pending" | "approved" | "denied";
  user_id: number | null;
  amr: string | null;
  auth_time: number | null;
  sid: string | null;
  poll_interval: number;
  last_poll_at: string | null;
  expires_at: string;
}

const DEVICE_CODE_TTL_SECONDS = 600;
const DEVICE_POLL_INTERVAL = 5;
/** Read off one screen, typed on another: no look-alikes (0/O, 1/I/L), upper case only. */
const USER_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

const normalizeUserCode = (raw: string): string => raw.toUpperCase().replace(/[^A-Z0-9]/g, "");
const formatUserCode = (code: string): string => `${code.slice(0, 4)}-${code.slice(4)}`;

function randomUserCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = "";
  for (const b of bytes) code += USER_CODE_ALPHABET[b % USER_CODE_ALPHABET.length];
  return code;
}

async function deviceCodeByUserCode(env: Env, userCode: string): Promise<DeviceCodeRow | null> {
  return env.DB.prepare("SELECT * FROM device_codes WHERE user_code = ?").bind(userCode).first<DeviceCodeRow>();
}

const stillPending = (row: DeviceCodeRow | null): row is DeviceCodeRow =>
  !!row && row.status === "pending" && new Date(row.expires_at).getTime() > Date.now();

// ---------- The device's end (RFC 8628 3.1) ----------

device.post("/device_authorization", async (c) => {
  const body = await c.req.parseBody();
  // Public clients are the point of this grant (CLIs, appliances); a secret
  // is verified the same way as /token when the client is confidential.
  const client = await authenticateClient(c.env, body, c.req.header("Authorization"), { allowPublic: true });
  if (!client) return c.json({ error: "invalid_client" }, 401);

  const deviceCode = randomToken(32);
  const scope = String(body.scope ?? "").slice(0, 512);
  const now = Date.now();
  const deviceCodeHash = await sha256Hex(deviceCode);

  // user_code has a UNIQUE constraint; a collision just re-rolls.
  let userCode = "";
  for (let attempt = 0; ; attempt++) {
    userCode = randomUserCode();
    try {
      await c.env.DB.prepare(
        `INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, status, poll_interval, created_at, expires_at)
         VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`
      )
        .bind(deviceCodeHash, userCode, client.client_id, scope, DEVICE_POLL_INTERVAL, new Date(now).toISOString(), new Date(now + DEVICE_CODE_TTL_SECONDS * 1000).toISOString())
        .run();
      break;
    } catch (err) {
      if (attempt >= 3) throw err;
    }
  }

  const verificationUri = `${c.env.ISSUER_URL}/device`;
  const shownCode = formatUserCode(userCode);
  return c.json({
    device_code: deviceCode,
    user_code: shownCode,
    verification_uri: verificationUri,
    verification_uri_complete: `${verificationUri}?user_code=${shownCode}`,
    expires_in: DEVICE_CODE_TTL_SECONDS,
    interval: DEVICE_POLL_INTERVAL,
  });
});

// ---------- The person's end ----------

const CODE_EXPIRED = { title: msg("msg.requestExpired.title"), message: msg("msg.requestExpired.message") };

device.get("/device", async (c) => {
  const userCode = normalizeUserCode(c.req.query("user_code") ?? "");
  const appearance = await loginAppearance(c);
  const { appName, locale } = appearance;
  const tx = (key: MessageKey, vars?: Record<string, string>) => escapeHtml(t(locale, key, vars));

  const entryForm = (error?: string) =>
    c.html(
      authPage(
        t(locale, "device.title"),
        appearance,
        `
        <h1>${tx("device.heading")}</h1>
        <p class="sub">${tx("device.intro")}</p>
        ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ""}
        <form method="GET" action="/device">
          <label for="user_code">${tx("device.codeLabel")}</label>
          <input type="text" id="user_code" name="user_code" placeholder="${tx("device.codePlaceholder")}" maxlength="9" required autofocus autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" style="text-transform:uppercase; letter-spacing:0.2em; text-align:center;" />
          <div class="row"><button class="primary" type="submit">${tx("device.continue")}</button></div>
        </form>`
      )
    );

  if (!userCode) return entryForm();

  const row = await deviceCodeByUserCode(c.env, userCode);
  if (!stillPending(row)) return entryForm(t(locale, "device.invalidCode"));

  const session = await getSession(c.req.raw, c.env);
  if (!session) {
    // Sign in first; the direct flow's `next` brings the person right back
    // to the approval page for this code.
    return c.redirect(`/login?next=${encodeURIComponent(`/device?user_code=${formatUserCode(userCode)}`)}`, 302);
  }

  const client = await getClientByClientId(c.env, row.client_id);
  if (!client) return renderAuthMessage(c, 400, { title: msg("msg.appUnregistered.title"), message: msg("msg.appUnregistered.message"), action: null });

  const user = await getUserById(c.env, session.userId);
  const scopes = row.scope.split(/\s+/).filter(Boolean);
  const appearanceForUser = await loginAppearance(c, { userId: session.userId });
  const txu = (key: MessageKey, vars?: Record<string, string>) => escapeHtml(t(appearanceForUser.locale, key, vars));

  return c.html(
    authPage(
      t(appearanceForUser.locale, "device.approveTitle"),
      appearanceForUser,
      `
      <h1>${txu("device.approveHeading", { client: client.name })}</h1>
      <p class="sub">${txu("device.approveBody", { appName })}</p>
      <ul class="consent-list">
        ${scopes.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}
      </ul>
      <p class="muted">${txu("device.signedInAs", { upn: user?.upn ?? "" })}</p>
      <form method="POST" action="/device/approve">
        <input type="hidden" name="user_code" value="${escapeHtml(formatUserCode(userCode))}" />
        <div class="row" style="display:flex; gap:10px;">
          <button class="secondary" type="submit" name="decision" value="deny" style="flex:1;">${txu("device.deny")}</button>
          <button class="primary" type="submit" name="decision" value="approve" style="flex:1;">${txu("device.approve")}</button>
        </div>
      </form>`
    )
  );
});

device.post("/device/approve", async (c) => {
  const session = await getSession(c.req.raw, c.env);
  if (!session) return c.redirect("/login?next=%2Fdevice", 302);

  const body = await c.req.parseBody();
  const userCode = normalizeUserCode(String(body.user_code ?? ""));
  const decision = String(body.decision ?? "");
  const appearance = await loginAppearance(c, { userId: session.userId });
  const { locale } = appearance;
  const tx = (key: MessageKey, vars?: Record<string, string>) => escapeHtml(t(locale, key, vars));

  const row = await deviceCodeByUserCode(c.env, userCode);
  if (!stillPending(row)) return renderAuthMessage(c, 400, CODE_EXPIRED);

  const client = await getClientByClientId(c.env, row.client_id);
  // App assignment, same bar as /authorize: a restricted client stamps the
  // code denied for anyone outside its groups - audited as app_denied below.
  const allowed = !!client && (parseAssignedGroupIds(client.assigned_groups).length === 0 || (await appVisibleTo(client.assigned_groups, await getUserGroupIds(c.env, session.userId))));
  const approve = decision === "approve" && allowed;
  // Only a pending row flips; a second tab racing the same code loses and
  // the answer it already gave stands.
  const stamped = await c.env.DB.prepare(
    `UPDATE device_codes SET status = ?, user_id = ?, amr = ?, auth_time = ?, sid = ? WHERE user_code = ? AND status = 'pending'`
  )
    .bind(approve ? "approved" : "denied", approve ? session.userId : null, approve ? JSON.stringify(session.amr) : null, approve ? Math.floor(Date.now() / 1000) : null, approve ? session.id : null, userCode)
    .run();
  if (Number(stamped.meta.changes) !== 1) return renderAuthMessage(c, 400, CODE_EXPIRED);

  await logAudit(c.env, { id: session.userId, upn: (await getUserById(c.env, session.userId))?.upn ?? "" }, approve ? "oauth.device_approved" : decision === "approve" && !allowed ? "oauth.app_denied" : "oauth.device_denied", client?.name ?? row.client_id, { client_id: row.client_id }, c.req.raw);

  return c.html(
    authPage(
      t(locale, approve ? "device.approvedTitle" : "device.deniedTitle"),
      appearance,
      `
      <h1>${tx(approve ? "device.approvedTitle" : "device.deniedTitle")}</h1>
      <p class="sub">${tx(approve ? "device.approvedMessage" : "device.deniedMessage", { client: client?.name ?? row.client_id })}</p>`
    )
  );
});
