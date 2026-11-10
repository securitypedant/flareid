import { sha256Hex } from "../src/lib/tokens.js";
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { inflateAuthnRequest, AuthnRequestError } from "../src/lib/saml/authn-request.js";

beforeEach(resetDatabase);

const ADMIN_PASSWORD = "test-admin-password-1";
const USER_PASSWORD = "user-password-123";
const REDIRECT_URI = "https://rp.test/callback";
const SP_ENTITY_ID = "https://sp.test/saml";
const SP_ACS = "https://sp.test/acs";
const SIGALG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

// ---------- helpers ----------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const char of clean) bits += BASE32_ALPHABET.indexOf(char).toString(2).padStart(5, "0");
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

async function hotp(secretB32: string, counter: number): Promise<string> {
  const cb = new Uint8Array(8);
  let v = counter;
  for (let i = 7; i >= 0; i--) {
    cb[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  const key = await crypto.subtle.importKey("raw", base32Decode(secretB32) as BufferSource, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", key, cb));
  const off = d[d.length - 1]! & 0x0f;
  const bin = ((d[off]! & 0x7f) << 24) | ((d[off + 1]! & 0xff) << 16) | ((d[off + 2]! & 0xff) << 8) | (d[off + 3]! & 0xff);
  return String(bin % 1e6).padStart(6, "0");
}

const totp = (secret: string, drift = 0) => hotp(secret, Math.floor(Date.now() / 1000 / 30) + drift);

function b64encode(input: ArrayBuffer | Uint8Array | string): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input instanceof Uint8Array ? input : new Uint8Array(input);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function deflateB64(xml: string): Promise<string> {
  const stream = new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return b64encode(await new Response(stream).arrayBuffer());
}

function authnRequestXml(opts: { id?: string; forceAuthn?: boolean } = {}): { xml: string; id: string } {
  const id = opts.id ?? `_req-${Math.random().toString(16).slice(2)}`;
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${id}" Version="2.0" IssueInstant="2026-11-04T00:00:00Z" AssertionConsumerServiceURL="${SP_ACS}" Destination="${BASE}/saml/sso"` +
    (opts.forceAuthn ? ` ForceAuthn="true"` : "") +
    `><saml:Issuer>${SP_ENTITY_ID}</saml:Issuer></samlp:AuthnRequest>`;
  return { xml, id };
}

/** Fetches a login form (from /login or /authorize or /saml/sso) and extracts the flow_id. */
async function getFlowId(url: string, cookie?: string): Promise<string> {
  const res = await SELF.fetch(`${BASE}${url}`, { redirect: "manual", headers: cookie ? { Cookie: cookie } : {} });
  const html = await res.text();
  const flowId = /name="flow_id" value="([^"]*)"/.exec(html)?.[1];
  if (!flowId) throw new Error(`no flow_id at ${url} (HTTP ${res.status}): ${html.slice(0, 200)}`);
  return flowId;
}

async function postLogin(params: { flowId: string; upn: string; password: string; ip?: string }): Promise<Response> {
  return SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: BASE,
      ...(params.ip ? { "CF-Connecting-IP": params.ip } : {}),
    },
    body: new URLSearchParams({ flow_id: params.flowId, upn: params.upn, password: params.password }).toString(),
    redirect: "manual",
  });
}

/** Direct login at /login; returns the Set-Cookie session value. */
async function signIn(upn: string, password = USER_PASSWORD, ip?: string): Promise<{ cookie: string; res: Response }> {
  const flowId = await getFlowId("/login");
  const res = await postLogin({ flowId, upn, password, ip });
  const cookie = res.headers.get("Set-Cookie")?.split(";")[0] ?? "";
  return { cookie, res };
}

async function importUser(apiKey: string, user: Record<string, unknown>): Promise<{ status: number; body: any }> {
  return apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [user] } });
}

async function userId(username: string): Promise<number> {
  const row = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>();
  if (!row) throw new Error(`no user ${username}`);
  return row.id;
}

async function seedClient(apiKey: string): Promise<{ clientId: string; clientSecret: string }> {
  const r = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "rp", redirect_uris: [REDIRECT_URI] } });
  if (r.status !== 200) throw new Error(`client seed: ${JSON.stringify(r.body)}`);
  return { clientId: r.body.client_id, clientSecret: r.body.client_secret };
}

async function seedSp(apiKey: string): Promise<void> {
  const r = await apiCall("/api/v1/saml/service-providers", {
    token: apiKey,
    body: { entity_id: SP_ENTITY_ID, name: "sp", acs_urls: [SP_ACS] },
  });
  if (r.status !== 200) throw new Error(`sp seed: ${JSON.stringify(r.body)}`);
}

function authorizeUrl(clientId: string, scope = "openid"): string {
  return `/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: REDIRECT_URI, response_type: "code", scope })}`;
}

async function ssoUrl(xml: string): Promise<string> {
  return `/saml/sso?SAMLRequest=${encodeURIComponent(await deflateB64(xml))}`;
}

async function mintKey(apiKey: string, scopes: string[]): Promise<string> {
  const r = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: `k-${Math.random()}`, scopes } });
  if (r.status !== 200) throw new Error(`key mint: ${JSON.stringify(r.body)}`);
  return r.body.token;
}

// ---------- high: API scope boundaries ----------

describe("privileged import fields require the admin scope", () => {
  it("rejects super_admin, 'Super Admins' membership and overwrites of existing admins", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const dw = await mintKey(apiKey, ["directory:write"]);

    for (const user of [
      { username: "mallory", password: USER_PASSWORD, status: "active", super_admin: true },
      { username: "mallory2", password: USER_PASSWORD, status: "active", groups: ["Super Admins"] },
      // "admin" is the bootstrap administrator: overwriting it resets its password.
      { username: "admin", password: "attacker-chosen-pw", status: "active" },
    ]) {
      const res = await importUser(dw, user);
      expect(res.status).toBe(400);
      expect(String(res.body.message)).toMatch(/admin-scoped|Super Admins/i);
    }

    // The same bundle works for an admin-scoped key.
    const ok = await importUser(apiKey, { username: "mallory", password: USER_PASSWORD, status: "active", super_admin: true });
    expect(ok.status).toBe(200);

    // And a plain bundle still works for directory:write.
    const plain = await importUser(dw, { username: "plain.user", password: USER_PASSWORD, status: "active" });
    expect(plain.status).toBe(200);
  });
});

describe("POST /api/v1/setup administrator block", () => {
  it("requires the admin scope, and refuses before any settings are applied", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const sw = await mintKey(apiKey, ["settings:write"]);

    const denied = await apiCall("/api/v1/setup", {
      token: sw,
      body: { app_name: "SHOULD NOT APPLY", admin: { username: "mallory", password: "mallory-pw-1" } },
    });
    expect(denied.status).toBe(403);

    // No partial effects: the settings in the same body were not applied.
    const status = await apiCall("/api/v1/status", { token: apiKey });
    expect(status.body.app_name).not.toBe("SHOULD NOT APPLY");
    const noUser = await env.DB.prepare("SELECT id FROM users WHERE username = 'mallory'").first();
    expect(noUser).toBeNull();

    // Settings-only calls still work for settings:write.
    const ok = await apiCall("/api/v1/setup", { token: sw, body: { app_name: "Renamed" } });
    expect(ok.status).toBe(200);
  });
});

// ---------- high: mandatory-MFA bypass ----------

describe("mandatory MFA", () => {
  async function seedMfaRequiredUser(): Promise<{ apiKey: string; upn: string }> {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/setup", { token: apiKey, body: { require_mfa: true } });
    const upn = `bob.smith@${domain}`;
    await importUser(apiKey, { username: "bob.smith", password: USER_PASSWORD, status: "active" });
    return { apiKey, upn };
  }

  it("a password-only session gets parked at MFA enrolment by /authorize and /saml/sso instead of minting credentials", async () => {
    const { apiKey, upn } = await seedMfaRequiredUser();
    await seedClient(apiKey);
    await seedSp(apiKey);
    const { clientId } = await apiCall("/api/v1/clients", { token: apiKey }).then(async () => {
      const r = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "rp2", redirect_uris: [REDIRECT_URI] } });
      return { clientId: r.body.client_id };
    });

    // Password login lands on enrolment but sets a session - the cookie that
    // used to answer SSO.
    const { cookie, res } = await signIn(upn);
    expect(res.headers.get("Location")).toMatch(/^\/account\/mfa\/setup\?resume=/);
    expect(cookie).toBeTruthy();

    // OIDC SSO reuse must not issue a code.
    const oidc = await SELF.fetch(`${BASE}${authorizeUrl(clientId)}`, { redirect: "manual", headers: { Cookie: cookie } });
    const oidcLoc = oidc.headers.get("Location") ?? "";
    expect(oidcLoc).toMatch(/^\/account\/mfa\/setup\?resume=/);
    expect(oidcLoc).not.toContain("code=");

    // SAML SSO reuse must not issue an assertion.
    const { xml } = authnRequestXml();
    const samlRes = await SELF.fetch(`${BASE}${await ssoUrl(xml)}`, { redirect: "manual", headers: { Cookie: cookie } });
    const samlLoc = samlRes.headers.get("Location") ?? "";
    expect(samlLoc).toMatch(/^\/account\/mfa\/setup\?resume=/);
  });

  it("enrolment resume finishes the SAML request through a bound /saml/complete", async () => {
    const { apiKey, upn } = await seedMfaRequiredUser();
    await seedSp(apiKey);

    // Drive the SSO branch: session exists, no MFA -> redirect to enrolment.
    const { cookie } = await signIn(upn);
    const { xml } = authnRequestXml();
    const samlRes = await SELF.fetch(`${BASE}${await ssoUrl(xml)}`, { redirect: "manual", headers: { Cookie: cookie } });
    const loc = samlRes.headers.get("Location") ?? "";
    const resumeId = /resume=([^&]+)/.exec(loc)?.[1] ?? "";
    expect(resumeId).toBeTruthy();

    // Before enrolment completes the flow is unbound: /saml/complete refuses it.
    const early = await SELF.fetch(`${BASE}/saml/complete?flow=${resumeId}`, { redirect: "manual", headers: { Cookie: cookie } });
    expect(early.status).toBe(400);

    // Enrol: the page creates the pending secret; the POST confirms it.
    await SELF.fetch(`${BASE}/account/mfa/setup?resume=${resumeId}`, { headers: { Cookie: cookie } });
    // The pending secret belongs to this session (mfa-enrollment.ts).
    const secret = await env.SESSIONS_KV.get(`enroll:${await sha256Hex(cookie.split("=")[1]!)}`);
    expect(secret).toBeTruthy();
    const enrol = await SELF.fetch(`${BASE}/account/mfa/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE, Cookie: cookie },
      body: new URLSearchParams({ resume: resumeId, code: await totp(secret!) }).toString(),
      redirect: "manual",
    });
    const enrolHtml = await enrol.text();
    const continueTo = /href="(\/saml\/complete\?flow=[^"]+)"/.exec(enrolHtml)?.[1] ?? "";
    expect(continueTo).toBeTruthy();

    // Now bound to this user: /saml/complete issues the assertion.
    const complete = await SELF.fetch(`${BASE}${continueTo}`, { redirect: "manual", headers: { Cookie: cookie } });
    expect(complete.status).toBe(200);
    expect(await complete.text()).toContain("SAMLResponse");
  });
});

// ---------- medium: SAML flow binding / ForceAuthn ----------

describe("/saml/complete flow binding", () => {
  it("refuses a flow minted by /saml/sso for a ForceAuthn request, even with a valid session", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    await seedSp(apiKey);
    const upn = `carol@${domain}`;
    await importUser(apiKey, { username: "carol", password: USER_PASSWORD, status: "active" });
    const { cookie } = await signIn(upn);

    const { xml } = authnRequestXml({ forceAuthn: true });
    const sso = await SELF.fetch(`${BASE}${await ssoUrl(xml)}`, { redirect: "manual", headers: { Cookie: cookie } });
    const html = await sso.text();
    const flowId = /name="flow_id" value="([^"]+)"/.exec(html)?.[1] ?? "";
    expect(flowId).toBeTruthy(); // a fresh login is demanded, as ForceAuthn requires

    // The ambient session alone must not redeem that flow at /saml/complete.
    const complete = await SELF.fetch(`${BASE}/saml/complete?flow=${flowId}`, { redirect: "manual", headers: { Cookie: cookie } });
    expect(complete.status).toBe(400);

    // The real path - re-entering the password - does issue the response.
    const res = await postLogin({ flowId, upn, password: USER_PASSWORD });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("SAMLResponse");
  });
});

// ---------- medium: lifecycle consistency ----------

describe("deactivation", () => {
  it("an import that disables a user revokes their sessions and tokens immediately", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = `dave@${domain}`;
    await importUser(apiKey, { username: "dave", password: USER_PASSWORD, status: "active" });
    const { cookie } = await signIn(upn);

    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" })).status).toBe(200);

    await importUser(apiKey, { username: "dave", status: "disabled" });
    const dead = await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" });
    expect(dead.status).toBe(302);
    expect(dead.headers.get("Location")).toContain("/login");

    // Re-activation must not resurrect the revoked session either.
    await importUser(apiKey, { username: "dave", password: USER_PASSWORD, status: "active" });
    const stillDead = await SELF.fetch(`${BASE}/account`, { headers: { Cookie: cookie }, redirect: "manual" });
    expect(stillDead.status).toBe(302);
  });

  it("the MFA step refuses an account deactivated while the challenge was pending", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = `erin@${domain}`;
    await importUser(apiKey, { username: "erin", password: USER_PASSWORD, status: "active" });
    const uid = await userId("erin");
    const secret = "JBSWY3DPEHPK3PXP";
    await env.DB.prepare("UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE id = ?").bind(secret, uid).run();

    // Password step succeeds -> MFA challenge pending.
    const flowId = await getFlowId("/login");
    const pw = await postLogin({ flowId, upn, password: USER_PASSWORD });
    const mfaId = /name="mfa_id" value="([^"]+)"/.exec(await pw.text())?.[1] ?? "";
    expect(mfaId).toBeTruthy();

    // Deactivated before the code arrives.
    await env.DB.prepare("UPDATE users SET status = 'disabled' WHERE id = ?").bind(uid).run();
    const mfa = await SELF.fetch(`${BASE}/login/mfa`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE },
      body: new URLSearchParams({ mfa_id: mfaId, code: await totp(secret) }).toString(),
      redirect: "manual",
    });
    expect(mfa.status).toBe(400);
  });
});

describe("token introspection", () => {
  it("reports tokens for a deactivated user as inactive", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    const { clientId, clientSecret } = await seedClient(apiKey);
    const upn = `frank@${domain}`;
    await importUser(apiKey, { username: "frank", password: USER_PASSWORD, status: "active" });

    const flowId = await getFlowId(authorizeUrl(clientId, "openid offline_access"));
    const login = await postLogin({ flowId, upn, password: USER_PASSWORD });
    const code = new URL(login.headers.get("Location")!).searchParams.get("code")!;
    const token = await SELF.fetch(`${BASE}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, client_id: clientId, client_secret: clientSecret }).toString(),
    });
    const tokens = (await token.json()) as { access_token: string; refresh_token?: string };
    expect(tokens.access_token).toBeTruthy();

    const introspect = (t: string) =>
      SELF.fetch(`${BASE}/introspect`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: t, client_id: clientId, client_secret: clientSecret }).toString(),
      }).then((r) => r.json() as Promise<{ active: boolean }>);

    expect((await introspect(tokens.access_token)).active).toBe(true);
    if (tokens.refresh_token) expect((await introspect(tokens.refresh_token)).active).toBe(true);

    await env.DB.prepare("UPDATE users SET status = 'disabled' WHERE username = 'frank'").run();
    expect((await introspect(tokens.access_token)).active).toBe(false);
    if (tokens.refresh_token) expect((await introspect(tokens.refresh_token)).active).toBe(false);
  });
});

describe("credential change", () => {
  it("a self-service password change signs out every other session", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = `grace@${domain}`;
    await importUser(apiKey, { username: "grace", password: USER_PASSWORD, status: "active" });

    const one = await signIn(upn);
    const two = await signIn(upn);
    const uid = await userId("grace");

    const change = await SELF.fetch(`${BASE}/account/password`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE, Cookie: one.cookie },
      body: new URLSearchParams({ current_password: USER_PASSWORD, new_password: "N3w-password-for-grace", confirm_password: "N3w-password-for-grace" }).toString(),
      redirect: "manual",
    });
    expect(change.status).toBe(302);

    const remaining = await env.DB.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND revoked_at IS NULL").bind(uid).first<{ n: number }>();
    expect(remaining?.n).toBe(1); // only the session that changed the password
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: two.cookie }, redirect: "manual" })).status).toBe(302);
    expect((await SELF.fetch(`${BASE}/account`, { headers: { Cookie: one.cookie }, redirect: "manual" })).status).toBe(200);
  });

  it("an admin password reset signs out all of that user's sessions", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = `heidi@${domain}`;
    await importUser(apiKey, { username: "heidi", password: USER_PASSWORD, status: "active" });
    const { cookie: userCookie } = await signIn(upn);
    const { cookie: adminCookie } = await signIn(`admin@${domain}`, ADMIN_PASSWORD);
    const uid = await userId("heidi");

    const reset = await SELF.fetch(`${BASE}/admin/users/${uid}/reset-password`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE, Cookie: adminCookie },
      body: new URLSearchParams({ require_chosen: "1", password: "Admin-chosen-99" }).toString(),
      redirect: "manual",
    });
    expect(reset.status).toBe(200);

    const dead = await SELF.fetch(`${BASE}/account`, { headers: { Cookie: userCookie }, redirect: "manual" });
    expect(dead.status).toBe(302);
  });
});

// ---------- medium: rate limiting ----------

describe("login rate limiting", () => {
  async function seedUser(name: string): Promise<{ apiKey: string; domain: string; upn: string }> {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    await importUser(apiKey, { username: name, password: USER_PASSWORD, status: "active" });
    return { apiKey, domain, upn: `${name}@${domain}` };
  }

  it("still locks the account after the policy's attempts", async () => {
    const { upn } = await seedUser("ivan");
    for (let i = 0; i < 5; i++) {
      const flowId = await getFlowId("/login");
      await postLogin({ flowId, upn, password: "wrong", ip: "203.0.113.1" });
    }
    const flowId = await getFlowId("/login");
    const sixth = await postLogin({ flowId, upn, password: USER_PASSWORD, ip: "203.0.113.1" });
    expect(await sixth.text()).toContain("Too many attempts");
  });

  it("respellings of one identifier share the account's bucket", async () => {
    const { upn } = await seedUser("judy");
    for (let i = 0; i < 5; i++) {
      const flowId = await getFlowId("/login");
      await postLogin({ flowId, upn, password: "wrong", ip: "203.0.113.2" });
    }
    // A whitespace/full-UPN respelling resolves to the same account, so it is
    // already over budget - no fresh allowance for a new spelling.
    const flowId = await getFlowId("/login");
    const respelled = await postLogin({ flowId, upn: `  ${upn} `, password: "wrong", ip: "203.0.113.2" });
    expect(await respelled.text()).toContain("Too many attempts");
  });

  it("a neighbour's failures on a shared IP do not lock out other accounts", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    await importUser(apiKey, { username: "karl", password: USER_PASSWORD, status: "active" });
    await importUser(apiKey, { username: "lena", password: USER_PASSWORD, status: "active" });

    for (let i = 0; i < 5; i++) {
      const flowId = await getFlowId("/login");
      await postLogin({ flowId, upn: `karl@${domain}`, password: "wrong", ip: "198.51.100.7" });
    }
    // Same egress IP, different account: the shared-IP budget (20x the account
    // budget) is not exhausted by five failures.
    const res = await postLogin({ flowId: await getFlowId("/login"), upn: `lena@${domain}`, password: USER_PASSWORD, ip: "198.51.100.7" });
    expect(res.headers.get("Set-Cookie")).toContain("flareid_session");
  });

  it("counts attempts atomically - a burst cannot lose increments", async () => {
    const { upn } = await seedUser("mike");
    const flowIds = await Promise.all(Array.from({ length: 10 }, () => getFlowId("/login")));
    await Promise.all(flowIds.map((flowId) => postLogin({ flowId, upn, password: "wrong", ip: "203.0.113.9" })));

    const row = await env.DB.prepare("SELECT count FROM rate_limits WHERE key = ?").bind(`login:upn:${upn.split("@")[0]}`).first<{ count: number }>();
    expect(row?.count).toBe(10);
  });

  it("password-step input cannot reach the MFA bucket", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = `nina@${domain}`;
    await importUser(apiKey, { username: "nina", password: USER_PASSWORD, status: "active" });
    const uid = await userId("nina");
    const secret = "JBSWY3DPEHPK3PXP";
    await env.DB.prepare("UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE id = ?").bind(secret, uid).run();

    // Poison what used to be the MFA namespace via the password step.
    for (let i = 0; i < 5; i++) {
      const flowId = await getFlowId("/login");
      await postLogin({ flowId, upn: `mfa:${upn}`, password: "wrong", ip: "203.0.113.10" });
    }

    // The real MFA step is keyed on the user id, untouched by the above.
    const pw = await postLogin({ flowId: await getFlowId("/login"), upn, password: USER_PASSWORD, ip: "203.0.113.10" });
    const mfaHtml = await pw.text();
    expect(mfaHtml).toContain('name="mfa_id"');
    expect(mfaHtml).not.toContain("Too many attempts");
  });
});

// ---------- medium: TOTP replay ----------

describe("TOTP replay guard", () => {
  async function mfaLogin(upn: string, secret: string, drift = 0): Promise<Response> {
    const flowId = await getFlowId("/login");
    const pw = await postLogin({ flowId, upn, password: USER_PASSWORD });
    const mfaId = /name="mfa_id" value="([^"]+)"/.exec(await pw.text())?.[1] ?? "";
    return SELF.fetch(`${BASE}/login/mfa`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE },
      body: new URLSearchParams({ mfa_id: mfaId, code: await totp(secret, drift) }).toString(),
      redirect: "manual",
    });
  }

  it("a code that already completed a login cannot be used again in its window", async () => {
    const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
    const upn = `olga@${domain}`;
    await importUser(apiKey, { username: "olga", password: USER_PASSWORD, status: "active" });
    const secret = "JBSWY3DPEHPK3PXP";
    await env.DB.prepare("UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE username = 'olga'").bind(secret).run();

    const first = await mfaLogin(upn, secret);
    expect(first.headers.get("Set-Cookie")).toContain("flareid_session");

    // Same code, second login: a replay, not a new factor.
    const replay = await mfaLogin(upn, secret);
    expect(replay.headers.get("Set-Cookie")).toBeNull();
    expect(await replay.text()).toContain("Incorrect code");

    // A later-window code still works (clock drift of one step is tolerated).
    const next = await mfaLogin(upn, secret, 1);
    expect(next.headers.get("Set-Cookie")).toContain("flareid_session");
  });
});

// ---------- medium: bounded SAML request parsing ----------

describe("SAMLRequest size limits", () => {
  it("inflateAuthnRequest aborts past the cap instead of buffering a bomb", async () => {
    const big = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${"A".repeat(200_000)}</saml:Issuer></samlp:AuthnRequest>`;
    const encoded = await deflateB64(big);
    await expect(inflateAuthnRequest(encoded)).rejects.toThrow(AuthnRequestError);

    const res = await SELF.fetch(`${BASE}/saml/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
    expect(res.status).toBe(400);
  });
});
