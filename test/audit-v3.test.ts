// Regression tests for the run-2 security audit (v3): one per fixed finding.
import { beforeEach, describe, expect, it } from "vitest";
import { SELF, env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { decodeJwt } from "jose";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { generateBackupCodes, verifyAndConsumeBackupCode } from "../src/lib/backup-codes.js";
import { rateLimitAddress } from "../src/lib/rate-limit.js";
import { TEST_SAML_SP_CERT_PEM, TEST_SAML_SP_KEY_PKCS8 } from "./fixtures/saml-keys.js";
import { b64decode, b64encode } from "../src/lib/saml/xml.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const PW = "user-password-123";
const CB = "https://rp.test/cb";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const sent: { to: string; text: string }[] = [];
const EMAIL = { async send(m: { to: string; text: string }) { sent.push(m); return { messageId: "m" }; } };
beforeEach(() => void (sent.length = 0));

async function call(path: string, init: RequestInit = {}, extraEnv: Record<string, unknown> = {}) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(BASE + path, { redirect: "manual", ...init }), { ...env, EMAIL, ...extraEnv } as unknown as typeof env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}
async function login(upn: string, password = PW, authorizeUrl?: string) {
  const page = await (await call(authorizeUrl ?? "/login")).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
  const res = await call("/login", { method: "POST", headers: FORM, body: new URLSearchParams({ flow_id: flowId, upn, password }).toString() });
  return { res, cookie: res.headers.get("Set-Cookie")?.split(";")[0] ?? "" };
}
async function setup() {
  const { apiKey, domain } = await bootstrapInstance({ domain: "horizon.test" });
  await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('email_from_address', 'no-reply@horizon.test', '')").run();
  await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "ola", password: PW, status: "active" }, { username: "nina", status: "disabled" }] } });
  const client = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "RP", redirect_uris: [CB] } });
  return { apiKey, upn: `ola@${domain}`, clientId: client.body.client_id as string, clientSecret: client.body.client_secret as string };
}
const authz = (clientId: string, extra: Record<string, string> = {}) =>
  `/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: CB, response_type: "code", scope: "openid offline_access", state: "s", ...extra })}`;
async function tokensFor(upn: string, clientId: string, clientSecret: string) {
  const { res, cookie } = await login(upn, PW, authz(clientId));
  const code = new URL(res.headers.get("Location")!).searchParams.get("code")!;
  const tok = await call("/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: clientId, client_secret: clientSecret }).toString() });
  return { cookie, tokens: (await tok.json()) as Record<string, string> };
}
const refresh = (rt: string, clientId: string, clientSecret: string) =>
  call("/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId, client_secret: clientSecret }).toString() });

describe("OIDC sid", () => {
  it("is not the session cookie, and a cookie built from it opens nothing", async () => {
    const { upn, clientId, clientSecret } = await setup();
    const { cookie, tokens } = await tokensFor(upn, clientId, clientSecret);
    const sid = decodeJwt(tokens.id_token!).sid as string;
    expect(sid).not.toBe(cookie.split("=")[1]);
    expect((await call("/account", { headers: { Cookie: `__Host-flareid_session=${sid}` } })).status).toBe(302);
    // RP-initiated logout still recognises its own session by that sid.
    const out = await call(`/oidc/logout?${new URLSearchParams({ id_token_hint: tokens.id_token! })}`, { headers: { Cookie: cookie } });
    expect(out.headers.get("Set-Cookie") ?? "").toContain("Max-Age=0");
  });
});

describe("credential lifecycle", () => {
  it("a password reset or change ends refresh tokens; deactivation voids an outstanding invitation", async () => {
    const { apiKey, upn, clientId, clientSecret } = await setup();
    const { cookie, tokens } = await tokensFor(upn, clientId, clientSecret);
    const pw = await call("/account/password", { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams({ current_password: PW, new_password: "New-password-456!", confirm_password: "New-password-456!" }).toString() });
    expect(pw.headers.get("Location")).toBe("/account?saved=password");
    expect((await refresh(tokens.refresh_token!, clientId, clientSecret)).status).toBe(400);

    expect((await call("/api/v1/users/nina/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } })).status).toBe(200);
    const link = /\/invite\/[0-9a-f]{64}/.exec(sent[0]!.text)![0];
    const ext = (await env.DB.prepare("SELECT external_id FROM users WHERE username = 'nina'").first<{ external_id: string }>())!.external_id;
    await apiCall(`/scim/v2/Users/${ext}`, { token: apiKey, method: "PATCH", body: { schemas: [PATCH], Operations: [{ op: "replace", path: "active", value: true }] } });
    await apiCall(`/scim/v2/Users/${ext}`, { token: apiKey, method: "PATCH", body: { schemas: [PATCH], Operations: [{ op: "replace", path: "active", value: false }] } });
    expect((await call(link, { method: "POST", headers: FORM, body: "password=nina-chosen-12&confirm=nina-chosen-12" })).status).toBe(400);
    expect((await env.DB.prepare("SELECT status FROM users WHERE username = 'nina'").first<{ status: string }>())!.status).toBe("disabled");
  });

  it("a backup code is consumed exactly once under concurrency", async () => {
    await setup();
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ola'").first<{ id: number }>())!.id;
    const [code] = await generateBackupCodes(env, id);
    const results = await Promise.all([verifyAndConsumeBackupCode(env, id, code!), verifyAndConsumeBackupCode(env, id, code!)]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });
});

describe("Super Admin boundaries", () => {
  it("directory:write cannot rewrite Super Admin UPNs, touch their memberships, or claim the group name", async () => {
    const { apiKey } = await setup();
    const dw = (await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "hr", scopes: ["directory:read", "directory:write"] } })).body.token as string;
    await apiCall("/api/v1/domains", { token: dw, body: { domain: "attacker.test" } });
    expect((await apiCall("/api/v1/domains/attacker.test/apply-to-all", { token: dw, body: {} })).status).toBe(403);

    const admin = (await env.DB.prepare("SELECT external_id FROM users WHERE username = 'admin'").first<{ external_id: string }>())!.external_id;
    expect((await apiCall("/scim/v2/Groups", { token: dw, body: { displayName: "Prod", members: [{ value: admin }] } })).status).toBe(403);
    const ops = await apiCall("/scim/v2/Groups", { token: dw, body: { displayName: "Ops" } });
    expect((await apiCall(`/scim/v2/Groups/${ops.body.id}`, { token: dw, method: "PATCH", body: { schemas: [PATCH], Operations: [{ op: "replace", path: "displayName", value: "Super Admins" }] } })).status).toBe(403);

    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const saId = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Super Admins'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    expect((await call(`/admin/groups/${saId}/delete`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "" })).status).toBe(400);
    const rename = await call(`/admin/groups/${saId}`, { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams({ name: "IT Admins", membership: "static", user_ids: String(adminId) }).toString() });
    expect(rename.status).toBe(400);
  });
});

describe("step-up and enrolment", () => {
  it("MFA enrolment cannot resume a sealed prompt=login flow, and pending secrets are per session", async () => {
    const { upn, clientId } = await setup();
    const { cookie } = await login(upn);
    const page = await (await call(authz(clientId, { prompt: "login" }), { headers: { Cookie: cookie } })).text();
    const sealed = /name="flow_id" value="([^"]+)"/.exec(page)![1]!;
    expect(sealed.startsWith("s.")).toBe(true);

    const other = await login(upn);
    const secretOf = async (c: string) => /manually: <code>([A-Z2-7]+)<\/code>/.exec(await (await call("/account/mfa/setup", { headers: { Cookie: c } })).text())?.[1];
    const mine = await secretOf(cookie);
    expect(mine).toBeTruthy();
    expect(await secretOf(other.cookie)).not.toBe(mine);

    const { totp } = await import("./helpers-totp.js");
    const enrol = await call("/account/mfa/setup", { method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams({ resume: sealed, code: await totp(mine!) }).toString() });
    expect(await enrol.text()).not.toContain("rp.test/cb?code=");
    // Enrolling ended the other, password-only session.
    expect((await call("/account", { headers: { Cookie: other.cookie } })).status).toBe(302);
  });
});

async function deflateB64(xml: string) {
  return b64encode(await new Response(new Blob([xml]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
}
async function spSigned(param: "SAMLRequest", xml: string) {
  const content = `${param}=${encodeURIComponent(await deflateB64(xml))}&SigAlg=${encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")}`;
  const key = await crypto.subtle.importKey("pkcs8", b64decode(TEST_SAML_SP_KEY_PKCS8.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")) as BufferSource, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  return `${content}&Signature=${encodeURIComponent(b64encode(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(content))))}`;
}

describe("SAML", () => {
  it("SLO refuses a request without SessionIndex, a stale one, and a replay", async () => {
    const { apiKey, upn } = await setup();
    await apiCall("/api/v1/saml/service-providers", { token: apiKey, body: { entity_id: "https://sp.test/saml", name: "SP", acs_urls: ["https://sp.test/acs"], signing_certs: [TEST_SAML_SP_CERT_PEM], slo_url: "https://sp.test/slo" } });
    const { cookie } = await login(upn);
    const req = (id: string, instant: string, index = "") =>
      `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${instant}"><saml:Issuer>https://sp.test/saml</saml:Issuer>${index}</samlp:LogoutRequest>`;
    const stale = await call(`/saml/slo?${await spSigned("SAMLRequest", req("_a", "2020-01-01T00:00:00Z"))}`, { headers: { Cookie: cookie } });
    expect(stale.status).toBe(400);
    const url = `/saml/slo?${await spSigned("SAMLRequest", req("_b", new Date().toISOString()))}`;
    expect((await call(url, { headers: { Cookie: cookie } })).status).toBe(302);
    expect((await call("/account", { headers: { Cookie: cookie } })).status).toBe(200); // no SessionIndex: nothing ended
    expect((await call(url, { headers: { Cookie: cookie } })).status).toBe(400); // replay
  });

  it("ForceAuthn=\"1\" forces a fresh login", async () => {
    const { apiKey, upn } = await setup();
    await apiCall("/api/v1/saml/service-providers", { token: apiKey, body: { entity_id: "https://sp.test/saml", name: "SP", acs_urls: ["https://sp.test/acs"] } });
    const { cookie } = await login(upn);
    const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_f1" Version="2.0" IssueInstant="${new Date().toISOString()}" AssertionConsumerServiceURL="https://sp.test/acs" ForceAuthn="1"><saml:Issuer>https://sp.test/saml</saml:Issuer></samlp:AuthnRequest>`;
    const html = await (await call(`/saml/sso?SAMLRequest=${encodeURIComponent(await deflateB64(xml))}`, { headers: { Cookie: cookie } })).text();
    expect(html).toContain('name="flow_id"');
    expect(html).not.toContain("SAMLResponse");
  });
});

describe("edges and inputs", () => {
  it("the edge limiter classifies the decoded path; IPv6 shares a /64 budget", async () => {
    await setup();
    const no = { limit: async () => ({ success: false }) };
    expect((await call("/log%69n", {}, { AUTH_LIMITER: no })).status).toBe(429);
    expect(rateLimitAddress("2001:db8:1:2::1")).toBe(rateLimitAddress("2001:DB8:1:2:ffff::fffe"));
    expect(rateLimitAddress("203.0.113.5")).toBe("203.0.113.5");
  });

  it("a cross-site POST to /oidc/logout without a session clears nothing", async () => {
    const res = await call("/oidc/logout", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://evil.example" }, body: "" });
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  it("a huge sign-in identifier is truncated before it becomes a key or an audit target", async () => {
    await setup();
    await login("a".repeat(100_000), "x");
    const longest = await env.DB.prepare("SELECT MAX(length(key)) AS n FROM rate_limits").first<{ n: number }>();
    const target = await env.DB.prepare("SELECT MAX(length(target)) AS n FROM audit_log").first<{ n: number }>();
    expect(longest!.n).toBeLessThanOrEqual(300);
    expect(target!.n).toBeLessThanOrEqual(256);
  });

  it("schemas refuse invalid names and a user-editable manager; fixed claims win inside custom", async () => {
    const { apiKey, upn, clientId, clientSecret } = await setup();
    expect((await apiCall("/api/v1/schemas", { token: apiKey, body: { object_type: "user", name: "Bad", attributes: [{ name: "custom.team", user_editable: true }] } })).status).toBe(400);
    expect((await apiCall("/api/v1/schemas", { token: apiKey, body: { object_type: "user", name: "Bad2", attributes: [{ name: "manager", user_editable: true }] } })).status).toBe(400);
    await env.DB.prepare("UPDATE users SET custom_attributes = ? WHERE username = 'ola'").bind(JSON.stringify({ email: "admin@horizon.test" })).run();
    const { res } = await login(upn, PW, `/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: CB, response_type: "code", scope: "openid email profile" })}`);
    const code = new URL(res.headers.get("Location")!).searchParams.get("code")!;
    const tok = (await (await call("/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CB, client_id: clientId, client_secret: clientSecret }).toString() })).json()) as Record<string, string>;
    expect((decodeJwt(tok.id_token!).custom as Record<string, string>).email).toBe(upn);
  });
});

describe("wave 2", () => {
  it("backup-code regeneration needs a factor; step-up checks are budgeted", async () => {
    await setup();
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ola'").first<{ id: number }>())!.id;
    await env.DB.prepare("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = 1 WHERE id = ?").bind(id).run();
    const cookie = (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const regen = await call("/account/mfa/backup-codes/regenerate", { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "" });
    expect(regen.headers.get("Location")).toBe("/account?error=mfa-code");
    let limited = false;
    for (let i = 0; i < 8 && !limited; i++) {
      const r = await call("/account/mfa/disable", { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "code=000000" });
      limited = r.headers.get("Location") === "/account?error=too-many";
    }
    expect(limited).toBe(true);
  });

  it("the lockout message no longer tells which accounts exist", async () => {
    await setup();
    const sixth = async (name: string) => {
      for (let i = 0; i < 5; i++) await login(name, "wrong");
      return (await (await login(`${name}@horizon.test`, "wrong")).res.text()).includes("Too many attempts");
    };
    expect(await sixth("ola")).toBe(await sixth("zed"));
  });

  it("an email correction voids a link sent to the old address", async () => {
    const { apiKey } = await setup();
    await env.DB.prepare("UPDATE users SET email = 'wrong@outside.test' WHERE username = 'nina'").run();
    await call("/api/v1/users/nina/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } });
    const link = /\/invite\/[0-9a-f]{64}/.exec(sent[0]!.text)![0];
    const ext = (await env.DB.prepare("SELECT external_id FROM users WHERE username = 'nina'").first<{ external_id: string }>())!.external_id;
    await apiCall(`/scim/v2/Users/${ext}`, { token: apiKey, method: "PATCH", body: { schemas: [PATCH], Operations: [{ op: "replace", path: "emails", value: [{ value: "nina@horizon.test", primary: true }] }] } });
    expect((await call(link, { method: "POST", headers: FORM, body: "password=old-holder-pw-12&confirm=old-holder-pw-12" })).status).toBe(400);
  });

  it("directory reset queues downstream deletions instead of losing them", async () => {
    const { apiKey } = await setup();
    await env.DB.prepare("UPDATE users SET scim_id = 'remote-ola' WHERE username = 'ola'").run();
    const reset = await apiCall("/api/v1/directory/reset", { token: apiKey, body: {} });
    expect(reset.status).toBe(200);
    // SCIM is not configured here, so the entry stays queued for a later drain.
    expect((await env.DB.prepare("SELECT label FROM scim_deprovision_queue WHERE scim_id = 'remote-ola'").first<{ label: string }>())?.label).toBe("ola@horizon.test");
  });
});

describe("wave 3", () => {
  it("a SCIM group PATCH with a failing operation changes nothing", async () => {
    const { apiKey } = await setup();
    const ola = (await env.DB.prepare("SELECT external_id FROM users WHERE username = 'ola'").first<{ external_id: string }>())!.external_id;
    const g = await apiCall("/scim/v2/Groups", { token: apiKey, body: { displayName: "Prod", members: [{ value: ola }] } });
    const r = await apiCall(`/scim/v2/Groups/${g.body.id}`, { token: apiKey, method: "PATCH", body: { schemas: [PATCH], Operations: [{ op: "remove", path: `members[value eq "${ola}"]` }, { op: "add", path: "members", value: [{ value: "00000000-0000-4000-8000-000000000000" }] }] } });
    expect(r.status).toBe(400);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?").bind(Number(g.body.id)).first<{ n: number }>())!.n).toBe(1);
  });

  it("the setup sample wipe removes users with trusted devices and queues their remote ids", async () => {
    await setup();
    const ola = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ola'").first<{ id: number }>())!.id;
    const now = new Date().toISOString();
    await env.DB.prepare("INSERT INTO trusted_devices (id, user_id, created_at, last_used_at, expires_at) VALUES ('d1', ?, ?, ?, '2999-01-01T00:00:00Z')").bind(ola, now, now).run();
    await env.DB.prepare("UPDATE users SET scim_id = 'remote-ola' WHERE id = ?").bind(ola).run();
    const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
    const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
    const res = await call("/admin/setup", { method: "POST", headers: { ...FORM, Cookie: cookie }, body: "domain=horizon.test&sample_data=remove" });
    expect(res.status).toBe(302);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE username = 'ola'").first<{ n: number }>())!.n).toBe(0);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM scim_deprovision_queue WHERE scim_id = 'remote-ola'").first<{ n: number }>())!.n).toBe(1);
  });
});
