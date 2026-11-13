// What a Deploy to Cloudflare install depends on: an empty ISSUER_URL worked
// out at runtime and fixed at setup (lib/issuer.ts), first-run setup in a
// browser at /setup (routes/setup.ts), and a Worker that runs with nothing but
// the two secrets in .dev.vars.example - no signing key or SAML certificate
// in its vars.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { forgetStoredIssuer } from "../src/lib/issuer.js";
import { BOOTSTRAP, resetDatabase } from "./helpers.js";

const WORKERS_DEV = "https://flareid-idp.someone.workers.dev";
const CUSTOM = "https://idp.someone.test";
const ADMIN_PASSWORD = "a-long-and-unbreached-passphrase-7";

beforeEach(async () => {
  await resetDatabase();
  forgetStoredIssuer();
});
afterEach(() => vi.restoreAllMocks());

/** The env a Deploy to Cloudflare install has: empty ISSUER_URL, no key material in vars, just the two secrets. */
function buttonEnv(overrides: Partial<typeof env> = {}): typeof env {
  const e = { ...env, ISSUER_URL: "", ...overrides } as Record<string, unknown>;
  for (const name of ["SIGNING_PUBLIC_JWK", "SIGNING_KEY_ID", "SIGNING_KEY_PKCS8", "COOKIE_ENCRYPTION_KEY", "SAML_SIGNING_CERT", "SAML_SIGNING_KEY_PKCS8"]) {
    if (!(name in overrides)) delete e[name];
  }
  return e as unknown as typeof env;
}

async function call(url: string, init: RequestInit = {}, e: typeof env = buttonEnv()) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(url, { redirect: "manual", ...init }), e, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

function postSetup(origin: string, fields: Record<string, string>, e?: typeof env) {
  return call(
    `${origin}/setup`,
    { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin }, body: new URLSearchParams(fields).toString() },
    e
  );
}

const goodForm = (overrides: Record<string, string> = {}) => ({
  bootstrap_token: BOOTSTRAP,
  domain: "someone.test",
  username: "admin",
  display_name: "Ada Admin",
  password: ADMIN_PASSWORD,
  confirm: ADMIN_PASSWORD,
  // Ticked on the page by default; a browser sends it unless it is unticked.
  admin_mfa: "1",
  ...overrides,
});

/** Signs in on the page with the administrator's password; the response to the password step. */
async function adminPasswordSignIn(origin = WORKERS_DEV) {
  const login = await (await call(`${origin}/login`)).text();
  const flowId = /name="flow_id" value="([^"]+)"/.exec(login)![1]!;
  return call(`${origin}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin },
    body: new URLSearchParams({ flow_id: flowId, upn: "admin", password: ADMIN_PASSWORD }).toString(),
  });
}

async function issuerAt(origin: string, e?: typeof env): Promise<string> {
  const res = await call(`${origin}/.well-known/openid-configuration`, {}, e);
  expect(res.status).toBe(200);
  return ((await res.json()) as { issuer: string }).issuer;
}

const userCount = async () => (await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>())!.n;
const setupDone = async () => (await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'setup_completed'").first<{ value: string }>())?.value === "true";

describe("issuer resolution with an empty ISSUER_URL", () => {
  it("is the request's own https origin before setup", async () => {
    expect(await issuerAt(WORKERS_DEV)).toBe(WORKERS_DEV);
    expect(await issuerAt(CUSTOM)).toBe(CUSTOM);
  });

  it("refuses plain http except on localhost", async () => {
    const res = await call("http://idp.someone.test/.well-known/openid-configuration");
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("HTTPS");
    expect(await issuerAt("http://localhost:8790")).toBe("http://localhost:8790");
    expect(await issuerAt("http://127.0.0.1:8790")).toBe("http://127.0.0.1:8790");
  });

  it("is fixed to the origin setup completed on, whatever Host arrives afterwards", async () => {
    expect((await postSetup(CUSTOM, goodForm())).status).toBe(303);
    const stored = await env.DB.prepare("SELECT value FROM idp_settings WHERE key = 'issuer_url'").first<{ value: string }>();
    expect(stored?.value).toBe(CUSTOM);

    forgetStoredIssuer(); // as a fresh isolate would see it
    expect(await issuerAt(WORKERS_DEV)).toBe(CUSTOM);
    expect(await issuerAt(CUSTOM)).toBe(CUSTOM);
    // Once fixed, a plain-http request no longer decides anything, so it is not refused here.
    expect(await issuerAt("http://idp.someone.test")).toBe(CUSTOM);
  });

  it("is persisted by the API's setup too, and a pinned ISSUER_URL still wins", async () => {
    const res = await call(`${WORKERS_DEV}/api/v1/setup`, {
      method: "POST",
      headers: { Authorization: `Bearer ${BOOTSTRAP}`, "Content-Type": "application/json" },
      body: JSON.stringify({ domain: "someone.test", admin: { username: "admin", password: ADMIN_PASSWORD }, complete: true }),
    });
    expect(res.status).toBe(200);
    forgetStoredIssuer();
    expect(await issuerAt(CUSTOM)).toBe(WORKERS_DEV);
    expect(await issuerAt(CUSTOM, buttonEnv({ ISSUER_URL: "https://pinned.someone.test" }))).toBe("https://pinned.someone.test");
  });
});

describe("first-run setup in the browser", () => {
  it("is where a fresh instance sends a visitor", async () => {
    expect((await call(`${WORKERS_DEV}/`)).headers.get("Location")).toBe("/setup");
    expect((await call(`${WORKERS_DEV}/login`)).headers.get("Location")).toBe("/setup");
    const page = await call(`${WORKERS_DEV}/setup`);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('data-theme="light"');
    expect(html).toContain('name="bootstrap_token"');
    expect(html).toContain(WORKERS_DEV); // says which issuer it will fix
    expect(page.headers.get("Content-Security-Policy")).toContain("script-src 'sha256-");
    // Secure by default: the administrators' second factor box is ticked.
    expect(html).toMatch(/<input type="checkbox" id="admin_mfa" name="admin_mfa" value="1"[^>]* checked/);
    expect(html).toContain("Require a second factor for administrators (recommended)");
    expect(html).toContain("administrators sign in with a password alone");
  });

  it("ticked (the default), makes the first administrator enrol a second factor at their first sign-in", async () => {
    expect((await postSetup(WORKERS_DEV, goodForm())).status).toBe(303);
    const def = await env.DB.prepare("SELECT name FROM auth_policies WHERE is_default = 1").first<{ name: string }>();
    expect(def!.name).toBe("Password and a second factor");
    const superAdmins = await env.DB.prepare(
      "SELECT p.name FROM auth_policy_groups apg JOIN auth_policies p ON p.id = apg.policy_id JOIN groups g ON g.id = apg.group_id WHERE g.name = 'Super Admins'"
    ).all<{ name: string }>();
    expect(superAdmins.results.map((r) => r.name)).toEqual(["Password and a second factor"]);
    const signIn = await adminPasswordSignIn();
    expect(signIn.status).toBe(302);
    expect(signIn.headers.get("Location")).toMatch(/^\/account\/mfa\/setup\?resume=/);
  });

  it("unticked, lets the first administrator sign in with the password alone, and audits it", async () => {
    const { admin_mfa: _ticked, ...unticked } = goodForm();
    expect((await postSetup(WORKERS_DEV, unticked)).status).toBe(303);
    // Super Admins are out of the MFA policy, and "Password only" is the default.
    expect(await env.DB.prepare("SELECT 1 FROM auth_policy_groups apg JOIN groups g ON g.id = apg.group_id WHERE g.name = 'Super Admins'").first()).toBeNull();
    expect((await env.DB.prepare("SELECT name FROM auth_policies WHERE is_default = 1").first<{ name: string }>())!.name).toBe("Password only");
    const audit = await env.DB.prepare("SELECT details FROM audit_log WHERE action = 'idp.setup_completed'").first<{ details: string }>();
    expect(JSON.parse(audit!.details)).toMatchObject({ via: "setup_page", admin_mfa_relaxed: true });
    expect(JSON.parse(audit!.details).applied).toContain("admin_mfa=false");

    const signIn = await adminPasswordSignIn();
    expect(signIn.status).toBe(302);
    expect(signIn.headers.get("Location")).toBe("/account");
    const cookie = signIn.headers.get("Set-Cookie")!.split(";")[0]!;
    expect((await call(`${WORKERS_DEV}/admin`, { headers: { Cookie: cookie } })).status).toBe(200);
  });

  it("keeps the box as it was when the form comes back with an error", async () => {
    const { admin_mfa: _ticked, ...unticked } = goodForm({ confirm: "something else entirely" });
    const html = await (await postSetup(WORKERS_DEV, unticked)).text();
    expect(html).toMatch(/<input type="checkbox" id="admin_mfa" name="admin_mfa" value="1"(?![^>]* checked)[^>]*\/>/);
    const ticked = await (await postSetup(WORKERS_DEV, goodForm({ confirm: "something else entirely" }))).text();
    expect(ticked).toMatch(/<input type="checkbox" id="admin_mfa" name="admin_mfa" value="1"[^>]* checked/);
  });

  it("refuses a wrong bootstrap token and creates nothing", async () => {
    const res = await postSetup(WORKERS_DEV, goodForm({ bootstrap_token: "not-the-token" }));
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("bootstrap token is not correct");
    expect(await userCount()).toBe(0);
    expect(await setupDone()).toBe(false);
  });

  it("refuses a cross-site post", async () => {
    const res = await call(`${WORKERS_DEV}/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: "https://evil.test", Accept: "text/html" },
      body: new URLSearchParams(goodForm()).toString(),
    });
    expect(res.status).toBe(403);
    expect(await userCount()).toBe(0);
  });

  it("applies the password policy and the breached-password check", async () => {
    const weak = await postSetup(WORKERS_DEV, goodForm({ password: "short", confirm: "short" }));
    expect(weak.status).toBe(400);
    expect(await weak.text()).toContain("Password rejected");

    const breached = "correct horse battery staple";
    const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(breached));
    const hash = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.startsWith("https://api.pwnedpasswords.com/range/")) return new Response(`${hash.slice(5)}:4242\r\n`, { status: 200 });
      return new Response("", { status: 404 });
    });
    const res = await postSetup(WORKERS_DEV, goodForm({ password: breached, confirm: breached }));
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("data breach");

    const mismatch = await postSetup(WORKERS_DEV, goodForm({ confirm: "something else entirely" }));
    expect(mismatch.status).toBe(400);
    expect(await userCount()).toBe(0);
    expect(await setupDone()).toBe(false);
  });

  it("creates the Super Admin, completes setup, sends them to sign in, and is inert afterwards", async () => {
    const res = await postSetup(WORKERS_DEV, goodForm());
    expect(res.status).toBe(303);
    expect(res.headers.get("Location")).toBe("/login");

    const admin = await env.DB.prepare(
      "SELECT u.upn, u.display_name FROM users u JOIN group_members m ON m.user_id = u.id JOIN groups g ON g.id = m.group_id WHERE g.name = 'Super Admins'"
    ).first<{ upn: string; display_name: string }>();
    expect(admin).toEqual({ upn: "admin@someone.test", display_name: "Ada Admin" });
    expect(await setupDone()).toBe(true);
    const audit = await env.DB.prepare("SELECT details FROM audit_log WHERE action = 'idp.setup_completed'").first<{ details: string }>();
    expect(audit?.details).toContain("setup_page");

    // The login page is the sign-in form now, not a redirect.
    expect((await call(`${WORKERS_DEV}/login`)).status).toBe(200);
    expect((await call(`${WORKERS_DEV}/`)).headers.get("Location")).toBe("/account");

    const after = await call(`${WORKERS_DEV}/setup`);
    expect(after.status).toBe(200);
    const html = await after.text();
    expect(html).toContain("Setup is complete");
    expect(html).not.toContain('name="bootstrap_token"');

    const again = await postSetup(WORKERS_DEV, goodForm({ username: "intruder" }));
    expect(again.status).toBe(409);
    expect(await again.text()).toContain("Setup is complete");
    expect(await userCount()).toBe(1);
    // The bootstrap token has retired for the API as well.
    const api = await call(`${WORKERS_DEV}/api/v1/status`, { headers: { Authorization: `Bearer ${BOOTSTRAP}` } });
    expect(api.status).toBe(403);
  });

  it("explains what to set when the secrets are missing or still placeholders", async () => {
    for (const e of [buttonEnv({ BOOTSTRAP_TOKEN: undefined }), buttonEnv({ BOOTSTRAP_TOKEN: "replace-me-with-openssl-rand-hex-32" })]) {
      const res = await call(`${WORKERS_DEV}/setup`, {}, e);
      expect(res.status).toBe(503);
      expect(await res.text()).toContain("openssl rand -hex 32");
    }
    const placeholderPost = await postSetup(WORKERS_DEV, goodForm({ bootstrap_token: "replace-me-with-openssl-rand-hex-32" }), buttonEnv({ BOOTSTRAP_TOKEN: "replace-me-with-openssl-rand-hex-32" }));
    expect(placeholderPost.status).toBe(503);
    // Nor does the placeholder open the API.
    const api = await call(`${WORKERS_DEV}/api/v1/status`, { headers: { Authorization: "Bearer replace-me-with-openssl-rand-hex-32" } }, buttonEnv({ BOOTSTRAP_TOKEN: "replace-me-with-openssl-rand-hex-32" }));
    expect(api.status).toBe(401);

    const noKek = await call(`${WORKERS_DEV}/setup`, {}, buttonEnv({ KEY_ENCRYPTION_KEY: undefined }));
    expect(noKek.status).toBe(503);
    expect(await noKek.text()).toContain("openssl rand -base64 48");
    expect(await userCount()).toBe(0);
  });

  it("is rate limited per address", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push((await postSetup(WORKERS_DEV, goodForm({ bootstrap_token: `wrong-${i}` }))).status);
    expect(statuses.slice(0, 10).every((s) => s === 403)).toBe(true);
    expect(statuses[10]).toBe(429);
  });
});

describe("a Worker with only the two secrets", () => {
  it("signs in, publishes generated keys, seals login flows, and keeps SAML off", async () => {
    expect((await postSetup(WORKERS_DEV, goodForm())).status).toBe(303);

    const jwks = (await (await call(`${WORKERS_DEV}/jwks.json`)).json()) as { keys: { alg: string; kid: string }[] };
    expect(jwks.keys.map((k) => k.alg).sort()).toEqual(["ES256", "RS256"]);
    expect(jwks.keys.every((k) => k.kid.startsWith("flareid-"))).toBe(true);

    const login = await (await call(`${WORKERS_DEV}/login`)).text();
    const flowId = /name="flow_id" value="([^"]+)"/.exec(login)![1]!;
    expect(flowId.startsWith("s.")).toBe(true); // sealed, not a KV write per page view

    const signIn = await adminPasswordSignIn();
    // An administrator is made to enrol a second factor first (setup's box was ticked).
    expect(signIn.status).toBe(302);
    expect(signIn.headers.get("Location")).toMatch(/^\/account\/mfa\/setup/);

    expect((await call(`${WORKERS_DEV}/saml/metadata`)).status).toBe(503);
    expect(await issuerAt(WORKERS_DEV)).toBe(WORKERS_DEV);
  });

  it("runs the Cron Trigger before and after setup", async () => {
    const run = async () => {
      const ctx = createExecutionContext();
      await worker.scheduled({ cron: "23 * * * *", scheduledTime: Date.now(), noRetry() {} } as ScheduledController, buttonEnv(), ctx);
      await waitOnExecutionContext(ctx);
    };
    const errors = vi.spyOn(console, "error");
    await run();
    expect((await postSetup(WORKERS_DEV, goodForm())).status).toBe(303);
    await run();
    expect(errors).not.toHaveBeenCalled();
  });
});
