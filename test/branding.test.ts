// Logos, per-domain brands and custom CSS: upload validation, how assets are
// served, which brand a page or an email gets, the CSS sanitiser and where
// the stylesheet is (and is not) applied, the API twins, and permissions.
import { beforeEach, describe, expect, it } from "vitest";
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { createSession } from "../src/lib/sessions.js";
import { customCssProblem, sniffLogo } from "../src/lib/brands.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const PNG = Uint8Array.from(atob(PNG_B64), (ch) => ch.charCodeAt(0));
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, ...new Array(54).fill(0)]);
const SVG = new TextEncoder().encode('<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
const b64 = (u: Uint8Array) => {
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
};

type Sent = { to: string; subject: string; text: string; html: string };
function fakeEmail() {
  const sent: Sent[] = [];
  return { sent, binding: { async send(m: Sent) { sent.push(m); return { messageId: `m${sent.length}` }; } } };
}

/** A request to the Worker; a path is on the issuer's host, a full URL on its own. */
async function call(path: string, init: RequestInit = {}, email?: ReturnType<typeof fakeEmail>) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(path.startsWith("https://") ? path : `${BASE}${path}`, { redirect: "manual", ...init }), { ...env, ...(email ? { EMAIL: email.binding } : {}) } as unknown as typeof env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}
const html = async (path: string, init: RequestInit = {}) => (await call(path, init)).text();
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };
const form = (cookie: string, fields: Record<string, string> | [string, string][]) => ({ method: "POST", headers: { ...FORM, Cookie: cookie }, body: new URLSearchParams(fields).toString() });
function upload(cookie: string, bytes: Uint8Array, name = "logo.png", type = "image/png"): RequestInit {
  const fd = new FormData();
  fd.append("logo", new File([bytes], name, { type }));
  return { method: "POST", headers: { Origin: BASE, Cookie: cookie }, body: fd };
}

async function setup() {
  const { apiKey } = await bootstrapInstance({ domain: "example.test" });
  expect((await apiCall("/api/v1/domains", { token: apiKey, body: { domain: "acme.test" } })).status).toBe(200);
  expect((await apiCall("/api/v1/groups", { token: apiKey, body: { name: "Viewers" } })).status).toBeLessThan(300);
  const mk = async (username: string, domain: string, groups: string[] = []) => {
    const r = await apiCall("/api/v1/users", { token: apiKey, body: { username, domain, given_name: username, family_name: "Test", email: `${username}@mail.test`, password: "correct-horse-battery-9", status: "active", groups } });
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
  };
  await mk("bob", "acme.test");
  await mk("carol", "example.test");
  await mk("vic", "example.test", ["Viewers"]);
  expect((await apiCall("/api/v1/security/roles", { token: apiKey, body: { name: "Branding Viewers", permissions: ["branding:read"], groups: ["Viewers"] } })).status).toBe(201);
  await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('email_from_address', 'no-reply@example.test', '')").run();
  const idOf = async (u: string) => (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
  const sessionFor = async (u: string) => (await createSession(env, await idOf(u), ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  return { apiKey, idOf, admin: await sessionFor("admin"), vic: await sessionFor("vic"), bob: await sessionFor("bob"), carol: await sessionFor("carol") };
}

async function acmeBrand(apiKey: string, extra: Record<string, unknown> = {}) {
  const r = await apiCall("/api/v1/branding/brands", { token: apiKey, body: { name: "Acme", app_name: "Acme ID", login_gradient: { from: "#111111", to: "#222222" }, email_accent: "#112233", domains: ["acme.test"], ...extra } });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body as { id: number; domains: string[]; effective: { app_name: string } };
}

const flowIdOf = (page: string) => /name="flow_id" value="([^"]*)"/.exec(page)?.[1];
const assetCount = async () => (await env.DB.prepare("SELECT COUNT(*) AS n FROM brand_assets").first<{ n: number }>())!.n;

describe("logo upload", () => {
  it("takes a PNG in the console and a JPEG over the API, serves them immutable, and removing restores the default", async () => {
    const { apiKey, admin } = await setup();
    const res = await call("/admin/branding/logo", upload(admin, PNG));
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("/admin/branding?saved=logo");
    const pngUrl = (await apiCall("/api/v1/branding", { token: apiKey })).body.logo_url as string;
    expect(pngUrl).toMatch(/^\/brand\/logo\/\d+-[0-9a-f]{16}\.png$/);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'branding.logo_changed' AND target = 'Default'").first()).not.toBeNull();

    const served = await call(pngUrl);
    expect(served.status).toBe(200);
    expect(served.headers.get("Content-Type")).toBe("image/png");
    expect(served.headers.get("Cache-Control")).toBe("public, max-age=31536000, immutable");
    expect(served.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(served.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(new Uint8Array(await served.arrayBuffer())).toEqual(PNG);
    // Only the exact name: a wrong hash or extension is not the asset.
    expect((await call(pngUrl.replace(/-[0-9a-f]{4}/, "-0000"))).status).toBe(404);
    expect((await call(pngUrl.replace(".png", ".jpg"))).status).toBe(404);

    // Sign-in page, the admin top bar and My account show it.
    expect(await html("/login")).toContain(`<img src="${pngUrl}"`);
    expect(await html("/admin", { headers: { Cookie: admin } })).toContain(`<img src="${pngUrl}" alt="" class="brand-logo brand-logo-custom"`);

    const jpeg = await apiCall("/api/v1/branding/logo", { token: apiKey, method: "PUT", body: { data: `data:image/jpeg;base64,${b64(JPEG)}` } });
    expect(jpeg.status).toBe(200);
    expect(jpeg.body.logo_url).toMatch(/\.jpg$/);
    expect((await call(jpeg.body.logo_url)).headers.get("Content-Type")).toBe("image/jpeg");
    // The replaced upload is gone.
    expect((await call(pngUrl)).status).toBe(404);
    expect(await assetCount()).toBe(1);

    const removed = await apiCall("/api/v1/branding/logo", { token: apiKey, method: "DELETE" });
    expect(removed.status).toBe(200);
    expect(removed.body.logo_url).toBeNull();
    expect(await assetCount()).toBe(0);
    expect(await html("/login")).toContain('src="/FlareID_Mark.png"');

    // The console's Remove logo does the same.
    await call("/admin/branding/logo", upload(admin, PNG));
    expect((await call("/admin/branding/logo/delete", form(admin, {}))).headers.get("Location")).toBe("/admin/branding?saved=logo-removed");
    expect(await assetCount()).toBe(0);
  });

  it("refuses oversized files, files that are not PNG or JPEG by their bytes, and SVG", async () => {
    const { apiKey, admin } = await setup();
    const put = (data: string) => apiCall("/api/v1/branding/logo", { token: apiKey, method: "PUT", body: { data } });

    const big = new Uint8Array(256 * 1024 + 1);
    big.set(PNG);
    const tooBig = await put(b64(big));
    expect(tooBig.status).toBe(400);
    expect(tooBig.body.message).toContain("256 KB");

    const gif = await put(b64(new TextEncoder().encode("GIF89a\u0001\u0000\u0001\u0000")));
    expect(gif.status).toBe(400);
    expect(gif.body.message).toContain("isn't a PNG or JPEG");

    // A PNG name and type do not make an HTML file a PNG.
    const fake = await call("/admin/branding/logo", upload(admin, new TextEncoder().encode("<html><script>alert(1)</script></html>"), "logo.png", "image/png"));
    expect(decodeURIComponent(fake.headers.get("Location") ?? "")).toContain("isn't a PNG or JPEG");

    for (const svg of [SVG, new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>')]) {
      const r = await put(b64(svg));
      expect(r.status).toBe(400);
      expect(r.body.message).toContain("SVG logos aren't accepted");
    }
    const viaConsole = await call("/admin/branding/logo", upload(admin, SVG, "logo.svg", "image/svg+xml"));
    expect(viaConsole.status).toBe(302);
    expect(decodeURIComponent(viaConsole.headers.get("Location") ?? "")).toContain("SVG logos aren't accepted");
    const bigUpload = await call("/admin/branding/logo", upload(admin, big));
    expect(decodeURIComponent(bigUpload.headers.get("Location") ?? "")).toContain("at most 256 KB");

    expect((await put("not base64!")).status).toBe(400);
    expect((await put("")).status).toBe(400);
    expect(await assetCount()).toBe(0);

    expect(sniffLogo(PNG)).toBe("image/png");
    expect(sniffLogo(JPEG)).toBe("image/jpeg");
    expect(sniffLogo(SVG)).toBe("svg");
    expect(sniffLogo(PNG.slice(0, 8))).toBeNull();
  });
});

describe("per-domain brands", () => {
  it("brands the sign-in page by ?domain=, login_hint and hostname, and keeps the brand through the flow", async () => {
    const { apiKey } = await setup();
    await acmeBrand(apiKey);

    const plain = await html("/login");
    expect(plain).not.toContain("Acme ID");
    expect(plain).toContain("<span>FlareID</span>");

    const hinted = await html("/login?domain=acme.test");
    expect(hinted).toContain("<span>Acme ID</span>");
    expect(hinted).toContain("linear-gradient(45deg, #111111, #222222)");
    expect(hinted).toContain("<title>Sign in - Acme ID</title>");
    // The hint rides in the sealed flow: a wrong password re-renders in the brand.
    const failed = await (await call("/login", { method: "POST", headers: FORM, body: new URLSearchParams({ flow_id: flowIdOf(hinted)!, upn: "bob@acme.test", password: "wrong" }).toString() })).text();
    expect(failed).toContain("Incorrect username/UPN or password.");
    expect(failed).toContain("<span>Acme ID</span>");

    expect(await html("/login?login_hint=someone%40acme.test")).toContain("<span>Acme ID</span>");
    expect(await html("/login?domain=unknown.test")).not.toContain("Acme ID");

    // OIDC login_hint.
    const client = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "App", redirect_uris: ["https://app.test/cb"] } });
    const q = (extra: Record<string, string>) => new URLSearchParams({ client_id: client.body.client_id, redirect_uri: "https://app.test/cb", response_type: "code", scope: "openid", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", ...extra });
    const oidc = await html(`/authorize?${q({ login_hint: "bob@acme.test" })}`);
    expect(oidc).toContain("<span>Acme ID</span>");
    expect(await html(`/authorize?${q({})}`)).not.toContain("Acme ID");

    // Hostnames: the branded domain and its subdomains, never the issuer's own.
    expect(await html("https://login.acme.test/login")).toContain("<span>Acme ID</span>");
    expect(await html("https://acme.test/login")).toContain("<span>Acme ID</span>");
    expect(await html("https://notacme.test/login")).not.toContain("Acme ID");
    await apiCall("/api/v1/domains", { token: apiKey, body: { domain: "idp.test" } });
    const brands = (await apiCall("/api/v1/branding/brands", { token: apiKey })).body.brands as { id: number }[];
    await apiCall("/api/v1/domains/idp.test/brand", { token: apiKey, method: "PUT", body: { brand_id: brands[0]!.id } });
    expect(await html("/login")).not.toContain("Acme ID");
  });

  it("uses the person's brand once identified: the second step, My account, link pages and every email", async () => {
    const { apiKey, admin, bob, carol, idOf } = await setup();
    const acme = await acmeBrand(apiKey);
    await apiCall(`/api/v1/branding/brands/${acme.id}/logo`, { token: apiKey, method: "PUT", body: { data: PNG_B64 } });
    const logo = (await apiCall(`/api/v1/branding/brands/${acme.id}`, { token: apiKey })).body.logo_url as string;
    expect(logo).toMatch(/^\/brand\/logo\//);

    // No hint on the sign-in page; Bob's second step is in his brand.
    await env.DB.prepare("UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', mfa_enabled = 1 WHERE username = 'bob'").run();
    const start = await html("/login");
    expect(start).not.toContain("Acme ID");
    const step = await (await call("/login", { method: "POST", headers: FORM, body: new URLSearchParams({ flow_id: flowIdOf(start)!, upn: "bob@acme.test", password: "correct-horse-battery-9" }).toString() })).text();
    expect(step).toContain("Two-step verification");
    expect(step).toContain("<span>Acme ID</span>");
    expect(step).toContain(`src="${logo}"`);

    // My account: the person's name and logo in the top bar.
    const bobAccount = await html("/account", { headers: { Cookie: bob } });
    expect(bobAccount).toContain('<span class="brand-name">Acme ID</span>');
    expect(bobAccount).toContain(`<img src="${logo}"`);
    const carolAccount = await html("/account", { headers: { Cookie: carol } });
    expect(carolAccount).toContain('<span class="brand-name">FlareID</span>');
    expect(carolAccount).not.toContain(logo);
    // The admin console always wears the default brand.
    expect(await html("/admin", { headers: { Cookie: admin } })).not.toContain("Acme ID");

    // Emails: name, accent and absolute logo URL of the recipient's brand.
    const email = fakeEmail();
    expect((await call("/api/v1/users/bob/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } }, email)).status).toBe(200);
    expect((await call("/api/v1/users/carol/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } }, email)).status).toBe(200);
    const [toBob, toCarol] = email.sent;
    // Active accounts get a password-reset link from this call.
    expect(toBob!.subject).toBe("Reset your Acme ID password");
    expect(toBob!.html).toContain("border-top:4px solid #112233");
    expect(toBob!.html).toContain(`<img src="https://idp.test${logo}"`);
    expect(toCarol!.subject).toBe("Reset your FlareID password");
    expect(toCarol!.html).not.toContain("/brand/logo/");

    // The link page knows who it is for.
    const token = /\/reset-password\/([0-9a-f]+)/.exec(toBob!.text)![1];
    expect(await html(`/reset-password/${token}`)).toContain("<span>Acme ID</span>");

    // The emailed sign-in code too.
    const { sendEmailOtp } = await import("../src/lib/email-otp.js");
    const bobRow = (await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(await idOf("bob")).first())!;
    const otp = fakeEmail();
    await sendEmailOtp({ ...env, EMAIL: otp.binding } as unknown as typeof env, bobRow as never, "test-scope", "enrol");
    expect(otp.sent[0]!.subject).toContain("Acme ID");
  });

  it("creates, edits and deletes brands, and assigns domains, in the console and the API", async () => {
    const { apiKey, admin } = await setup();
    const created = await call("/admin/branding/brands", form(admin, { name: "Globex" }));
    expect(created.status).toBe(302);
    const id = Number(/\/admin\/branding\/brands\/(\d+)\?saved=1$/.exec(created.headers.get("Location") ?? "")?.[1]);
    expect(id).toBeGreaterThan(0);
    const page = await html(`/admin/branding/brands/${id}`, { headers: { Cookie: admin } });
    expect(page).toContain('value="Globex"');
    expect(page).toContain(`href="/login?brand_preview=${id}"`);
    expect(page).toContain('href="/admin/branding/brands" class="sub active"');

    const saved = await call(
      `/admin/branding/brands/${id}`,
      form(admin, [["domains_present", "1"], ["name", "Globex"], ["app_name", "Globex Login"], ["login_subtitle", ""], ["gradient_default", "1"], ["gradient_from", "#000000"], ["gradient_to", "#000000"], ["email_accent", "#abcdef"], ["custom_css", ""], ["domains", "acme.test"]])
    );
    expect(saved.headers.get("Location")).toBe(`/admin/branding/brands/${id}?saved=1`);
    const read = (await apiCall(`/api/v1/branding/brands/${id}`, { token: apiKey })).body;
    expect(read).toMatchObject({ name: "Globex", app_name: "Globex Login", login_subtitle: null, login_gradient: null, email_accent: "#abcdef", domains: ["acme.test"] });
    expect(read.effective.login_subtitle).toBe("Sign in to continue.");
    expect(read.preview_url).toBe(`/login?brand_preview=${id}`);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'brand.updated' AND target = 'Globex'").first()).not.toBeNull();

    // Names are unique and "Default" is taken.
    expect(decodeURIComponent((await call("/admin/branding/brands", form(admin, { name: "globex" }))).headers.get("Location") ?? "")).toContain("already exists");
    expect((await apiCall("/api/v1/branding/brands", { token: apiKey, body: { name: "GLOBEX" } })).status).toBe(409);
    expect((await apiCall("/api/v1/branding/brands", { token: apiKey, body: { name: "Default" } })).status).toBe(400);
    expect((await apiCall("/api/v1/branding/brands", { token: apiKey, body: { name: "X", domains: ["nope.test"] } })).status).toBe(400);
    expect((await apiCall("/api/v1/branding/brands", { token: apiKey, body: { name: "X", email_accent: "red" } })).status).toBe(400);

    // PATCH: null goes back to the default brand's value.
    const patched = await apiCall(`/api/v1/branding/brands/${id}`, { token: apiKey, method: "PATCH", body: { app_name: null } });
    expect(patched.status).toBe(200);
    expect(patched.body.app_name).toBeNull();
    expect(patched.body.effective.app_name).toBe("FlareID");

    // Domains page: the brand is chosen per domain; the API twin does the same.
    const domains = await html("/admin/domains", { headers: { Cookie: admin } });
    expect(domains).toContain(`<option value="${id}" selected>Globex</option>`);
    const acmeId = (await env.DB.prepare("SELECT id FROM domains WHERE domain = 'acme.test'").first<{ id: number }>())!.id;
    expect((await call(`/admin/domains/${acmeId}/brand`, form(admin, { brand_id: "" }))).status).toBe(302);
    expect((await env.DB.prepare("SELECT brand_id FROM domains WHERE id = ?").bind(acmeId).first<{ brand_id: number | null }>())!.brand_id).toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'domain.brand_changed' AND target = 'acme.test'").first()).not.toBeNull();
    expect((await apiCall("/api/v1/domains/acme.test/brand", { token: apiKey, method: "PUT", body: { brand_id: id } })).status).toBe(200);
    const listed = (await apiCall("/api/v1/domains", { token: apiKey })).body.domains as { domain: string; brand_id: number | null }[];
    expect(listed.find((d) => d.domain === "acme.test")?.brand_id).toBe(id);
    expect((await apiCall("/api/v1/domains/acme.test/brand", { token: apiKey, method: "PUT", body: { brand_id: 9999 } })).status).toBe(404);
    expect((await apiCall("/api/v1/domains/nope.test/brand", { token: apiKey, method: "PUT", body: { brand_id: null } })).status).toBe(404);

    // Deleting a brand returns its domains to the default brand and deletes its logo.
    await call(`/admin/branding/brands/${id}/logo`, upload(admin, PNG));
    expect(await assetCount()).toBe(1);
    expect((await call(`/admin/branding/brands/${id}/delete`, form(admin, {}))).headers.get("Location")).toBe("/admin/branding/brands?saved=1");
    expect(await assetCount()).toBe(0);
    expect((await env.DB.prepare("SELECT brand_id FROM domains WHERE id = ?").bind(acmeId).first<{ brand_id: number | null }>())!.brand_id).toBeNull();
    expect((await apiCall(`/api/v1/branding/brands/${id}`, { token: apiKey })).status).toBe(404);
    expect((await apiCall(`/api/v1/branding/brands/${id}`, { token: apiKey, method: "DELETE" })).status).toBe(404);
  });
});

describe("custom CSS", () => {
  it("is served as text/css by hash and linked only from the auth pages, with ?nocustom=1 as the escape hatch", async () => {
    const { apiKey, admin, bob } = await setup();
    const css = ".auth-brand span { color: #123456; }";
    const patched = await apiCall("/api/v1/branding", { token: apiKey, method: "PATCH", body: { custom_css: css } });
    expect(patched.status).toBe(200);
    const url = patched.body.css_url as string;
    expect(url).toMatch(/^\/brand\/css\/default-[0-9a-f]{16}\.css$/);

    const served = await call(url);
    expect(served.status).toBe(200);
    expect(served.headers.get("Content-Type")).toBe("text/css; charset=utf-8");
    expect(served.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(served.headers.get("Cache-Control")).toContain("immutable");
    expect(await served.text()).toBe(css);
    expect((await call(url.replace(/-[0-9a-f]{16}/, "-0123456789abcdef"))).status).toBe(404);
    expect((await call("/brand/css/42-0123456789abcdef.css")).status).toBe(404);

    // Linked, never inlined.
    const login = await html("/login");
    expect(login).toContain(`<link rel="stylesheet" href="${url}" />`);
    expect(login).not.toContain("#123456");
    expect(await html("/forgot-password")).toContain(url); // the "not available" page here: no EMAIL binding
    // Never on the console or My account.
    expect(await html("/admin/branding", { headers: { Cookie: admin } })).not.toContain('<link rel="stylesheet"');
    expect(await html("/admin", { headers: { Cookie: admin } })).not.toContain("/brand/css/");
    expect(await html("/account", { headers: { Cookie: bob } })).not.toContain("/brand/css/");

    // The escape hatch, kept for the browser by a cookie.
    const off = await call("/login?nocustom=1");
    expect(await off.text()).not.toContain("/brand/css/");
    expect(off.headers.get("Set-Cookie")).toContain("flareid_nocustom=1");
    expect(await html("/login", { headers: { Cookie: "flareid_nocustom=1" } })).not.toContain("/brand/css/");
    const on = await call("/login?nocustom=0", { headers: { Cookie: "flareid_nocustom=1" } });
    expect(await on.text()).toContain(url);
    expect(on.headers.get("Set-Cookie")).toContain("Max-Age=0");

    // A brand's own stylesheet, else the default brand's.
    const acme = await acmeBrand(apiKey, { custom_css: ".card { border-radius: 0; }" });
    const acmeLogin = await html("/login?domain=acme.test");
    expect(acmeLogin).toMatch(new RegExp(`<link rel="stylesheet" href="/brand/css/${acme.id}-[0-9a-f]{16}\\.css" />`));
    await apiCall(`/api/v1/branding/brands/${acme.id}`, { token: apiKey, method: "PATCH", body: { custom_css: "" } });
    expect(await html("/login?domain=acme.test")).toContain(url);

    // The console saves it too, and removing it unlinks it.
    expect((await call("/admin/branding/custom-css", form(admin, { custom_css: "" }))).headers.get("Location")).toBe("/admin/branding?saved=1");
    expect(await html("/login")).not.toContain("/brand/css/");
    expect((await call(url)).status).toBe(404);
  });

  it("refuses what has no place in a stylesheet", async () => {
    const { apiKey, admin } = await setup();
    const bad = [
      "</style><script>alert(1)</script>",
      "a{}</STYLE>",
      "@import url(https://evil.test/x.css);",
      "@import 'local.css';",
      "@\\69mport 'x.css';",
      "a{background:url(https://evil.test/x.png)}",
      "a{background:url( //evil.test/x.png )}",
      "a{background:url('http://evil.test/x.png')}",
      "a{background:\\75 rl(https://evil.test/x.png)}",
      "a{background:u\\72l(//evil.test/x.png)}",
      "a{background:image-set(\"https://evil.test/x.png\" 1x)}",
      "@font-face{font-family:x;src:url(https://fonts.evil.test/f.woff2)}",
      "a{width:expression(alert(1))}",
      "a{background:url(javascript:alert(1))}",
      "a{-moz-binding:url(/x.xml#y)}",
      "a{behavior:url(/x.htc)}",
      "a{}\u0000",
      `a{content:"${"x".repeat(20 * 1024)}"}`,
    ];
    for (const css of bad) expect(customCssProblem(css), css.slice(0, 60)).not.toBeNull();
    const good = [
      ".auth-brand span { display: none; } /* hide the name */",
      "body{background:url(/FlareID_Icon.png) no-repeat}",
      "a{background:url('data:image/png;base64,AAAA')}",
      'a::before{content:"\\2014"}',
      "@media (max-width: 600px) { .center-wrap { margin-top: 2vh; } }",
      "",
    ];
    for (const css of good) expect(customCssProblem(css), css).toBeNull();

    const refused = await apiCall("/api/v1/branding", { token: apiKey, method: "PATCH", body: { app_name: "Changed", custom_css: "@import url(https://evil.test/x.css);" } });
    expect(refused.status).toBe(400);
    expect(refused.body.message).toContain("@import");
    // Validated before anything is saved.
    expect((await apiCall("/api/v1/branding", { token: apiKey })).body.app_name).toBe("FlareID");
    expect((await apiCall("/api/v1/branding/brands", { token: apiKey, body: { name: "Bad", custom_css: "a{background:url(https://x.test/y)}" } })).status).toBe(400);
    const viaConsole = await call("/admin/branding/custom-css", form(admin, { custom_css: "</style><script>alert(1)</script>" }));
    expect(decodeURIComponent(viaConsole.headers.get("Location") ?? "")).toContain("error=Custom CSS cannot contain <style> or <script>");
    expect((await apiCall("/api/v1/branding", { token: apiKey })).body.custom_css).toBe("");
  });
});

describe("branding permissions and preview", () => {
  it("lets branding:read look and preview but not change anything; previews need it", async () => {
    const { apiKey, vic, bob } = await setup();
    const acme = await acmeBrand(apiKey);
    const acmeDomain = (await env.DB.prepare("SELECT id FROM domains WHERE domain = 'acme.test'").first<{ id: number }>())!.id;

    for (const path of ["/admin/branding", "/admin/branding/brands", `/admin/branding/brands/${acme.id}`]) {
      expect((await call(path, { headers: { Cookie: vic } })).status, path).toBe(200);
    }
    expect(await html("/admin/branding", { headers: { Cookie: vic } })).toContain('href="/login?brand_preview=default"');
    const refusals: [string, RequestInit][] = [
      ["/admin/branding/logo", upload(vic, PNG)],
      ["/admin/branding/logo/delete", form(vic, {})],
      ["/admin/branding/custom-css", form(vic, { custom_css: "a{}" })],
      ["/admin/branding/brands", form(vic, { name: "Mine" })],
      [`/admin/branding/brands/${acme.id}`, form(vic, { name: "Renamed" })],
      [`/admin/branding/brands/${acme.id}/delete`, form(vic, {})],
      [`/admin/branding/brands/${acme.id}/logo`, upload(vic, PNG)],
      [`/admin/branding/brands/${acme.id}/logo/delete`, form(vic, {})],
      [`/admin/domains/${acmeDomain}/brand`, form(vic, { brand_id: "" })],
    ];
    for (const [path, init] of refusals) expect((await call(path, init)).status, path).toBe(403);
    expect((await apiCall(`/api/v1/branding/brands/${acme.id}`, { token: apiKey })).body.name).toBe("Acme");
    expect(await assetCount()).toBe(0);

    // The preview: for branding:read, a branded sign-in page even while signed in.
    const preview = await call(`/login?brand_preview=${acme.id}`, { headers: { Cookie: vic } });
    expect(preview.status).toBe(200);
    const previewHtml = await preview.text();
    expect(previewHtml).toContain('Preview of the &quot;Acme&quot; brand.');
    expect(previewHtml).toContain("<span>Acme ID</span>");
    expect(await html("/login?brand_preview=default", { headers: { Cookie: vic } })).toContain("Preview of the default brand.");
    // Without branding:read, or signed out, the parameter does nothing.
    const bobTry = await call(`/login?brand_preview=${acme.id}`, { headers: { Cookie: bob } });
    expect(bobTry.status).toBe(302);
    const anon = await html(`/login?brand_preview=${acme.id}`);
    expect(anon).not.toContain("Preview of");
    expect(anon).not.toContain("Acme ID");
    expect((await call("/login?brand_preview=9999", { headers: { Cookie: vic } })).status).toBe(302);

    // An API key with branding:read reads but cannot write.
    const key = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "reader", scopes: ["branding:read"] } });
    const reader = key.body.token as string;
    expect((await apiCall("/api/v1/branding", { token: reader })).status).toBe(200);
    expect((await apiCall("/api/v1/branding/brands", { token: reader })).status).toBe(200);
    expect((await apiCall("/api/v1/branding/logo", { token: reader, method: "PUT", body: { data: PNG_B64 } })).status).toBe(403);
    expect((await apiCall("/api/v1/branding/brands", { token: reader, body: { name: "Nope" } })).status).toBe(403);
    expect((await apiCall(`/api/v1/branding/brands/${acme.id}`, { token: reader, method: "DELETE" })).status).toBe(403);
    expect((await apiCall("/api/v1/domains/acme.test/brand", { token: reader, method: "PUT", body: { brand_id: null } })).status).toBe(403);
  });
});
