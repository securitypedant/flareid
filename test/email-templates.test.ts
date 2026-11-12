// Branding > Email templates in the console: editing, resetting, the accent
// colour, the preview, and that what is saved is what gets sent.
import { beforeEach, describe, expect, it } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { createSession } from "../src/lib/sessions.js";
import { DEFAULT_TEMPLATES, getAccent, getTemplate } from "../src/lib/email-templates.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";

beforeEach(resetDatabase);

const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

function fakeEmail() {
  const sent: { to: string; subject: string; text: string; html: string }[] = [];
  return {
    sent,
    binding: {
      async send(message: { to: string; subject: string; text: string; html: string }) {
        sent.push(message);
        return { messageId: `msg-${sent.length}` };
      },
    },
  };
}

async function call(email: ReturnType<typeof fakeEmail>, path: string, init: RequestInit = {}) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${BASE}${path}`, { redirect: "manual", ...init }), { ...env, EMAIL: email.binding } as unknown as typeof env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

async function setup() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", {
    token: apiKey,
    body: {
      version: 1,
      passwords: "none",
      groups: [{ name: "Viewers" }],
      users: [
        { username: "nina", status: "disabled", email: "nina@personal.test", display_name: "Nina Simone" },
        { username: "vic", status: "active", groups: ["Viewers"] },
      ],
    },
  });
  const role = await apiCall("/api/v1/security/roles", { token: apiKey, body: { name: "Branding Viewers", permissions: ["branding:read"], groups: ["Viewers"] } });
  expect(role.status).toBe(201);
  await env.DB.prepare("INSERT OR REPLACE INTO idp_settings (key, value, updated_at) VALUES ('email_from_address', 'no-reply@horizon.test', '')").run();
  const sessionFor = async (u: string) => {
    const id = (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(u).first<{ id: number }>())!.id;
    return (await createSession(env, id, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  };
  return { apiKey, admin: await sessionFor("admin"), vic: await sessionFor("vic") };
}

describe("email templates in the console", () => {
  it("saves a template that the next invitation uses, and resets it to the default", async () => {
    const { apiKey, admin } = await setup();
    const email = fakeEmail();
    const page = await (await call(email, "/admin/branding/email-templates?t=invitation", { headers: { Cookie: admin } })).text();
    expect(page).toContain('action="/admin/branding/email-templates/invitation"');
    expect(page).toContain("{{app_name}}");
    expect(page).toContain("Button label");
    expect(page).toContain('href="/admin/branding/email-templates" class="sub active"');

    const save = await call(email, "/admin/branding/email-templates/invitation", {
      method: "POST",
      headers: { ...FORM, Cookie: admin },
      body: new URLSearchParams({ subject: "Join {{app_name}} today", heading: "Hi {{name}}", body: "Welcome aboard.", action: "Get started", footer: "Questions? Ask IT." }).toString(),
    });
    expect(save.status).toBe(302);
    expect(save.headers.get("Location")).toContain("saved=1");
    const audit = await env.DB.prepare("SELECT action, target FROM audit_log WHERE action = 'settings.email_template_changed'").first<{ action: string; target: string }>();
    expect(audit?.target).toBe("invitation");

    const invite = await call(email, "/api/v1/users/nina/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } });
    expect(invite.status).toBe(200);
    expect(email.sent).toHaveLength(1);
    const appName = (await apiCall("/api/v1/branding", { token: apiKey })).body.app_name as string;
    expect(email.sent[0]!.subject).toBe(`Join ${appName} today`);
    expect(email.sent[0]!.text).toContain("Hi Nina Simone");
    expect(email.sent[0]!.html).toContain("Get started");
    expect(email.sent[0]!.text).toContain("Get started: https://idp.test/invite/");

    const reset = await call(email, "/admin/branding/email-templates/invitation/reset", { method: "POST", headers: { ...FORM, Cookie: admin } });
    expect(reset.status).toBe(302);
    expect(await getTemplate(env, "invitation")).toEqual(DEFAULT_TEMPLATES.invitation);
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'settings.email_template_reset' AND target = 'invitation'").first()).not.toBeNull();
    await call(email, "/api/v1/users/nina/invite", { method: "POST", headers: { Authorization: `Bearer ${apiKey}` } });
    expect(email.sent[1]!.subject).toBe(`You've been invited to ${appName}`);
  });

  it("refuses an empty subject and an unknown template", async () => {
    const { admin } = await setup();
    const email = fakeEmail();
    const res = await call(email, "/admin/branding/email-templates/password_reset", { method: "POST", headers: { ...FORM, Cookie: admin }, body: "subject=+&heading=Hi" });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toContain("error=");
    expect(await getTemplate(env, "password_reset")).toEqual(DEFAULT_TEMPLATES.password_reset);
    expect((await call(email, "/admin/branding/email-templates/nope", { method: "POST", headers: { ...FORM, Cookie: admin }, body: "subject=x&heading=y" })).status).toBe(404);
  });

  it("saves a valid accent colour and refuses anything else", async () => {
    const { admin } = await setup();
    const email = fakeEmail();
    const ok = await call(email, "/admin/branding/email-accent", { method: "POST", headers: { ...FORM, Cookie: admin }, body: "accent=%23123ABC&t=email_otp" });
    expect(ok.status).toBe(302);
    expect(ok.headers.get("Location")).toBe("/admin/branding/email-templates?t=email_otp&saved=1");
    expect(await getAccent(env)).toBe("#123abc");
    expect(await env.DB.prepare("SELECT 1 FROM audit_log WHERE action = 'settings.email_accent_changed'").first()).not.toBeNull();
    for (const bad of ["red", "#12345", "#12345g", "javascript:alert(1)"]) {
      const res = await call(email, "/admin/branding/email-accent", { method: "POST", headers: { ...FORM, Cookie: admin }, body: new URLSearchParams({ accent: bad }).toString() });
      expect(res.status, bad).toBe(400);
    }
    expect(await getAccent(env)).toBe("#123abc");
  });

  it("previews the rendered email with sample values, escaped, without saving", async () => {
    const { admin } = await setup();
    const email = fakeEmail();
    const page = await (await call(email, "/admin/branding/email-templates?t=email_otp", { headers: { Cookie: admin } })).text();
    expect(page).toContain("428 913");
    expect(page).toContain("for the next 10 minutes");
    expect(page).not.toContain("Button label");
    expect(page).toContain("{{code}}");

    const q = new URLSearchParams({ t: "invitation", subject: "Hello {{name}}", heading: "<script>alert(1)</script>", body: "Line one", footer: "Bye" });
    const frag = await call(email, `/admin/branding/email-templates/preview?${q}&accent=%23ff0000`, { headers: { Cookie: admin } });
    expect(frag.status).toBe(200);
    const html = await frag.text();
    expect(html).toContain("Hello Ada Lovelace");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain("https://example.com/invite/sample-link");
    expect(html).toContain("#ff0000");
    expect(html).toContain("Activate your account"); // a field not sent keeps the saved wording

    // The no-script Preview button: the draft on the page, nothing saved.
    const draft = await (await call(email, `/admin/branding/email-templates?${q}`, { headers: { Cookie: admin } })).text();
    expect(draft).toContain("Previewing unsaved changes");
    expect(draft).toContain("Hello Ada Lovelace");
    expect(await getTemplate(env, "invitation")).toEqual(DEFAULT_TEMPLATES.invitation);
  });

  it("lets branding:read see the templates but not change them", async () => {
    const { vic } = await setup();
    const email = fakeEmail();
    expect((await call(email, "/admin/branding/email-templates", { headers: { Cookie: vic } })).status).toBe(200);
    const post = (path: string, body: string) => call(email, path, { method: "POST", headers: { ...FORM, Cookie: vic }, body });
    expect((await post("/admin/branding/email-templates/invitation", "subject=Pwned&heading=Pwned")).status).toBe(403);
    expect((await post("/admin/branding/email-templates/invitation/reset", "")).status).toBe(403);
    expect((await post("/admin/branding/email-accent", "accent=%23000000")).status).toBe(403);
    expect(await getTemplate(env, "invitation")).toEqual(DEFAULT_TEMPLATES.invitation);
  });
});
