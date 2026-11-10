// Regression for run-2 wave-5 findings (hunter h28-scim-expand reproduction, assertions inverted).
import { beforeEach, describe, expect, it } from "vitest";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/index.js";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { setScimConfig } from "../src/lib/settings.js";
import { syncAll } from "../src/lib/scim-client.js";

beforeEach(resetDatabase);
const FORM = { "Content-Type": "application/x-www-form-urlencoded", Origin: BASE };

async function call(path: string, init: RequestInit = {}) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(BASE + path, { redirect: "manual", ...init }), env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}
async function setup() {
  const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
  await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "ola", password: "user-password-123", status: "active" }] } });
  await setScimConfig(env, { endpoint: "https://scim.test/scim/v2", secret: "x" });
  const ola = (await env.DB.prepare("SELECT id FROM users WHERE username = 'ola'").first<{ id: number }>())!.id;
  await env.DB.prepare("UPDATE users SET scim_id = 'remote-ola' WHERE id = ?").bind(ola).run();
  const contractors = (await env.DB.prepare("INSERT INTO groups (name, rule) VALUES ('Contractors', '') RETURNING id").first<{ id: number }>())!.id;
  const adminId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>())!.id;
  const cookie = (await createSession(env, adminId, ["pwd", "mfa"], new Request(BASE))).setCookie.split(";")[0]!;
  return { ola, contractors, cookie };
}
function recordFetch(failPatch: boolean) {
  const seen: string[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (i: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(i, init);
    seen.push(`${req.method} ${new URL(req.url).pathname}`);
    return failPatch && req.method === "PATCH" ? new Response("unavailable", { status: 503 }) : real(req);
  }) as typeof fetch;
  return { seen, restore: () => void (globalThis.fetch = real) };
}

describe("h28 scim scope", () => {
  it("scope-narrowing deactivation failure is audited", async () => {
    const { contractors, cookie } = await setup();
    const f = recordFetch(true);
    try {
      const res = await call("/admin/scim/scope", { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `mode=selected&group_ids=${contractors}` });
      expect(res.status).toBe(302);
    } finally { f.restore(); }
    console.log("H28-A seen:", JSON.stringify(f.seen));
    expect(f.seen).toContain("PATCH /scim/v2/Users/remote-ola");
    const audits = await env.DB.prepare("SELECT action FROM audit_log WHERE action LIKE 'scim.%'").all<{ action: string }>();
    console.log("H28-A scim audit rows:", JSON.stringify(audits.results));
    expect(audits.results.length).toBeGreaterThan(0);
  });

  it("scope narrowing removes a previously synced out-of-scope group downstream", async () => {
    const { ola, contractors, cookie } = await setup();
    const eng = (await env.DB.prepare("INSERT INTO groups (name, rule, scim_id) VALUES ('Eng', '', 'remote-eng') RETURNING id").first<{ id: number }>())!.id;
    await env.DB.batch([
      env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(eng, ola),
      env.DB.prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)").bind(contractors, ola),
    ]);
    const f = recordFetch(false);
    try {
      await call("/admin/scim/scope", { method: "POST", headers: { ...FORM, Cookie: cookie }, body: `mode=selected&group_ids=${contractors}` });
    } finally { f.restore(); }
    const row = await env.DB.prepare("SELECT scim_id FROM groups WHERE id = ?").bind(eng).first<{ scim_id: string | null }>();
    console.log("H28-B after scope POST seen:", JSON.stringify(f.seen), "eng.scim_id:", row?.scim_id);
    expect(f.seen).toContain("PUT /scim/v2/Users/remote-ola");
    expect(f.seen).toContain("DELETE /scim/v2/Groups/remote-eng");
    expect(row?.scim_id ?? null).toBeNull();
  });
});
