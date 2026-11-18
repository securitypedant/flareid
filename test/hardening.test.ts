import { beforeEach, describe, expect, it, vi } from "vitest";
import { SELF, env } from "cloudflare:test";
import { apiCall, BASE, bootstrapInstance, resetDatabase, BOOTSTRAP } from "./helpers.js";
import { createSession } from "../src/lib/sessions.js";
import { drainSsfOutbox, emitSsfEvent, receiveSet, ssfClearCaches, SSF_EVENTS } from "../src/lib/ssf.js";
import { verifyAuditChain } from "../src/lib/audit.js";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

beforeEach(async () => {
  await resetDatabase();
  ssfClearCaches();
});

async function seedUser(apiKey: string, username: string): Promise<number> {
  const res = await apiCall("/api/v1/users", { token: apiKey, body: { username, given_name: username[0]!.toUpperCase() + username.slice(1), password: "user-password-123", status: "active" } });
  if (res.status !== 201) throw new Error(`user create failed: ${JSON.stringify(res.body)}`);
  return (await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first<{ id: number }>())!.id;
}

/** Stubs outbound fetch for the named hosts; other requests pass through. */
function stubHosts(handler: (url: URL, init?: RequestInit) => Response, ...hosts: string[]) {
  const calls: { method: string; url: string }[] = [];
  const real = globalThis.fetch.bind(globalThis);
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const u = new URL(url);
    if (!hosts.some((h) => u.hostname === h || u.hostname.endsWith(`.${h}`))) return real(input as RequestInfo, init);
    calls.push({ method: init?.method ?? "GET", url });
    return handler(u, init);
  });
  return calls;
}

describe("audit tamper-evidence", () => {
  it("chains rows and verifies; a tampered row breaks the chain", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, "ada");
    await seedUser(apiKey, "bob");

    const verify = await apiCall("/api/v1/audit/verify", { token: apiKey });
    expect(verify.status).toBe(200);
    expect(verify.body.status).toBe("ok");
    expect(verify.body.checked).toBeGreaterThan(0);

    // Rewrite history: change what a row says happened.
    const row = await env.DB.prepare("SELECT id FROM audit_log WHERE chain_hash IS NOT NULL ORDER BY id LIMIT 1 OFFSET 1").first<{ id: number }>();
    await env.DB.prepare("UPDATE audit_log SET action = 'user.created_innocently' WHERE id = ?").bind(row!.id).run();
    const broken = await apiCall("/api/v1/audit/verify", { token: apiKey });
    expect(broken.body.status).toBe("broken");
    expect(broken.body.at_id).toBe(row!.id);

    // Deleting a later row also breaks it - the next row's parent vanishes.
    await resetDatabase();
    const { apiKey: k2 } = await bootstrapInstance();
    await seedUser(k2, "ada");
    const mid = await env.DB.prepare("SELECT id FROM audit_log WHERE chain_hash IS NOT NULL ORDER BY id LIMIT 1 OFFSET 1").first<{ id: number }>();
    await env.DB.prepare("DELETE FROM audit_log WHERE id = ?").bind(mid!.id).run();
    const deleted = await verifyAuditChain(env);
    expect(deleted.status).toBe("broken");
  });

  it("exports NDJSON with chain_hash for offline re-verification", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, "ada");
    const res = await SELF.fetch(`${BASE}/api/v1/audit/export`, { headers: { Authorization: `Bearer ${apiKey}` } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("ndjson");
    const lines = (await res.text()).trim().split("\n");
    const first = JSON.parse(lines[0]!);
    expect(first.chain_hash).toBeTruthy();
    expect(first.action).toBeTruthy();
  });
});

describe("backup and restore", () => {
  it("exports every table; restore brings a deleted user back", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, "ada");

    const backup = await apiCall("/api/v1/backup", { token: apiKey });
    expect(backup.status).toBe(200);
    expect(backup.body.version).toBe(1);
    expect(backup.body.tables.users.length).toBeGreaterThan(1);
    expect(backup.body.tables.d1_migrations).toBeUndefined();

    await apiCall("/api/v1/users/ada", { token: apiKey, method: "DELETE" });
    expect(await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first()).toBeNull();

    // The restore needs the bootstrap token - an admin API key is refused.
    expect((await apiCall("/api/v1/backup/restore", { token: apiKey, body: backup.body })).status).toBe(401);
    // And it needs the confirmation flag.
    expect((await apiCall("/api/v1/backup/restore", { token: BOOTSTRAP, body: backup.body })).status).toBe(400);

    const restore = await apiCall("/api/v1/backup/restore", { token: BOOTSTRAP, body: { ...backup.body, confirm: true } });
    expect(restore.status).toBe(200);
    expect(restore.body.restored).toBeGreaterThan(10);
    expect(await env.DB.prepare("SELECT id FROM users WHERE username = 'ada'").first()).toBeTruthy();
  });
});

describe("shared signals", () => {
  it("advertises its configuration", async () => {
    const res = await SELF.fetch(`${BASE}/.well-known/ssf-configuration`);
    const doc = await res.json<{ issuer: string; jwks_uri: string; events_supported: string[] }>();
    expect(doc.jwks_uri).toContain("/jwks.json");
    expect(doc.events_supported).toContain(SSF_EVENTS["caep.session-revoked"]);
  });

  it("renders the console page", async () => {
    await bootstrapInstance();
    const admin = await env.DB.prepare("SELECT id FROM users WHERE username = 'admin'").first<{ id: number }>();
    const { setCookie } = await createSession(env, admin!.id, ["pwd", "mfa"], new Request(BASE));
    const res = await SELF.fetch(`${BASE}/admin/integrations/signals`, { headers: { Cookie: setCookie.split(";")[0]! } });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Outbound streams");
    expect(html).toContain("Inbound transmitters");
    expect(html).toContain("/ssf/receive");
  });

  it("queues and delivers SETs to a registered stream", async () => {
    const { apiKey } = await bootstrapInstance();
    const stream = await apiCall("/api/v1/ssf/streams", { token: apiKey, body: { name: "Okta", endpoint_url: "https://rx.example.com/events" } });
    expect(stream.status).toBe(201);

    await emitSsfEvent(env, SSF_EVENTS["caep.session-revoked"], { format: "email", email: "ada@example.com" });
    expect(await env.DB.prepare("SELECT id FROM ssf_outbox").first()).toBeTruthy();

    const calls = stubHosts(() => new Response("{}", { status: 200 }), "rx.example.com");
    const drained = await drainSsfOutbox(env);
    expect(drained).toEqual({ sent: 1, failed: 0 });
    expect(await env.DB.prepare("SELECT id FROM ssf_outbox").first()).toBeNull();
    // The receiver got a signed secevent+jwt, not JSON.
    expect(calls[0]!.url).toBe("https://rx.example.com/events");

    const streamNow = await apiCall("/api/v1/ssf/streams", { token: apiKey });
    expect(streamNow.body.streams[0].last_push_at).toBeTruthy();
  });

  it("retries a failing endpoint and reports the error", async () => {
    await bootstrapInstance();
    await env.DB.prepare("INSERT INTO ssf_streams (name, endpoint_url, aud, events, created_at) VALUES ('rx', 'https://rx.example.com/e', '', '[]', 'now')").run();
    await emitSsfEvent(env, SSF_EVENTS["caep.credential-change"], { format: "email", email: "x@example.com" });
    stubHosts(() => new Response("down", { status: 500 }), "rx.example.com");
    const r = await drainSsfOutbox(env);
    expect(r).toEqual({ sent: 0, failed: 1 });
    const row = await env.DB.prepare("SELECT attempts, last_error FROM ssf_outbox").first<{ attempts: number; last_error: string }>();
    expect(row!.attempts).toBe(1);
    expect(row!.last_error).toContain("500");
  });

  it("receives a signed SET: session-revoked kills sessions, risk events flag the user", async () => {
    const { apiKey } = await bootstrapInstance();
    const userId = await seedUser(apiKey, "ada");
    const upn = (await env.DB.prepare("SELECT upn FROM users WHERE id = ?").bind(userId).first<{ upn: string }>())!.upn;
    await createSession(env, userId, ["pwd"], new Request(BASE));

    const tx = await apiCall("/api/v1/ssf/transmitters", { token: apiKey, body: { name: "CF", issuer: "https://tx.example.com", jwks_url: "https://tx.example.com/jwks.json" } });
    expect(tx.status).toBe(201);

    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "tx1" };
    stubHosts(() => Response.json({ keys: [jwk] }), "tx.example.com");

    const set = await new SignJWT({ events: { [SSF_EVENTS["caep.session-revoked"]]: { subject: { format: "email", email: upn } } } })
      .setProtectedHeader({ alg: "RS256", kid: "tx1" })
      .setIssuer("https://tx.example.com")
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(privateKey);

    const res = await SELF.fetch(`${BASE}/ssf/receive`, { method: "POST", body: set });
    expect(res.status).toBe(202);
    expect((await res.json<{ accepted: string[] }>()).accepted).toContain(SSF_EVENTS["caep.session-revoked"]);
    expect(await env.DB.prepare("SELECT id FROM sessions WHERE user_id = ? AND revoked_at IS NULL").bind(userId).first()).toBeNull();

    // A risk signal flags the user on the watchlist.
    const flag = await new SignJWT({ events: { ["https://schemas.openid.net/secevent/risc/event-type/credential-compromise"]: { subject: { format: "email", email: upn } } } })
      .setProtectedHeader({ alg: "RS256", kid: "tx1" })
      .setIssuer("https://tx.example.com")
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(privateKey);
    expect((await SELF.fetch(`${BASE}/ssf/receive`, { method: "POST", body: flag })).status).toBe(202);
    expect(await env.DB.prepare("SELECT user_id FROM user_watch WHERE user_id = ?").bind(userId).first()).toBeTruthy();
  });

  it("rejects SETs from unknown issuers and bad signatures", async () => {
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/ssf/transmitters", { token: apiKey, body: { name: "CF", issuer: "https://tx.example.com", jwks_url: "https://tx.example.com/jwks.json" } });

    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = { ...(await exportJWK(publicKey)), kid: "tx1" };
    stubHosts(() => Response.json({ keys: [jwk] }), "tx.example.com");

    const unknown = await new SignJWT({ events: {} })
      .setProtectedHeader({ alg: "RS256", kid: "x" })
      .setIssuer("https://stranger.example.com")
      .setIssuedAt()
      .sign(privateKey);
    expect((await SELF.fetch(`${BASE}/ssf/receive`, { method: "POST", body: unknown })).status).toBe(401);

    const { privateKey: evil } = await generateKeyPair("RS256");
    const forged = await new SignJWT({ events: {} })
      .setProtectedHeader({ alg: "RS256", kid: "tx1" })
      .setIssuer("https://tx.example.com")
      .setIssuedAt()
      .sign(evil);
    expect((await SELF.fetch(`${BASE}/ssf/receive`, { method: "POST", body: forged })).status).toBe(401);
  });
});
