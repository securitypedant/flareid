import { SELF, env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BASE, bootstrapInstance, resetDatabase } from "./helpers.js";
import { parseIdentifier } from "../src/lib/identifier.js";
import { createUpstreamIdp, resolveFederatedUser } from "../src/lib/federation.js";

const PASSWORD = "user-password-123";
const IDP = { name: "GitHub", protocol: "oidc" as const, config: { issuer: "https://i.test", client_id: "c", client_secret: "s" }, jit: true, jitDomain: "" };

beforeEach(resetDatabase);

async function seedUser(apiKey: string, body: Record<string, unknown>) {
  const r = await apiCall("/api/v1/users", { token: apiKey, body: { given_name: "U", password: PASSWORD, status: "active", ...body } });
  if (r.status !== 201) throw new Error(`seed: ${JSON.stringify(r.body)}`);
  return r.body;
}

/** A failed or successful sign-in; `target` is who the directory resolved the name to. */
async function signIn(upn: string, password = PASSWORD): Promise<boolean> {
  const loginPage = await SELF.fetch(`${BASE}/login`, { redirect: "manual" });
  const flowId = /name="flow_id" value="([^"]+)"/.exec(await loginPage.text())?.[1] ?? "";
  const res = await SELF.fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ flow_id: flowId, upn, password }).toString(),
    redirect: "manual",
  });
  await res.text();
  return Boolean(res.headers.get("Set-Cookie")?.includes("flareid_session"));
}

async function lastFailedLogin(): Promise<{ target: string; details: string }> {
  return (await env.DB.prepare("SELECT target, details FROM audit_log WHERE action = 'login.failed' ORDER BY id DESC LIMIT 1").first<{ target: string; details: string }>())!;
}

describe("parseIdentifier", () => {
  it("classifies the three forms and normalizes", () => {
    expect(parseIdentifier("Simon@D.COM")).toMatchObject({ kind: "upn", normalized: "simon@d.com", username: "simon" });
    expect(parseIdentifier("Simon")).toMatchObject({ kind: "handle", normalized: "simon" });
    expect(parseIdentifier("+1 (555) 123-4567")).toMatchObject({ kind: "phone", normalized: "+15551234567" });
  });

  it("rejects digit-only handles and bad shapes", () => {
    expect(parseIdentifier("15551234567")).toBeNull(); // reserved: would shadow a phone
    expect(parseIdentifier("+555")).toBeNull();
    expect(parseIdentifier("a@")).toBeNull();
    expect(parseIdentifier("@b.com")).toBeNull();
    expect(parseIdentifier("")).toBeNull();
  });
});

describe("sign-in names", () => {
  it("creates a handle account that signs in with the bare name", async () => {
    const { apiKey } = await bootstrapInstance();
    const r = await seedUser(apiKey, { identifier: "simon" });
    expect(r.upn).toBe("simon");
    expect(await signIn("simon")).toBe(true);
  });

  it("creates a phone account that signs in with the number", async () => {
    const { apiKey } = await bootstrapInstance();
    const r = await seedUser(apiKey, { identifier: "+15551234567" });
    expect(r.upn).toBe("+15551234567");
    expect(await signIn("+15551234567")).toBe(true);
    expect(await signIn("+1 (555) 123-4567")).toBe(true);
  });

  it("lets the same local part exist under two domains", async () => {
    const { apiKey } = await bootstrapInstance();
    await env.DB.prepare("INSERT INTO domains (domain, is_default, created_at) VALUES ('d2.test', 0, ?)").bind(new Date().toISOString()).run();
    await seedUser(apiKey, { username: "simon" }); // simon@example.com (default domain)
    await seedUser(apiKey, { username: "simon", domain: "d2.test" });
    expect(await signIn("simon@example.com")).toBe(true);
    expect(await signIn("simon@d2.test")).toBe(true);
  });

  it("resolves a bare local part only when it names one account", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { username: "ned" });
    expect(await signIn("ned")).toBe(true);
    await env.DB.prepare("INSERT INTO domains (domain, is_default, created_at) VALUES ('d2.test', 0, ?)").bind(new Date().toISOString()).run();
    await seedUser(apiKey, { username: "ned", domain: "d2.test" });
    // Now ambiguous: fails like an unknown name, never picks an account.
    expect(await signIn("ned")).toBe(false);
    const audit = await lastFailedLogin();
    expect(audit.target).toBe("ned");
    expect(JSON.parse(audit.details).reason).toBe("ambiguous_identifier");
  });

  it("a handle owns its bare name against UPN local parts", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { username: "securitypedant" }); // securitypedant@example.com
    await seedUser(apiKey, { identifier: "securitypedant" }); // the handle account
    // A wrong password against "securitypedant" audits the handle's upn -
    // the exact identifier match won over the local-part candidate.
    expect(await signIn("securitypedant", "wrong-password")).toBe(false);
    expect((await lastFailedLogin()).target).toBe("securitypedant");
  });

  it("resolves a phone alias on a UPN account", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { username: "ned", phones: [{ value: "+15551234567", type: "mobile", primary: true }] });
    expect(await signIn("+15551234567")).toBe(true);
  });

  it("refuses a phone alias that is another account's sign-in name", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { identifier: "+15551234567" });
    const r = await apiCall("/api/v1/users", { token: apiKey, body: { username: "ned", given_name: "N", phones: [{ value: "+15551234567" }] } });
    expect(r.status).toBe(400); // same as a clashing email alias
  });

  it("GETs and PATCHes a user by any sign-in name form", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { identifier: "simon" });
    const got = await apiCall("/api/v1/users/simon", { token: apiKey });
    expect(got.status).toBe(200);
    expect(got.body.upn).toBe("simon");
    const moved = await apiCall("/api/v1/users/simon", { token: apiKey, method: "PATCH", body: { identifier: "simon@example.com" } });
    expect(moved.status).toBe(200);
    expect(moved.body.upn).toBe("simon@example.com");
  });
});

describe("federated minting", () => {
  const profile = { subject: "s1", email: "p@mail.test", givenName: "P", familyName: "P", displayName: "P P", emailVerified: true };

  it("mints a verbatim UPN for an @-form upstream name, unmanaged domain included", async () => {
    await bootstrapInstance();
    const idp = await createUpstreamIdp(env, { ...IDP });
    const user = await resolveFederatedUser(env, idp, { ...profile, username: "simonsmith01@gmail.com" });
    expect(user.upn).toBe("simonsmith01@gmail.com");
  });

  it("mints {handle}-{idp} for a bare upstream handle", async () => {
    await bootstrapInstance();
    const idp = await createUpstreamIdp(env, { ...IDP });
    const user = await resolveFederatedUser(env, idp, { ...profile, username: "simon" });
    expect(user.upn).toBe("simon-github");
    expect(user.username).toBe("simon-github");
  });

  it("refuses to mint inside a managed domain the provider isn't granted", async () => {
    await bootstrapInstance(); // example.com is managed; the IdP's jit_domain is ""
    const idp = await createUpstreamIdp(env, { ...IDP });
    await expect(resolveFederatedUser(env, idp, { ...profile, username: "exec@example.com" })).rejects.toThrow(/managed domain/);
  });

  it("mints inside a managed domain when the IdP is granted it (jit_domain)", async () => {
    await bootstrapInstance();
    const idp = await createUpstreamIdp(env, { ...IDP, jitDomain: "example.com" });
    const user = await resolveFederatedUser(env, idp, { ...profile, username: "exec@example.com" });
    expect(user.upn).toBe("exec@example.com");
  });

  it("won't adopt an account named by an @-form claim the IdP calls unverified", async () => {
    const { apiKey } = await bootstrapInstance();
    await seedUser(apiKey, { username: "ada" }); // ada@example.com
    const idp = await createUpstreamIdp(env, { ...IDP });
    // The claim names the managed-domain account but is explicitly unverified:
    // no adoption, and the managed-domain mint refusal stops the fallback too.
    await expect(resolveFederatedUser(env, idp, { ...profile, subject: "sub-ada", username: "ada@example.com", emailVerified: false })).rejects.toThrow();
    expect(await env.DB.prepare("SELECT 1 FROM federated_identities WHERE subject = 'sub-ada'").first()).toBeNull();
  });
});
