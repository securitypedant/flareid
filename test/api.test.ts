import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, BOOTSTRAP, bootstrapInstance, resetDatabase } from "./helpers.js";
import { MAX_USERS_PER_IMPORT } from "../src/lib/directory-import.js";

beforeEach(resetDatabase);

describe("API authentication", () => {
  it("refuses a request with no token", async () => {
    const { status, body } = await apiCall("/api/v1/status");
    expect(status).toBe(401);
    expect(body.error).toBe("unauthorized");
  });

  it("refuses an unknown token", async () => {
    const { status } = await apiCall("/api/v1/status", { token: "flareid_sk_notarealkey" });
    expect(status).toBe(401);
  });

  it("accepts the bootstrap token before setup is complete", async () => {
    const { status, body } = await apiCall("/api/v1/status", { token: BOOTSTRAP });
    expect(status).toBe(200);
    expect(body.setup_completed).toBe(false);
    expect(body.counts.users).toBe(0);
  });

  it("stops accepting the bootstrap token once setup completes", async () => {
    await bootstrapInstance();
    const { status, body } = await apiCall("/api/v1/status", { token: BOOTSTRAP });
    expect(status).toBe(403);
    expect(body.message).toMatch(/only works until initial setup/);
  });

  it("keeps accepting the bootstrap token while setup is left incomplete", async () => {
    // This is the contract provisioning scripts depend on: marking setup
    // complete is what retires the token, so a multi-step provisioning run
    // leaves `complete` until its very last call. Getting this wrong means the
    // directory import arrives with a token that was valid one request ago.
    const first = await apiCall("/api/v1/setup", {
      token: BOOTSTRAP,
      body: { domain: "horizon.test", admin: { username: "admin" } },
    });
    expect(first.status).toBe(200);
    expect(first.body.setup_completed).toBe(false);

    const stillWorks = await apiCall("/api/v1/directory/import", {
      token: BOOTSTRAP,
      body: { version: 1, users: [{ username: "ada", given_name: "Ada" }] },
    });
    expect(stillWorks.status).toBe(200);

    const completed = await apiCall("/api/v1/setup", { token: BOOTSTRAP, body: { complete: true } });
    expect(completed.body.setup_completed).toBe(true);

    const afterwards = await apiCall("/api/v1/directory/import", {
      token: BOOTSTRAP,
      body: { version: 1, users: [] },
    });
    expect(afterwards.status).toBe(403);
  });

  it("enforces scopes", async () => {
    const { apiKey } = await bootstrapInstance();
    const readOnly = await apiCall("/api/v1/api-keys", {
      token: apiKey,
      body: { name: "read-only", scopes: ["directory:read"] },
    });
    expect(readOnly.status).toBe(200);

    const reads = await apiCall("/api/v1/users", { token: readOnly.body.token });
    expect(reads.status).toBe(200);

    const writes = await apiCall("/api/v1/directory/import", {
      token: readOnly.body.token,
      body: { version: 1, users: [] },
    });
    expect(writes.status).toBe(403);
    expect(writes.body.message).toMatch(/directory:write/);
  });

  it("rejects an unknown scope rather than silently granting nothing", async () => {
    const { status, body } = await apiCall("/api/v1/api-keys", {
      token: BOOTSTRAP,
      body: { name: "bad", scopes: ["directory:destroy"] },
    });
    expect(status).toBe(400);
    expect(body.message).toMatch(/Unknown scope/);
  });

  it("stops accepting a revoked key", async () => {
    const { apiKey } = await bootstrapInstance();
    const second = await apiCall("/api/v1/api-keys", { token: apiKey, body: { name: "doomed" } });

    const before = await apiCall("/api/v1/status", { token: second.body.token });
    expect(before.status).toBe(200);

    const { env } = await import("cloudflare:test");
    await env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), second.body.id)
      .run();

    const after = await apiCall("/api/v1/status", { token: second.body.token });
    expect(after.status).toBe(401);
  });
});

describe("setup", () => {
  it("creates the domain, the administrator and nothing else", async () => {
    const { status, body } = await apiCall("/api/v1/setup", {
      token: BOOTSTRAP,
      body: {
        domain: "horizon.test",
        admin: { username: "admin" },
        app_name: "Horizon ID",
        require_mfa: false,
        complete: true,
      },
    });

    expect(status).toBe(200);
    expect(body.setup_completed).toBe(true);
    expect(body.admin.upn).toBe("admin@horizon.test");
    // No default password is configured on a fresh instance, so one is
    // generated and handed back exactly once. This is the mechanism that
    // replaced shipping a known credential in a migration.
    expect(body.admin.password).toBeTypeOf("string");
    expect(body.admin.password.length).toBeGreaterThanOrEqual(12);

    const { env } = await import("cloudflare:test");
    const users = await env.DB.prepare("SELECT COUNT(*) as n FROM users").first<{ n: number }>();
    expect(users?.n).toBe(1);
  });

  it("uses the supplied administrator password when given one", async () => {
    const { body } = await apiCall("/api/v1/setup", {
      token: BOOTSTRAP,
      body: { domain: "horizon.test", admin: { username: "admin", password: "a-chosen-password" }, complete: true },
    });
    // Nothing is returned when the caller already knows it.
    expect(body.admin.password).toBeUndefined();
  });

  it("puts the administrator in Super Admins but not All Employees", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const { env } = await import("cloudflare:test");
    const { results } = await env.DB.prepare(
      "SELECT g.name FROM groups g JOIN group_members gm ON gm.group_id = g.id JOIN users u ON u.id = gm.user_id WHERE u.username = 'admin'"
    ).all<{ name: string }>();

    expect(results.map((r) => r.name)).toEqual(["Super Admins"]);
  });

  it("can be re-run with an API key without duplicating the administrator", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });

    const again = await apiCall("/api/v1/setup", {
      token: apiKey,
      body: { domain: "horizon.test", admin: { username: "admin" }, complete: true },
    });
    expect(again.status).toBe(200);

    const users = await apiCall("/api/v1/users", { token: apiKey });
    expect(users.body.total).toBe(1);
  });
});

describe("directory import", () => {
  const BUNDLE = {
    version: 1,
    groups: [
      { name: "Engineering", description: "Everyone in Engineering" },
      { name: "Executives", description: "The CEO and their direct reports" },
    ],
    users: [
      {
        username: "ada.kowalski",
        given_name: "Ada",
        family_name: "Kowalski",
        job_title: "Chief Executive Officer",
        department: "Executive",
        groups: ["All Employees", "Executives"],
      },
      {
        username: "nikita.chapman",
        given_name: "Nikita",
        family_name: "Chapman",
        job_title: "Staff Engineer",
        department: "Engineering",
        manager: "ada.kowalski",
        groups: ["All Employees", "Engineering"],
      },
    ],
  };

  it("creates users, groups, membership and manager links", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const { status, body } = await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });

    expect(status).toBe(200);
    expect(body.domain).toBe("horizon.test");
    expect(body.users).toEqual({ created: 2, updated: 0, skipped: 0 });
    expect(body.groups.created).toBe(2); // Engineering and Executives; All Employees already existed
    expect(body.managers_resolved).toBe(1);
    expect(body.errors).toEqual([]);

    const users = await apiCall("/api/v1/users", { token: apiKey });
    const nikita = users.body.users.find((u: any) => u.username === "nikita.chapman");
    expect(nikita.upn).toBe("nikita.chapman@horizon.test");
    expect(nikita.manager_upn).toBe("ada.kowalski@horizon.test");
    expect(nikita.groups.sort()).toEqual(["All Employees", "Engineering"]);
  });

  it("composes the UPN from the domain parameter, not from the bundle", async () => {
    // The whole point of the format: the same bundle lands on any zone.
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { ...BUNDLE, domain: "elsewhere.test" } });

    const users = await apiCall("/api/v1/users", { token: apiKey });
    const upns = users.body.users.map((u: any) => u.upn).sort();
    expect(upns).toContain("ada.kowalski@elsewhere.test");
    expect(upns).toContain("nikita.chapman@elsewhere.test");
  });

  it("is idempotent - a second identical import updates rather than duplicating", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });
    const second = await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });

    expect(second.body.users).toEqual({ created: 0, updated: 2, skipped: 0 });

    const users = await apiCall("/api/v1/users", { token: apiKey });
    expect(users.body.total).toBe(3); // the two people plus the administrator
  });

  it("does not reset an existing user's password on re-import", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });

    const { env } = await import("cloudflare:test");
    const before = await env.DB.prepare("SELECT password_hash FROM users WHERE username = 'ada.kowalski'").first<{
      password_hash: string;
    }>();

    await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });

    const after = await env.DB.prepare("SELECT password_hash FROM users WHERE username = 'ada.kowalski'").first<{
      password_hash: string;
    }>();
    expect(after?.password_hash).toBe(before?.password_hash);
  });

  it("returns generated passwords once, keyed by UPN", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    const { body } = await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });

    expect(Object.keys(body.generated_passwords).sort()).toEqual([
      "ada.kowalski@horizon.test",
      "nikita.chapman@horizon.test",
    ]);
  });

  it("uses the configured shared password when one is set", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/setup", {
      token: apiKey,
      body: { default_password: "SharedDemoPassword1!", new_user_password_mode: "default" },
    });

    const { body } = await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });
    // Nothing generated, because the shared password was used.
    expect(body.generated_passwords).toEqual({});
  });

  it("rejects a bundle larger than the batch cap", async () => {
    const { apiKey } = await bootstrapInstance();
    const users = Array.from({ length: MAX_USERS_PER_IMPORT + 1 }, (_, i) => ({ username: `user${i}` }));
    const { status, body } = await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users } });

    expect(status).toBe(400);
    expect(body.message).toMatch(/maximum is 100/);
  });

  it("accepts a bundle exactly at the cap", async () => {
    const { apiKey } = await bootstrapInstance();
    const users = Array.from({ length: MAX_USERS_PER_IMPORT }, (_, i) => ({ username: `user${i}`, given_name: `User ${i}` }));
    const { status, body } = await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users } });

    expect(status).toBe(200);
    expect(body.users.created).toBe(MAX_USERS_PER_IMPORT);
  });

  it("rejects malformed usernames before writing anything", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status, body } = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "ada@example.com" }] },
    });

    expect(status).toBe(400);
    expect(body.message).toMatch(/Invalid username/);

    const users = await apiCall("/api/v1/users", { token: apiKey });
    expect(users.body.total).toBe(1); // just the administrator
  });

  it("rejects a duplicate username within one bundle", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status, body } = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "ada" }, { username: "ada" }] },
    });

    expect(status).toBe(400);
    expect(body.message).toMatch(/Duplicate username/);
  });

  it("rejects an unsupported bundle version", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status, body } = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 2, users: [] },
    });

    expect(status).toBe(400);
    expect(body.message).toMatch(/version 1/);
  });

  it("replace mode clears the previous directory but keeps the administrators", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });

    const { status } = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, mode: "replace", users: [{ username: "solo", given_name: "Solo" }] },
    });
    expect(status).toBe(200);

    const users = await apiCall("/api/v1/users", { token: apiKey });
    expect(users.body.users.map((u: any) => u.username).sort()).toEqual(["admin", "solo"]);

    // Engineering and Executives are gone; the two built-ins remain.
    const groups = await apiCall("/api/v1/groups", { token: apiKey });
    expect(groups.body.groups.map((g: any) => g.name).sort()).toEqual(["All Employees", "Super Admins"]);
  });

  it("never exposes password material through the users endpoint", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/directory/import", { token: apiKey, body: BUNDLE });

    const users = await apiCall("/api/v1/users", { token: apiKey });
    const serialized = JSON.stringify(users.body);
    expect(serialized).not.toMatch(/password_hash/);
    expect(serialized).not.toMatch(/password_salt/);
    expect(serialized).not.toMatch(/totp_secret/);
  });

  it("reports an unknown manager without failing the user", async () => {
    const { apiKey } = await bootstrapInstance();
    const { body } = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "orphan", manager: "nobody" }] },
    });

    expect(body.users.created).toBe(1);
    expect(body.errors).toHaveLength(1);
    expect(body.errors[0].message).toMatch(/Unknown manager/);
  });

  it("resolves a manager who is not in the same chunk", async () => {
    // Chunked imports are the normal case for anything over a hundred people,
    // so a manager reference has to survive crossing a chunk boundary.
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/directory/import", { token: apiKey, body: { version: 1, users: [{ username: "boss" }] } });
    const { body } = await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "report", manager: "boss" }] },
    });

    expect(body.managers_resolved).toBe(1);
    expect(body.errors).toEqual([]);
  });
});

describe("OIDC client registration", () => {
  it("generates a credential when none is supplied", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status, body } = await apiCall("/api/v1/clients", {
      token: apiKey,
      body: { name: "Cloudflare Access", redirect_uris: ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"] },
    });

    expect(status).toBe(200);
    expect(body.client_id).toMatch(/^flareid_/);
    expect(body.client_secret).toBeTypeOf("string");
  });

  it("accepts a caller-supplied credential and does not echo the secret back", async () => {
    // This is what lets Terraform create the Access identity provider on its
    // first apply: it generates the pair, passes it in, and nothing has to flow
    // back from the machine that deployed FlareID.
    const { apiKey } = await bootstrapInstance();
    const { status, body } = await apiCall("/api/v1/clients", {
      token: apiKey,
      body: {
        name: "Cloudflare Access",
        redirect_uris: ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
        client_id: "flareid_deadbeefdeadbeef",
        client_secret: "a-secret-of-at-least-24-chars",
      },
    });

    expect(status).toBe(200);
    expect(body.client_id).toBe("flareid_deadbeefdeadbeef");
    expect(body.client_secret).toBeUndefined();
  });

  it("refuses a seeded secret that is too short, rather than quietly replacing it", async () => {
    // It used to generate its own instead, which left Access holding a
    // credential FlareID had never heard of and every login failing silently.
    const { apiKey } = await bootstrapInstance();
    const { status, body } = await apiCall("/api/v1/clients", {
      token: apiKey,
      body: { name: "X", redirect_uris: ["https://x.test/cb"], client_id: "flareid_x", client_secret: "too-short" },
    });

    expect(status).toBe(400);
    expect(body.message).toMatch(/at least 24/);
  });

  it("refuses an id without a secret", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status } = await apiCall("/api/v1/clients", {
      token: apiKey,
      body: { name: "X", redirect_uris: ["https://x.test/cb"], client_id: "flareid_x" },
    });
    expect(status).toBe(400);
  });

  it("requires at least one redirect URI", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status } = await apiCall("/api/v1/clients", { token: apiKey, body: { name: "X", redirect_uris: [] } });
    expect(status).toBe(400);
  });

  it("converges rather than colliding when the same client is registered twice", async () => {
    const { apiKey } = await bootstrapInstance();
    const payload = {
      name: "Cloudflare Access",
      redirect_uris: ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
      client_id: "flareid_deadbeefdeadbeef",
      client_secret: "a-secret-of-at-least-24-chars",
    };

    const first = await apiCall("/api/v1/clients", { token: apiKey, body: payload });
    const second = await apiCall("/api/v1/clients", { token: apiKey, body: payload });

    expect(first.body.created).toBe(true);
    expect(second.status).toBe(200);
    expect(second.body.created).toBe(false);

    const clients = await apiCall("/api/v1/clients", { token: apiKey });
    expect(clients.body.clients).toHaveLength(1);
  });

  it("never exposes client secrets through the list endpoint", async () => {
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/clients", { token: apiKey, body: { name: "X", redirect_uris: ["https://x.test/cb"] } });

    const clients = await apiCall("/api/v1/clients", { token: apiKey });
    expect(JSON.stringify(clients.body)).not.toMatch(/secret/i);
  });
});

describe("domains", () => {
  it("adds a domain and makes it the default on request", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "first.test" });
    await apiCall("/api/v1/domains", { token: apiKey, body: { domain: "second.test", set_default: true } });

    const { body } = await apiCall("/api/v1/domains", { token: apiKey });
    const second = body.domains.find((d: any) => d.domain === "second.test");
    expect(second.is_default).toBe(true);
  });

  it("404s when making an unknown domain the default", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status } = await apiCall("/api/v1/domains/nope.test/default", { token: apiKey, body: {} });
    expect(status).toBe(404);
  });

  it("rewrites every UPN when a domain is applied to all", async () => {
    const { apiKey } = await bootstrapInstance({ domain: "first.test" });
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "ada", given_name: "Ada" }] },
    });
    await apiCall("/api/v1/domains", { token: apiKey, body: { domain: "second.test" } });

    const { status, body } = await apiCall("/api/v1/domains/second.test/apply-to-all", { token: apiKey, body: {} });
    expect(status).toBe(200);
    expect(body.updated).toBe(2);

    const users = await apiCall("/api/v1/users", { token: apiKey });
    expect(users.body.users.every((u: any) => u.upn.endsWith("@second.test"))).toBe(true);
  });
});

describe("break-glass recovery", () => {
  it("is refused with an ordinary API key", async () => {
    const { apiKey } = await bootstrapInstance();
    const { status } = await apiCall("/api/v1/recovery/admin-reset", {
      token: apiKey,
      body: { username: "admin", password: "new-admin-password" },
    });
    expect(status).toBe(403);
  });

  it("still works with the bootstrap token after setup is complete", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    const { status, body } = await apiCall("/api/v1/recovery/admin-reset", {
      token: BOOTSTRAP,
      body: { username: "admin", password: "a-brand-new-password" },
    });

    expect(status).toBe(200);
    expect(body.upn).toBe("admin@horizon.test");
  });

  it("records the reset in the audit log", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    await apiCall("/api/v1/recovery/admin-reset", { token: BOOTSTRAP, body: { username: "admin" } });

    const { env } = await import("cloudflare:test");
    const row = await env.DB.prepare("SELECT * FROM audit_log WHERE action = 'idp.admin_recovery'").first<{
      actor_upn: string;
      actor_user_id: number | null;
    }>();

    expect(row?.actor_upn).toBe("bootstrap-token");
    // Not a person, so no user id - see the comment on audit_log in 0001_schema.
    expect(row?.actor_user_id).toBeNull();
  });
});

describe("audit trail", () => {
  it("attributes API actions to the key that made them", async () => {
    const { apiKey } = await bootstrapInstance();
    await apiCall("/api/v1/directory/import", {
      token: apiKey,
      body: { version: 1, users: [{ username: "ada", given_name: "Ada" }] },
    });

    const { env } = await import("cloudflare:test");
    const row = await env.DB.prepare("SELECT actor_upn FROM audit_log WHERE action = 'directory.imported'").first<{
      actor_upn: string;
    }>();

    expect(row?.actor_upn).toBe("api-key:test-suite");
  });
});
