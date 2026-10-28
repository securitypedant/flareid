import { applyD1Migrations, env, SELF } from "cloudflare:test";

export const BASE = "https://idp.test";
export const BOOTSTRAP = "test-bootstrap-token";

/**
 * Returns the database to a freshly migrated state.
 *
 * Every table is dropped and the migrations are re-applied, rather than a
 * hand-written list of DELETEs - the table list comes from sqlite_master, so
 * adding a table to the schema does not quietly leave rows behind in it between
 * tests. Dropping d1_migrations is what lets the migrations run again.
 *
 * Call it in beforeEach. Tests then depend on their own setup rather than on
 * the test runner's storage isolation, which has changed shape twice across
 * versions of the Workers Vitest integration.
 */
export async function resetDatabase(): Promise<void> {
  const { results } = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'"
  ).all<{ name: string }>();

  // Reversed, because sqlite_master lists tables in creation order and foreign
  // keys point backwards along it - group_members references users, which is
  // created first. Dropping forwards removes a parent while a child still
  // references it and fails with "no such table: main.users", which is a
  // confusing way to be told about a foreign key.
  for (const table of [...results].reverse()) {
    await env.DB.prepare(`DROP TABLE IF EXISTS "${table.name}"`).run();
  }

  await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
}

export async function apiCall(
  path: string,
  opts: { token?: string; method?: string; body?: unknown } = {}
): Promise<{ status: number; body: any }> {
  const response = await SELF.fetch(`${BASE}${path}`, {
    method: opts.method ?? (opts.body !== undefined ? "POST" : "GET"),
    headers: {
      ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  });

  const text = await response.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: response.status, body };
}

/**
 * Brings a fresh instance to a configured state, the way a deploy script does:
 * a domain, an administrator, and setup marked complete.
 *
 * Returns an admin-scoped API key, because the bootstrap token stops working
 * the moment setup completes - which is the behaviour under test elsewhere, and
 * a trap to fall into here otherwise.
 */
export async function bootstrapInstance(
  opts: { domain?: string; adminPassword?: string; complete?: boolean } = {}
): Promise<{ apiKey: string; domain: string }> {
  const domain = opts.domain ?? "example.com";

  const key = await apiCall("/api/v1/api-keys", {
    token: BOOTSTRAP,
    body: { name: "test-suite", scopes: ["admin"] },
  });
  if (key.status !== 200) throw new Error(`could not mint an API key: ${JSON.stringify(key.body)}`);

  const setup = await apiCall("/api/v1/setup", {
    token: BOOTSTRAP,
    body: {
      domain,
      admin: { username: "admin", password: opts.adminPassword ?? "test-admin-password-1" },
      complete: opts.complete ?? true,
    },
  });
  if (setup.status !== 200) throw new Error(`setup failed: ${JSON.stringify(setup.body)}`);

  return { apiKey: key.body.token as string, domain };
}
