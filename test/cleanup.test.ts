import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { purgeExpiredState } from "../src/lib/cleanup.js";
import { setAuditRetentionDays } from "../src/lib/settings.js";
import { resetDatabase } from "./helpers.js";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const iso = (ms: number) => new Date(ms).toISOString();

async function count(table: string): Promise<number> {
  return (await env.DB.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())!.n;
}

/** One live and one dead row of every kind of expiring state. */
async function seed(now: number) {
  await env.DB.prepare(
    "INSERT INTO users (upn, username, display_name, given_name, family_name, external_id, password_hash, password_salt, password_iterations, created_at, updated_at) VALUES ('a@x.test', 'a', 'A', 'A', '', 'ext-a', 'h', 's', 1, ?, ?)"
  ).bind(iso(now), iso(now)).run();
  const userId = (await env.DB.prepare("SELECT id FROM users WHERE username = 'a'").first<{ id: number }>())!.id;

  await env.DB.batch([
    env.DB.prepare("INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, expires_at) VALUES ('live', 'c', ?, 'r', 'openid', ?), ('dead', 'c', ?, 'r', 'openid', ?)").bind(userId, iso(now + 60_000), userId, iso(now - 60_000)),
    env.DB.prepare("INSERT INTO access_tokens (token_hash, client_id, user_id, scope, expires_at) VALUES ('live', 'c', ?, 'openid', ?), ('dead', 'c', ?, 'openid', ?)").bind(userId, iso(now + 60_000), userId, iso(now - 60_000)),
    env.DB.prepare(
      `INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, created_at, expires_at, family_id, rotated_at, revoked_at) VALUES
        ('live', 'c', ?, 'openid', ?, ?, 'f1', NULL, NULL),
        ('recently-rotated', 'c', ?, 'openid', ?, ?, 'f1', ?, NULL),
        ('expired', 'c', ?, 'openid', ?, ?, 'f2', NULL, NULL),
        ('long-revoked', 'c', ?, 'openid', ?, ?, 'f3', NULL, ?)`
    ).bind(
      userId, iso(now), iso(now + 10 * DAY),
      userId, iso(now - DAY), iso(now + 10 * DAY), iso(now - DAY),
      userId, iso(now - 40 * DAY), iso(now - DAY),
      userId, iso(now - 40 * DAY), iso(now + DAY), iso(now - 31 * DAY)
    ),
    env.DB.prepare(
      `INSERT INTO sessions (id, user_id, created_at, last_seen_at, revoked_at) VALUES
        ('live', ?, ?, ?, NULL), ('timed-out', ?, ?, ?, NULL), ('just-revoked', ?, ?, ?, ?), ('long-revoked', ?, ?, ?, ?)`
    ).bind(
      userId, iso(now - HOUR), iso(now),
      userId, iso(now - 13 * HOUR), iso(now - 13 * HOUR),
      userId, iso(now - 2 * HOUR), iso(now - HOUR), iso(now - HOUR),
      userId, iso(now - 3 * HOUR), iso(now - 3 * HOUR), iso(now - 2 * DAY)
    ),
    env.DB.prepare("INSERT INTO trusted_devices (id, user_id, created_at, last_used_at, expires_at) VALUES ('live', ?, ?, ?, ?), ('dead', ?, ?, ?, ?)").bind(
      userId, iso(now), iso(now), iso(now + DAY),
      userId, iso(now - 40 * DAY), iso(now - 40 * DAY), iso(now - DAY)
    ),
    env.DB.prepare("INSERT INTO audit_log (at, action) VALUES (?, 'recent'), (?, 'ancient')").bind(iso(now - DAY), iso(now - 400 * DAY)),
  ]);
}

describe("scheduled cleanup", () => {
  beforeEach(resetDatabase);

  it("deletes expired state and keeps everything still live or in its grace period", async () => {
    const now = Date.now();
    await seed(now);

    const removed = await purgeExpiredState(env, now);

    expect(removed).toEqual({ auth_codes: 1, access_tokens: 1, refresh_tokens: 2, sessions: 2, trusted_devices: 1, audit_log: 1 });
    expect(await count("auth_codes")).toBe(1);
    expect(await count("access_tokens")).toBe(1);
    // live + recently-rotated (kept so a replay is still recognised as reuse)
    expect((await env.DB.prepare("SELECT token_hash FROM refresh_tokens ORDER BY token_hash").all<{ token_hash: string }>()).results.map((r) => r.token_hash)).toEqual(["live", "recently-rotated"]);
    expect((await env.DB.prepare("SELECT id FROM sessions ORDER BY id").all<{ id: string }>()).results.map((r) => r.id)).toEqual(["just-revoked", "live"]);
    expect(await count("trusted_devices")).toBe(1);
    expect((await env.DB.prepare("SELECT action FROM audit_log").all<{ action: string }>()).results.map((r) => r.action)).toEqual(["recent"]);
  });

  it("honours the configured audit retention", async () => {
    const now = Date.now();
    await seed(now);
    await setAuditRetentionDays(env, 3650);

    await purgeExpiredState(env, now);
    expect(await count("audit_log")).toBe(2);
  });

  it("clamps audit retention to a sane range", async () => {
    expect(await setAuditRetentionDays(env, 1)).toBe(30);
    expect(await setAuditRetentionDays(env, 99999)).toBe(3650);
  });
});
