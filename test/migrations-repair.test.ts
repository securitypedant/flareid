// Migration 0029 repairs two name-keyed bindings earlier migrations made
// silently: role groups bound by name only, and the Super-Admins MFA policy
// bound by the policy's mutable display name. The scenarios below recreate
// the broken states a pre-upgrade install could carry, replay the migration
// against them, and assert the repair.
import { beforeEach, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import { bootstrapInstance, resetDatabase } from "./helpers.js";
// @ts-expect-error vite ?raw import
import MIGRATION_0029 from "../migrations/0029_repairs.sql?raw";

beforeEach(resetDatabase);
// env.DB.exec takes one statement at a time and rejects comment-only chunks.
const replay = async () => {
  const sql = MIGRATION_0029.split("\n")
    .filter((l: string) => !l.trimStart().startsWith("--"))
    .join("\n");
  for (const stmt of sql.split(";").map((s: string) => s.trim()).filter(Boolean)) {
    await env.DB.prepare(stmt).run();
  }
};

const roleBound = (role: string) =>
  env.DB.prepare("SELECT 1 FROM admin_role_groups arg JOIN admin_roles r ON r.id = arg.role_id JOIN groups g ON g.id = arg.group_id WHERE r.name = ?").bind(role).first();

const superAdminMfaPolicy = () =>
  env.DB.prepare(
    `SELECT p.requirement FROM auth_policy_groups pg
       JOIN auth_policies p ON p.id = pg.policy_id
       JOIN groups g ON g.id = pg.group_id
      WHERE g.name = 'Super Admins' AND p.requirement = 'mfa'`
  ).first();

describe("repair: role groups bound by name", () => {
  it("unbinds an operator group that collided with a seeded name, and keeps the real one", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    // The collided state 0023 produced: the operator's own 'Directory Admins'
    // group (their description, not the seeded one) bound to Directory Admin.
    const gid = (await env.DB.prepare("SELECT id FROM groups WHERE name = 'Directory Admins'").first<{ id: number }>())!.id;
    await env.DB.prepare("UPDATE groups SET description = 'Mailing-list owners for the directory team' WHERE id = ?").bind(gid).run();
    expect(await roleBound("Directory Admin")).not.toBeNull();

    await replay();
    expect(await roleBound("Directory Admin")).toBeNull();

    // The untouched seeds stay bound.
    expect(await roleBound("Super Admin")).not.toBeNull();
    expect(await roleBound("Auditor")).not.toBeNull();
  });

  it("unbinds a colliding 'Super Admins' group too", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    await env.DB.prepare("UPDATE groups SET description = 'Ops-run super users, not the IdP role' WHERE name = 'Super Admins'").run();
    await replay();
    expect(await roleBound("Super Admin")).toBeNull();
  });
});

describe("repair: Super-Admins MFA policy bound by name", () => {
  it("rebinds when the shipped policy was renamed before the upgrade", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    // Pre-upgrade state: operator renamed the policy, 0022's name match
    // silently bound nothing.
    await env.DB.prepare("DELETE FROM auth_policy_groups WHERE group_id = (SELECT id FROM groups WHERE name = 'Super Admins')").run();
    await env.DB.prepare("UPDATE auth_policies SET name = 'Our two-step rule' WHERE requirement = 'mfa'").run();
    expect(await superAdminMfaPolicy()).toBeNull();

    await replay();
    const bound = await superAdminMfaPolicy();
    expect(bound).not.toBeNull();
    // The strongest existing mfa policy was chosen and put ahead of the rest.
    const p = await env.DB.prepare(
      `SELECT p.name, p.priority FROM auth_policy_groups pg JOIN auth_policies p ON p.id = pg.policy_id JOIN groups g ON g.id = pg.group_id WHERE g.name = 'Super Admins' AND p.requirement = 'mfa'`
    ).first<{ name: string; priority: number }>();
    expect(p!.name).toBe("Our two-step rule");
    expect(p!.priority).toBe(1);
  });

  it("creates the policy when none exists", async () => {
    await bootstrapInstance({ domain: "horizon.test" });
    await env.DB.prepare("DELETE FROM auth_policy_groups WHERE group_id = (SELECT id FROM groups WHERE name = 'Super Admins')").run();
    await env.DB.prepare("DELETE FROM auth_policies WHERE requirement = 'mfa'").run();

    await replay();
    const bound = await superAdminMfaPolicy();
    expect(bound).not.toBeNull();
    expect(await env.DB.prepare("SELECT 1 FROM auth_policies WHERE name = 'Password and a second factor'").first()).not.toBeNull();
  });

  it("leaves a deliberate, already-bound state alone", async () => {
    await bootstrapInstance({ domain: "horizon.test", secureDefaults: true });
    const before = await env.DB.prepare("SELECT COUNT(*) AS n FROM auth_policy_groups").first<{ n: number }>();
    await replay();
    const after = await env.DB.prepare("SELECT COUNT(*) AS n FROM auth_policy_groups").first<{ n: number }>();
    expect(after!.n).toBe(before!.n);
    expect(await superAdminMfaPolicy()).not.toBeNull();
  });
});
