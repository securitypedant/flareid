import { z } from "@hono/zod-openapi";
import { AnyObject, badRequest, defineRoute, readJson } from "./openapi.js";
import { exportDatabase, restoreDatabase } from "../lib/backup.js";
import { bootstrapTokenValid, auditActor } from "../lib/api-auth.js";
import { logAudit } from "../lib/audit.js";

/** Whole-database export/import for disaster recovery - see docs/dr.md. */

defineRoute(
  {
    method: "get",
    path: "/api/v1/backup",
    tag: "Backup",
    permission: "admin",
    summary: "Export the whole database",
    description:
      "A JSON bundle `{ version: 1, at, tables: { name: [rows] } }` covering every table except the migration ledger. It contains everything an attacker would want - password hashes, encrypted secrets, session state - so it needs an `admin` permission key and should be handled like the database itself. Restore with POST /api/v1/backup/restore (bootstrap token only).",
    response: AnyObject.openapi({ description: "The backup bundle." }),
  },
  async (c) => {
    const bundle = await exportDatabase(c.env);
    await logAudit(c.env, auditActor(c.get("apiActor")), "backup.exported", undefined, { tables: Object.keys(bundle.tables).length }, c.req.raw);
    return new Response(JSON.stringify(bundle), {
      headers: { "content-type": "application/json; charset=utf-8", "content-disposition": `attachment; filename="flareid-backup-${bundle.at.slice(0, 10)}.json"` },
    });
  }
);

defineRoute(
  {
    method: "post",
    path: "/api/v1/backup/restore",
    tag: "Backup",
    permission: null,
    summary: "Restore a backup bundle",
    description:
      "Bootstrap token only. Body is the bundle from GET /api/v1/backup plus `confirm: true`. **Wipes every table and rewrites it** - the bundle's tables and columns are validated against this schema before the first delete, so a bundle from a newer schema aborts cleanly. Apply the target's migrations first.",
    body: AnyObject,
    response: z.object({ ok: z.literal(true), restored: z.number(), tables: z.number() }),
    errors: [400],
  },
  async (c) => {
    const token = (c.req.header("authorization") ?? "").replace(/^Bearer\s+/i, "");
    if (!token || !(await bootstrapTokenValid(c.env, token))) {
      return c.json({ error: "unauthorized", message: "Restore needs the BOOTSTRAP_TOKEN secret." }, 401);
    }
    const body = await readJson<Record<string, unknown>>(c);
    if (body.confirm !== true) {
      return c.json(badRequest("Restore wipes every table. Send the bundle with `confirm: true` to proceed."), 400);
    }
    let result;
    try {
      result = await restoreDatabase(c.env, body);
    } catch (e) {
      return c.json(badRequest((e as Error).message), 400);
    }
    await logAudit(c.env, auditActor(c.get("apiActor")), "backup.restored", undefined, { ...result }, c.req.raw);
    return c.json({ ok: true as const, ...result });
  }
);
