import type { Env } from "../env.js";

/**
 * Whole-database backup and restore for disaster recovery.
 *
 * The export is a JSON bundle `{ version, at, tables: { name: [rows] } }`
 * covering every table except `d1_migrations` (the ledger is rebuilt by
 * `wrangler d1 migrations apply` on the target). Byte columns store base64
 * text throughout the schema (user_photos, brand_assets, signing keys), so
 * rows round-trip through JSON losslessly.
 *
 * The bundle contains everything an attacker would want - password hashes,
 * encrypted SCIM/API secrets, session state - so export needs an `admin`
 * permission key and restore needs the bootstrap token.
 */

export interface BackupBundle {
  version: number;
  at: string;
  tables: Record<string, Record<string, unknown>[]>;
}

async function tableNames(env: Env): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name != 'd1_migrations' ORDER BY name"
  ).all<{ name: string }>();
  return results.map((t) => t.name);
}

export async function exportDatabase(env: Env): Promise<BackupBundle> {
  const tables: Record<string, Record<string, unknown>[]> = {};
  for (const name of await tableNames(env)) {
    const { results } = await env.DB.prepare(`SELECT * FROM "${name}"`).all();
    tables[name] = results as Record<string, unknown>[];
  }
  return { version: 1, at: new Date().toISOString(), tables };
}

export interface RestoreResult {
  restored: number; // rows written
  tables: number;
}

function isFkError(e: unknown): boolean {
  return /FOREIGN KEY/i.test(String((e as Error)?.message ?? e));
}

/**
 * Tables ordered parents-before-children by their own foreign keys (Kahn's
 * on the dependency graph). Self-references and any residual cycle go to the
 * end in declaration order - the caller's retry pass handles them.
 */
async function dependencyOrder(env: Env, names: string[]): Promise<string[]> {
  const deps = new Map<string, Set<string>>();
  for (const name of names) {
    const { results } = await env.DB.prepare(`PRAGMA foreign_key_list("${name}")`).all<{ table: string }>();
    deps.set(name, new Set(results.map((r) => r.table).filter((t) => t !== name && names.includes(t))));
  }
  const ordered: string[] = [];
  const pending = new Set(names);
  for (;;) {
    const ready = [...pending].filter((n) => [...deps.get(n)!].every((d) => !pending.has(d)));
    if (!ready.length) {
      // Cycle (or nothing left): take what remains as-is.
      ordered.push(...pending);
      break;
    }
    for (const n of ready) {
      ordered.push(n);
      pending.delete(n);
    }
    if (!pending.size) break;
  }
  return ordered;
}

/**
 * Wipes every table and rewrites it from the bundle. Validated fully before
 * the first DELETE: an unknown table or column aborts with the database
 * untouched.
 */
export async function restoreDatabase(env: Env, bundle: unknown): Promise<RestoreResult> {
  const b = bundle as Partial<BackupBundle>;
  if (!b || b.version !== 1 || !b.tables || typeof b.tables !== "object") {
    throw new Error("Not a FlareID backup bundle (expected { version: 1, tables: {...} }).");
  }
  const existing = new Set(await tableNames(env));
  // Validate up front: every bundled table must exist here, and every column
  // named in its rows must exist too - a bundle from a newer schema is
  // refused rather than partially applied.
  const colChecks: { name: string; cols: Set<string> }[] = [];
  for (const [name, rows] of Object.entries(b.tables)) {
    if (!existing.has(name)) throw new Error(`Backup contains table "${name}", which does not exist in this schema - apply migrations first.`);
    const { results: cols } = await env.DB.prepare(`PRAGMA table_info("${name}")`).all<{ name: string }>();
    const colSet = new Set(cols.map((c) => c.name));
    for (const row of rows) {
      for (const col of Object.keys(row)) {
        if (!colSet.has(col)) throw new Error(`Backup names column "${name}.${col}", which does not exist in this schema.`);
      }
    }
    colChecks.push({ name, cols: colSet });
  }
  const names = [...existing];
  // D1 runs every statement in its own session, so session pragmas like
  // foreign_keys=OFF cannot help: order is the only lever. Insert parents
  // before the rows that reference them, delete children before their
  // parents - the dependency order comes from the schema's own FKs.
  const order = await dependencyOrder(env, names);
  // Clear everything (bundle tables or not), children first, so no stale row
  // survives a restore onto a busier database.
  for (const name of [...order].reverse()) await env.DB.prepare(`DELETE FROM "${name}"`).run();

  let restored = 0;
  const BATCH = 100;
  const deferred: { name: string; row: Record<string, unknown> }[] = [];
  const insertRow = (name: string, row: Record<string, unknown>) => {
    const cols = Object.keys(row);
    return env.DB.prepare(`INSERT INTO "${name}" (${cols.map((col) => `"${col}"`).join(",")}) VALUES (${cols.map(() => "?").join(",")})`).bind(...cols.map((col) => row[col] as never));
  };
  for (const name of order) {
    const rows = b.tables[name] ?? [];
    for (let i = 0; i < rows.length; i += BATCH) {
      const chunk = rows.slice(i, i + BATCH);
      try {
        if (chunk.length) await env.DB.batch(chunk.map((row) => insertRow(name, row)));
        restored += chunk.length;
      } catch (e) {
        if (!isFkError(e)) throw e;
        // A row ahead of its parent (self-referencing table, or a schema
        // cycle the topo couldn't see): write what fits, retry the rest
        // after the sweep.
        for (const row of chunk) {
          try {
            await insertRow(name, row).run();
            restored++;
          } catch (e2) {
            if (!isFkError(e2)) throw e2;
            deferred.push({ name, row });
          }
        }
      }
    }
  }
  // Second pass: every parent is in place now, so deferred rows land.
  for (const { name, row } of deferred) {
    try {
      await insertRow(name, row).run();
      restored++;
    } catch (e) {
      throw new Error(`Restore could not satisfy a foreign key in "${name}" (${(e as Error).message}). The bundle may be inconsistent.`);
    }
  }
  return { restored, tables: colChecks.length };
}

/** Daily snapshot to an optional R2 binding (wrangler.jsonc "r2_buckets"). */
export async function snapshotToR2(env: Env): Promise<{ written: string | null }> {
  if (!env.BACKUPS) return { written: null };
  const key = `backups/${new Date().toISOString().slice(0, 10)}.json`;
  if (await env.BACKUPS.head(key)) return { written: null };
  const bundle = await exportDatabase(env);
  await env.BACKUPS.put(key, JSON.stringify(bundle));
  return { written: key };
}
