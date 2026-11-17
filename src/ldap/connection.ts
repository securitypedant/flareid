import type { Env } from "../env.js";
import type { LdapAppRow, UserRow } from "../lib/types.js";
import { logAuditRaw } from "../lib/audit.js";
import { sha256Hex } from "../lib/tokens.js";
import { BerError, BerReader, concat } from "./ber.js";
import { ldapBind, AD_BAD_CREDENTIALS, type BindCtx } from "./bind.js";
import { loadSnapshot, viewForApp, type DirectorySnapshot } from "./directory.js";
import {
  decodeMessage,
  message,
  bindResponse,
  searchDone,
  searchEntry,
  compareResponse,
  extendedResponse,
  ldapResult,
  noticeOfDisconnection,
  partialAttribute,
  pagedResponseControl,
  refusal,
  OP,
  OID,
  RC,
  type Control,
  type Operation,
} from "./protocol.js";
import { executeCompare, executeSearch, type SearchCtx } from "./search.js";
import { getLdapSettings, type LdapSettings } from "./settings.js";
import { escapeDnValue } from "./dn.js";

/**
 * The connection dispatcher (LDAP.md sections 6 and 10). Transport-agnostic:
 * reads framed BER messages off a ReadableStream and writes responses to a
 * WritableStream, so tests drive it with TransformStream pairs.
 */

type Bound = { kind: "anonymous" } | { kind: "service"; app: LdapAppRow } | { kind: "user"; user: UserRow; app: LdapAppRow | null };

export interface LdapConnDeps {
  env: Env;
  /** The remote address Spectrum/SocketInfo gave us, for rate limits and audit. */
  ip: string;
  /** ExecutionContext.waitUntil, when the caller has one - audit writes off the bind path. */
  waitUntil?: (p: Promise<unknown>) => void;
  log?: (event: string, fields: Record<string, unknown>) => void;
}

const MAX_OPS = 10_000;
const MAX_FRAME = 64 * 1024;

const te = new TextEncoder();
const td = new TextDecoder();

// The snapshot is shared across connections on this isolate; it expires after
// 30s so directory changes appear quickly without a per-op directory read.
let snapshotCache: { at: number; snap: DirectorySnapshot } | null = null;
const SNAPSHOT_TTL_MS = 30_000;
export async function cachedSnapshot(env: Env): Promise<DirectorySnapshot> {
  if (!snapshotCache || Date.now() - snapshotCache.at > SNAPSHOT_TTL_MS) snapshotCache = { at: Date.now(), snap: await loadSnapshot(env) };
  return snapshotCache.snap;
}
export function resetSnapshotCache(): void {
  snapshotCache = null;
}

/** Pulls whole BER frames off the byte stream, keeping leftovers between reads. */
class FrameReader {
  private buf: Uint8Array = new Uint8Array(0);
  constructor(private reader: ReadableStreamDefaultReader<Uint8Array>) {}

  async next(): Promise<Uint8Array | null> {
    for (;;) {
      const frame = this.tryFrame();
      if (frame) return frame;
      const { done, value } = await this.reader.read();
      if (done) return null; // EOF - a truncated trailing frame is just a close
      this.buf = concat(this.buf, value);
      if (this.buf.length > MAX_FRAME) throw new BerError("message exceeds 64KB");
    }
  }

  private tryFrame(): Uint8Array | null {
    const b = this.buf;
    if (b.length < 2 || b[0] !== 0x30) {
      if (b.length && b[0] !== 0x30) throw new BerError("expected LDAPMessage SEQUENCE");
      return null;
    }
    const first = b[1]!;
    let headerLen: number, len: number;
    if (first < 0x80) {
      headerLen = 2;
      len = first;
    } else {
      const n = first & 0x7f;
      if (n === 0 || n > 4) throw new BerError("indefinite or oversized length");
      if (b.length < 2 + n) return null;
      len = 0;
      for (let k = 0; k < n; k++) len = len * 256 + b[2 + k]!;
      headerLen = 2 + n;
    }
    if (len > MAX_FRAME) throw new BerError("message exceeds 64KB");
    if (b.length < headerLen + len) return null;
    const frame = b.subarray(0, headerLen + len);
    this.buf = b.subarray(headerLen + len);
    return frame;
  }
}

export async function handleLdapConnection(readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>, deps: LdapConnDeps): Promise<void> {
  const { env, ip } = deps;
  const writer = writable.getWriter();
  const reader = new FrameReader(readable.getReader());
  const log = (event: string, fields: Record<string, unknown> = {}) => deps.log?.(event, { ip, ...fields });
  const send = (bytes: Uint8Array) => writer.write(bytes);

  const settings: LdapSettings | null = await getLdapSettings(env).catch(() => null);
  if (!settings || !settings.enabled || settings.base.length === 0) {
    await send(noticeOfDisconnection(RC.unavailable, "LDAP is not enabled"));
    writer.releaseLock();
    return;
  }

  const idleMs = Math.max(1, settings.idleTimeoutMinutes) * 60_000;
  // Unbound connections are implicitly anonymous: they may read the root DSE
  // and subschema, which is how clients discover us.
  let bound: Bound = { kind: "anonymous" };
  let app: LdapAppRow | null = null; // sticky app attribution across binds
  let ops = 0;
  const opCounts: Record<string, number> = {};
  const resultCodes: Record<string, number> = {};
  let lastActivity = Date.now();
  const startedAt = Date.now();
  const track = (kind: string, code?: number) => {
    opCounts[kind] = (opCounts[kind] ?? 0) + 1;
    if (code !== undefined) resultCodes[`${kind}:${code}`] = (resultCodes[`${kind}:${code}`] ?? 0) + 1;
  };
  // Audit + last_used go through waitUntil when the runtime offers it, so they
  // don't add latency to the bind path. user_agent = ldap:<app slug>.
  const audit = (actor: Parameters<typeof logAuditRaw>[1], action: string, target: string | undefined, details: Record<string, unknown> | undefined, slug: string | null) => {
    const p = logAuditRaw(env, actor, action, target, details, { ip, userAgent: `ldap:${slug ?? "unbound"}` });
    if (deps.waitUntil) deps.waitUntil(p);
    else return p;
  };

  log("ldap.session.open", {});
  try {
    while (ops < MAX_OPS) {
      const idleLeft = idleMs - (Date.now() - lastActivity);
      if (idleLeft <= 0) {
        await send(noticeOfDisconnection(RC.unavailable, "idle timeout"));
        break;
      }
      let frame: Uint8Array | "idle" | null;
      try {
        frame = await Promise.race([reader.next(), sleep(idleLeft).then(() => "idle" as const)]);
      } catch {
        await send(noticeOfDisconnection(RC.protocolError, "framing error"));
        break;
      }
      if (frame === "idle") {
        await send(noticeOfDisconnection(RC.unavailable, "idle timeout"));
        break;
      }
      if (frame === null) break;
      lastActivity = Date.now();
      ops++;

      let msg;
      try {
        msg = decodeMessage(frame);
      } catch (e) {
        await send(noticeOfDisconnection(RC.protocolError, e instanceof BerError ? e.message : "malformed message"));
        break;
      }

      const op = msg.op;
      if (op.kind === "unbind") break;
      if (op.kind === "abandon") continue;

      if (op.kind === "bind") {
        if (op.version !== 3) {
          await send(message(msg.id, bindResponse(RC.protocolError, "LDAPv3 only")));
          continue;
        }
        if (op.simple === null) {
          await send(message(msg.id, bindResponse(RC.authMethodNotSupported, "simple binds only")));
          continue;
        }
        const out = await ldapBind({ env, settings, app, ip, kv: env.SESSIONS_KV ?? null }, op.name, op.simple);
        if (out.ok) {
          bound = out.bound;
          app = out.app;
          if (bound.kind === "service") {
            void audit({ id: null, upn: `svc:${bound.app.slug}` }, "ldap.bind.success", bound.app.slug, { name: op.name }, bound.app.slug);
          } else if (bound.kind === "user") {
            void audit(bound.user, "ldap.bind.success", bound.app?.slug ?? undefined, { name: op.name }, bound.app?.slug ?? null);
          }
          if (app) {
            const stamp = env.DB.prepare("UPDATE ldap_apps SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)").bind(new Date().toISOString(), app.id, new Date(Date.now() - 60_000).toISOString()).run();
            if (deps.waitUntil) deps.waitUntil(stamp);
          }
          await send(message(msg.id, bindResponse(RC.success, "")));
          track("bind", RC.success);
        } else {
          const isService = op.name.includes(",ou=services,");
          const action = out.reason === "rate_limited" || out.reason === "svc_rate_limited" ? "ldap.bind.rate_limited" : isService ? "ldap.service_bind.failed" : "ldap.bind.failed";
          void audit({ id: null, upn: op.name.slice(0, 128) }, action, app?.slug ?? undefined, { reason: out.reason }, app?.slug ?? null);
          await send(message(msg.id, bindResponse(RC.invalidCredentials, AD_BAD_CREDENTIALS)));
          track("bind", RC.invalidCredentials);
        }
        continue;
      }

      if (op.kind === "search") {
        await handleSearch(writer, deps, settings, bound, app, msg.id, op, msg.controls, track);
        continue;
      }
      if (op.kind === "compare") {
        const ctx = await searchCtx(env, settings, bound, app);
        if (!ctx) {
          await send(message(msg.id, compareResponse(RC.insufficientAccessRights, "compare failed")));
          continue;
        }
        const res = await executeCompare(ctx, op);
        await send(message(msg.id, compareResponse(res.code, "", res.matchedDn)));
        track("compare", res.code);
        continue;
      }
      if (op.kind === "extended") {
        if (op.name === OID.whoami) {
          const authz =
            bound.kind === "anonymous"
              ? ""
              : bound.kind === "service"
                ? `dn:cn=${escapeDnValue(bound.app.slug)},ou=services,${settings.baseDn}`
                : `dn:uid=${escapeDnValue(bound.user.username)},ou=people,${bound.app ? `ou=${escapeDnValue(bound.app.slug)},` : ""}${settings.baseDn}`;
          await send(message(msg.id, extendedResponse(RC.success, "", OID.whoami, te.encode(authz))));
          continue;
        }
        if (op.name === OID.startTls) {
          // We only ever see traffic Spectrum already TLS-terminated; a bare
          // StartTLS request means the app landed on a plaintext port - refuse
          // rather than negotiate crypto mid-stream.
          await send(message(msg.id, extendedResponse(RC.operationsError, "TLS is terminated at the edge; connect on 636", OID.startTls)));
          break;
        }
        await send(message(msg.id, extendedResponse(RC.unwillingToPerform, `unsupported extended op ${op.name}`)));
        continue;
      }
      if (op.kind === "write") {
        const tag = op.op === "modify" ? OP.modifyResponse : op.op === "add" ? OP.addResponse : op.op === "del" ? OP.delResponse : OP.modifyDnResponse;
        await send(refusal(msg.id, tag, RC.unwillingToPerform, "read-only directory"));
        continue;
      }
      await send(noticeOfDisconnection(RC.protocolError, "unsupported operation"));
      break;
    }
    if (ops >= MAX_OPS) await send(noticeOfDisconnection(RC.unavailable, "operation limit"));
  } catch (e) {
    log("ldap.session.error", { error: e instanceof Error ? e.message : String(e) });
  }
  // One structured line per connection (LDAP.md section 15): searches are not
  // audited - SSSD alone would flood the table - so this is where they live.
  log("ldap.session.close", { ops, opCounts, resultCodes, ms: Date.now() - startedAt });
  writer.releaseLock();
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function searchCtx(env: Env, settings: LdapSettings, bound: Bound, stickyApp: LdapAppRow | null): Promise<SearchCtx | null> {
  const app = bound.kind === "service" ? bound.app : bound.kind === "user" ? (bound.app ?? stickyApp) : stickyApp;
  if (!app && bound.kind !== "anonymous") return null;
  const snap = await cachedSnapshot(env);
  return { env, settings, app: app as LdapAppRow, view: app ? viewForApp(snap, app) : { users: [], groups: [], groupMembers: new Map(), userGroups: new Map(), userById: new Map() }, bound };
}

/** Parse the Simple Paged Results request control: SEQUENCE { size INTEGER, cookie OCTET STRING }. */
function pagedRequest(controls: Control[]): { size: number; cookie: Uint8Array | null } | null {
  const c = controls.find((x) => x.type === OID.pagedResults);
  if (!c?.value) return null;
  try {
    const r = new BerReader(c.value).readConstructed(0x30);
    const size = r.readInteger();
    const cookie = r.readOctetString();
    return { size, cookie: cookie.length ? cookie : null };
  } catch {
    return null;
  }
}

async function handleSearch(writer: WritableStreamDefaultWriter<Uint8Array>, deps: LdapConnDeps, settings: LdapSettings, bound: Bound, stickyApp: LdapAppRow | null, msgId: number, op: Extract<Operation, { kind: "search" }>, controls: Control[], track: (kind: string, code?: number) => void): Promise<void> {
  const send = (bytes: Uint8Array) => writer.write(bytes);
  const ctx = await searchCtx(deps.env, settings, bound, stickyApp);
  if (!ctx) {
    await send(message(msgId, searchDone(RC.insufficientAccessRights, "no app context")));
    return;
  }
  const out = await executeSearch(ctx, op);
  const paged = pagedRequest(controls);

  let entries = out.entries;
  let cookie: Uint8Array | null = null;
  if (paged && out.code === RC.success) {
    const contextHash = (await sha256Hex(`${ctx.app?.id}|${op.base}|${op.scope}|${Array.from(op.filterRaw).join(",")}|${op.attributes.join(",")}`)).slice(0, 16);
    let offset = 0;
    if (paged.cookie) {
      try {
        const parsed = JSON.parse(td.decode(paged.cookie)) as { o: number; h: string };
        if (parsed.h !== contextHash) {
          await send(message(msgId, searchDone(RC.unwillingToPerform, "paging cookie does not match this search")));
          return;
        }
        offset = parsed.o;
      } catch {
        await send(message(msgId, searchDone(RC.unwillingToPerform, "bad paging cookie")));
        return;
      }
    }
    entries = out.entries.slice(offset, offset + paged.size);
    cookie = offset + paged.size < out.entries.length ? te.encode(JSON.stringify({ o: offset + paged.size, h: contextHash })) : new Uint8Array(0);
  }

  for (const e of entries) {
    const attrs = [...e.attrs.entries()].map(([name, values]) => partialAttribute(name, out.typesOnly ? [] : values));
    await send(message(msgId, searchEntry(e.dn, attrs)));
  }
  const controlsOut = paged && cookie ? [pagedResponseControl(cookie)] : [];
  await send(message(msgId, searchDone(out.code, out.diagnostic, out.matchedDn), controlsOut));
  track("search", out.code);
}
