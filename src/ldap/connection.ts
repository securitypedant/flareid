import type { Env } from "../env.js";
import type { LdapAppRow, UserRow } from "../lib/types.js";
import { logAuditRaw } from "../lib/audit.js";
import { sha256Hex, randomToken } from "../lib/tokens.js";
import { hashPassword, verifyPassword } from "../lib/password.js";
import { newPasswordError } from "../lib/breached-passwords.js";
import { clearLoginAttempts, loginRateKey, recordLoginAttempt } from "../lib/rate-limit.js";
import { revokeTokensForUser } from "../lib/sessions.js";
import { BerError, BerReader, concat, seq, ctx, tlv } from "./ber.js";
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
  sortResultControl,
  refusal,
  OP,
  OID,
  RC,
  type Control,
  type Operation,
} from "./protocol.js";
import { executeCompare, executeSearch, type SearchCtx } from "./search.js";
import { getLdapSettings, type LdapSettings } from "./settings.js";
import { dnEquals, escapeDnValue, parseDn } from "./dn.js";
import { USER_RDN } from "./entries.js";

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
        if (op.name === OID.passwordModify) {
          await handlePasswordModify({ send, deps, settings, bound, app, msgId: msg.id, value: op.value, track, audit });
          continue;
        }
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

interface SortKey {
  attr: string;
  reverse: boolean;
}

/** Parse the server-side sort request control (RFC 2891): SEQUENCE OF SEQUENCE { attr, [0] rule, [1] reverse }. */
function sortRequest(controls: Control[]): SortKey[] | null | "bad" {
  const c = controls.find((x) => x.type === OID.serverSort);
  if (!c) return null;
  if (!c.value) return "bad";
  try {
    const outer = new BerReader(c.value).readConstructed(0x30);
    const keys: SortKey[] = [];
    while (!outer.atEnd()) {
      const k = outer.readConstructed(0x30);
      const attr = k.readString().toLowerCase();
      let reverse = false;
      while (!k.atEnd()) {
        const f = k.readElement();
        if (f.tag === 0x81) reverse = f.content[0] !== 0; // [1] IMPLICIT BOOLEAN
        // [0] orderingRule: accepted and ignored - we have one ordering per syntax.
      }
      keys.push({ attr, reverse });
    }
    return keys.length ? keys : "bad";
  } catch {
    return "bad";
  }
}

const hexOf = (v: string | Uint8Array) => (typeof v === "string" ? v : Array.from(v, (b) => b.toString(16).padStart(2, "0")).join(""));

/** First-value comparison per key; absent attributes sort last (RFC 2891). */
function entryComparator(keys: SortKey[]) {
  return (a: { attrs: Map<string, (string | Uint8Array)[]> }, b: { attrs: Map<string, (string | Uint8Array)[]> }): number => {
    for (const { attr, reverse } of keys) {
      const va = a.attrs.get(attr)?.[0];
      const vb = b.attrs.get(attr)?.[0];
      let cmp: number;
      if (va === undefined && vb === undefined) continue;
      else if (va === undefined) cmp = 1;
      else if (vb === undefined) cmp = -1;
      else {
        const sa = hexOf(va);
        const sb = hexOf(vb);
        const na = /^\d+$/.test(sa) ? Number(sa) : null;
        const nb = /^\d+$/.test(sb) ? Number(sb) : null;
        cmp = na !== null && nb !== null ? na - nb : sa.toLowerCase() < sb.toLowerCase() ? -1 : sa.toLowerCase() > sb.toLowerCase() ? 1 : 0;
      }
      if (cmp !== 0) return reverse ? -cmp : cmp;
    }
    return 0;
  };
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
  const sort = sortRequest(controls);
  if (sort === "bad") {
    await send(message(msgId, searchDone(RC.unwillingToPerform, "malformed server-side sort control"), [sortResultControl(RC.unwillingToPerform)]));
    track("search", RC.unwillingToPerform);
    return;
  }
  if (sort && out.code === RC.success) out.entries.sort(entryComparator(sort));

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
  const controlsOut = [...(paged && cookie ? [pagedResponseControl(cookie)] : []), ...(sort ? [sortResultControl(RC.success)] : [])];
  await send(message(msgId, searchDone(out.code, out.diagnostic, out.matchedDn), controlsOut));
  track("search", out.code);
}

/**
 * RFC 3062 Password Modify (LDAP.md section 13, phase 3 pull-forward). Only a
 * user-bound connection may change a password, and only its own - there is no
 * admin reset over LDAP. The old password is always required; a missing new
 * password generates one and returns it as genPasswd. On success we run the
 * same compromise response as the account-page change: revoke sessions,
 * revoke tokens, drop passkeys.
 */
async function handlePasswordModify(args: {
  send: (bytes: Uint8Array) => Promise<void>;
  deps: LdapConnDeps;
  settings: LdapSettings;
  bound: Bound;
  app: LdapAppRow | null;
  msgId: number;
  value: Uint8Array | null;
  track: (kind: string, code?: number) => void;
  audit: (actor: Parameters<typeof logAuditRaw>[1], action: string, target: string | undefined, details: Record<string, unknown> | undefined, slug: string | null) => void;
}): Promise<void> {
  const { send, deps, settings, bound, app, msgId, value, track, audit } = args;
  const fail = async (code: number, diagnostic: string, reason?: string) => {
    if (reason) void audit({ id: null, upn: bound.kind === "user" ? bound.user.upn : "ldap:unbound" }, "ldap.password_modify.failed", app?.slug ?? undefined, { reason }, app?.slug ?? null);
    await send(message(msgId, extendedResponse(code, diagnostic, OID.passwordModify)));
    track("passwdmodify", code);
  };

  if (bound.kind !== "user") return fail(RC.insufficientAccessRights, "password modify requires a user bind");
  const user = bound.user;
  const userApp = app ?? bound.app;
  if (!userApp) return fail(RC.insufficientAccessRights, "no app context");

  // requestValue ::= SEQUENCE { userIdentity [0], oldPasswd [1], newPasswd [2] } (all optional, IMPLICIT OCTET STRING)
  let userIdentity: string | null = null;
  let oldPw: string | null = null;
  let newPw: string | null = null;
  try {
    const r = new BerReader(value ?? new Uint8Array(0)).readConstructed(0x30);
    while (!r.atEnd()) {
      const f = r.readElement();
      if (f.tag === 0x80) userIdentity = td.decode(f.content);
      else if (f.tag === 0x81) oldPw = td.decode(f.content);
      else if (f.tag === 0x82) newPw = td.decode(f.content);
    }
  } catch {
    return fail(RC.protocolError, "malformed password modify request");
  }

  // userIdentity, when present, must name the bound user: their entry DN,
  // username, or UPN. Anything else is an attempt at someone else's account.
  if (userIdentity) {
    const canonical = USER_RDN(user.username, userApp.slug, settings.baseDn);
    let ok = userIdentity.toLowerCase() === user.username.toLowerCase() || userIdentity.toLowerCase() === (user.upn ?? "").toLowerCase();
    if (!ok && userIdentity.includes("=")) {
      try {
        ok = dnEquals(parseDn(userIdentity), parseDn(canonical));
      } catch {
        ok = false;
      }
    }
    if (!ok) return fail(RC.insufficientAccessRights, "cannot modify another user's password", "identity_mismatch");
  }

  if (oldPw === null) return fail(RC.unwillingToPerform, "old password required", "old_password_missing");

  // Share the web sign-in lockout budget: guessing old passwords over LDAP
  // must not get a second allowance.
  if (await recordLoginAttempt(deps.env, loginRateKey(user.username, user), deps.ip)) return fail(RC.unwillingToPerform, "too many attempts", "rate_limited");
  const oldOk = await verifyPassword(oldPw, { password_hash: user.password_hash, password_salt: user.password_salt, password_iterations: user.password_iterations });
  if (!oldOk) return fail(RC.invalidCredentials, AD_BAD_CREDENTIALS, "old_password");

  let generated: string | null = null;
  if (newPw === null) {
    generated = randomToken(18);
    newPw = generated;
  } else {
    const policyError = await newPasswordError(deps.env, newPw);
    if (policyError) return fail(RC.unwillingToPerform, policyError, "policy");
  }

  const { hash, salt, iterations } = await hashPassword(newPw, deps.env);
  const now = new Date().toISOString();
  await deps.env.DB.batch([
    deps.env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?").bind(hash, salt, iterations, now, user.id),
    deps.env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").bind(now, user.id),
    deps.env.DB.prepare("DELETE FROM webauthn_credentials WHERE user_id = ?").bind(user.id),
  ]);
  await revokeTokensForUser(deps.env, user.id);
  await clearLoginAttempts(deps.env, loginRateKey(user.username, user), deps.ip);
  void audit(user, "ldap.password_modify", userApp.slug, { generated: generated !== null }, userApp.slug);

  const responseValue = generated !== null ? seq(tlv(ctx(0), te.encode(generated))) : undefined;
  await send(message(msgId, extendedResponse(RC.success, "", undefined, responseValue)));
  track("passwdmodify", RC.success);
}
