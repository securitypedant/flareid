import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { apiCall, bootstrapInstance, resetDatabase } from "./helpers.js";
import { totp } from "./helpers-totp.js";
import { handleLdapConnection, resetSnapshotCache } from "../src/ldap/connection.js";
import { enableLdap, disableLdap } from "../src/ldap/settings.js";
import { writeLdapApp } from "../src/ldap/apps.js";
import { BerReader, appC, booleanValue, concat, enumValue, integer, octetString, seq, tlv } from "../src/ldap/ber.js";
import { appC as appTag, ctx, ctxC } from "../src/ldap/ber.js";

/**
 * End-to-end LDAP tests: real BER messages through handleLdapConnection over
 * TransformStream pairs, against a migrated D1 (LDAP.md section 17).
 */

const BASE_DN = "dc=example,dc=com";
const PAGED = "1.2.840.113556.1.4.319";
const WHOAMI = "1.3.6.1.4.1.4203.1.11.3";

// ---- client side: encode requests, decode responses ----

const ldapMessage = (id: number, op: Uint8Array, controls: Uint8Array[] = []) =>
  seq(integer(id), op, ...(controls.length ? [tlv(0xa0, concat(...controls))] : []));
const control = (oid: string, value?: Uint8Array) => seq(octetString(oid), ...(value ? [octetString(value)] : []));

const bindReq = (id: number, name: string, pw: string) => ldapMessage(id, tlv(appC(0), concat(integer(3), octetString(name), tlv(ctx(0), new TextEncoder().encode(pw)))));
const unbindReq = (id: number) => ldapMessage(id, tlv(appC(2), new Uint8Array(0)));
const whoamiReq = (id: number) => ldapMessage(id, tlv(appC(23), tlv(ctx(0), new TextEncoder().encode(WHOAMI))));

const eqFilter = (attr: string, value: string) => tlv(ctxC(3), concat(octetString(attr), octetString(value)));
const presentFilter = (attr: string) => tlv(ctx(7), new TextEncoder().encode(attr)); // [7] is IMPLICIT: content is the attr name itself
const andFilter = (...parts: Uint8Array[]) => tlv(ctxC(0), concat(...parts));

function searchReq(id: number, base: string, scope: 0 | 1 | 2, filter: Uint8Array, attrs: string[] = [], controls: Uint8Array[] = []) {
  return ldapMessage(
    id,
    tlv(appC(3), concat(octetString(base), enumValue(scope), enumValue(0), integer(0), integer(0), booleanValue(false), filter, seq(...attrs.map(octetString)))),
    controls
  );
}

interface Response {
  id: number;
  tag: number;
  code?: number;
  diagnostic?: string;
  dn?: string;
  attrs?: Map<string, string[]>;
  responseValue?: string;
  controls?: { oid: string; value: Uint8Array }[];
}

/** Decode one response LDAPMessage from raw frame bytes. */
function decodeResponse(frame: Uint8Array): Response {
  const r = new BerReader(frame).readConstructed(0x30);
  const id = r.readInteger();
  const el = r.readElement();
  const body = new BerReader(el.content);
  const res: Response = { id, tag: el.tag };
  if (el.tag === 0x64) {
    // SearchResultEntry
    res.dn = body.readString();
    res.attrs = new Map();
    const attrs = body.readConstructed(0x30);
    while (!attrs.atEnd()) {
      const pa = attrs.readConstructed(0x30);
      const name = pa.readString();
      const vals = pa.readConstructed(0x31);
      const list: string[] = [];
      while (!vals.atEnd()) list.push(vals.readString());
      res.attrs.set(name, list);
    }
  } else if (el.tag === 0x78) {
    // ExtendedResponse
    res.code = body.readEnumerated();
    body.readString();
    res.diagnostic = body.readString();
    if (body.peekTag() === 0x8a) body.readOctetString(0x8a);
    if (body.peekTag() === 0x8b) res.responseValue = new TextDecoder().decode(body.readOctetString(0x8b));
  } else {
    res.code = body.readEnumerated();
    body.readString();
    res.diagnostic = body.readString();
  }
  if (r.peekTag() === 0xa0) {
    res.controls = [];
    const cs = r.readConstructed(0xa0);
    while (!cs.atEnd()) {
      const c = cs.readConstructed(0x30);
      const oid = c.readString();
      const value = c.peekTag() === 0x04 ? c.readOctetString() : new Uint8Array(0);
      res.controls.push({ oid, value });
    }
  }
  return res;
}

/** A connected LDAP client over in-memory streams. */
function client(ip = "203.0.113.9") {
  const c2s = new TransformStream<Uint8Array, Uint8Array>();
  const s2c = new TransformStream<Uint8Array, Uint8Array>();
  const done = handleLdapConnection(c2s.readable, s2c.writable, { env, ip });
  const writer = c2s.writable.getWriter();
  const reader = s2c.readable.getReader();
  let buf = new Uint8Array(0);

  const frame = async (): Promise<Response> => {
    for (;;) {
      if (buf.length >= 2) {
        // frame length from header
        const first = buf[1]!;
        let headerLen = 2, len = first;
        if (first >= 0x80) {
          const n = first & 0x7f;
          len = 0;
          for (let k = 0; k < n; k++) len = len * 256 + buf[2 + k]!;
          headerLen = 2 + n;
        }
        if (buf.length >= headerLen + len) {
          const f = buf.subarray(0, headerLen + len);
          buf = buf.subarray(headerLen + len);
          return decodeResponse(f);
        }
      }
      const { done: eof, value } = await reader.read();
      if (eof) throw new Error("connection closed while expecting a response");
      const merged = new Uint8Array(buf.length + value.length);
      merged.set(buf);
      merged.set(value, buf.length);
      buf = merged;
    }
  };

  return {
    send: async (bytes: Uint8Array) => writer.write(bytes),
    recv: frame,
    /** Read until SearchResultDone; returns entries + the done response. */
    search: async (id: number, base: string, scope: 0 | 1 | 2, filter: Uint8Array, attrs: string[] = [], controls: Uint8Array[] = []) => {
      await writer.write(searchReq(id, base, scope, filter, attrs, controls));
      const entries: Response[] = [];
      for (;;) {
        const r = await frame();
        if (r.tag === 0x65) return { entries, done: r };
        entries.push(r);
      }
    },
    close: async () => {
      await writer.close().catch(() => {});
      reader.releaseLock();
      await done;
    },
    done,
  };
}

// ---- shared fixture ----

let appSecret = "";
const SLUG = "grafana";

async function setupLdap(opts: { mfaMode?: "password" | "otp_if_enrolled" | "otp_required" } = {}) {
  const { apiKey } = await bootstrapInstance();
  await enableLdap(env);
  const { app, secret } = await writeLdapApp(env, { slug: SLUG, name: "Grafana", mfa_mode: opts.mfaMode ?? "password" });
  appSecret = secret!;
  // Alice: active, has a password, member of Eng.
  const grp = await apiCall("/api/v1/groups", { token: apiKey, body: { name: "Eng" } });
  expect(grp.status).toBe(201);
  const created = await apiCall("/api/v1/users", { token: apiKey, body: { username: "alice", given_name: "Alice", family_name: "Doe", groups: ["Eng"] } });
  expect(created.status).toBe(201);
  await apiCall("/api/v1/users/alice/reset-password", { token: apiKey, body: { password: "correct-horse-9" } });
  await apiCall("/api/v1/users/alice", { token: apiKey, method: "PATCH", body: { status: "active" } });
  // Bob: active too, no groups.
  const bob = await apiCall("/api/v1/users", { token: apiKey, body: { username: "bob", given_name: "Bob" } });
  expect(bob.status).toBe(201);
  await apiCall("/api/v1/users/bob/reset-password", { token: apiKey, body: { password: "bob-password-7" } });
  await apiCall("/api/v1/users/bob", { token: apiKey, method: "PATCH", body: { status: "active" } });
  resetSnapshotCache();
  return { apiKey, app };
}

const ALICE_DN = `uid=alice,ou=people,ou=${SLUG},${BASE_DN}`;
const SERVICE_DN = `cn=${SLUG},ou=services,${BASE_DN}`;

beforeEach(async () => {
  await resetDatabase();
});

describe("ldap binds", { timeout: 60000 }, () => {
  it("binds a service account and a user under its branch", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    expect((await c.recv()).code).toBe(0);
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(0);
    await c.send(unbindReq(3));
    await c.close();
  });

  it("rejects a bad user password with invalidCredentials and the AD 52e diagnostic", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "wrong-password"));
    const res = await c.recv();
    expect(res.code).toBe(49);
    expect(res.diagnostic).toContain("data 52e");
    await c.close();
  });

  it("rejects a bad service secret and an unknown app DN", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, "flareid_ldap_wrong"));
    expect((await c.recv()).code).toBe(49);
    await c.send(bindReq(2, `cn=nope,ou=services,${BASE_DN}`, "flareid_ldap_x"));
    expect((await c.recv()).code).toBe(49);
    await c.close();
  });

  it("rejects an empty password and a non-v3 bind", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, ALICE_DN, ""));
    expect((await c.recv()).code).toBe(49);
    await c.send(ldapMessage(2, tlv(appTag(0), concat(integer(2), octetString(""), tlv(ctx(0), new Uint8Array(0))))));
    expect((await c.recv()).code).toBe(2);
    await c.close();
  });

  it("denies an unattributed user bind when no unscoped app is set", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, "alice@example.com", "correct-horse-9"));
    expect((await c.recv()).code).toBe(49);
    await c.close();
  });

  it("accepts a UPN bind attributed via ldap_unscoped_bind_app", async () => {
    const { apiKey } = await setupLdap();
    await env.DB.prepare("UPDATE idp_settings SET value = ? WHERE key = 'ldap_unscoped_bind_app'").bind(SLUG).run();
    resetSnapshotCache();
    const c = client();
    await c.send(bindReq(1, "alice@example.com", "correct-horse-9"));
    expect((await c.recv()).code).toBe(0);
    await c.close();
  });

  it("binds with password,otp when the app requires it", async () => {
    const { apiKey } = await setupLdap({ mfaMode: "otp_required" });
    const secret = "JBSWY3DPEHPK3PXP";
    await env.DB.prepare("UPDATE users SET mfa_enabled = 1, totp_secret = ? WHERE username = 'alice'").bind(secret).run();
    resetSnapshotCache();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    // Password alone is refused.
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(49);
    // password,<current code> succeeds.
    await c.send(bindReq(3, ALICE_DN, `correct-horse-9,${await totp(secret)}`));
    expect((await c.recv()).code).toBe(0);
    await c.close();
  });
});

describe("ldap search", { timeout: 60000 }, () => {
  it("returns the root DSE anonymously without binding", async () => {
    await setupLdap();
    const c = client();
    const { entries, done } = await c.search(1, "", 0, presentFilter("objectClass"));
    expect(done.code).toBe(0);
    expect(entries).toHaveLength(1);
    const dse = entries[0]!.attrs!;
    expect(dse.get("namingcontexts")).toEqual([BASE_DN]);
    expect(dse.get("supportedldapversion")).toContain("3");
    await c.close();
  });

  it("refuses an anonymous subtree search of the directory", async () => {
    await setupLdap();
    const c = client();
    const { done } = await c.search(1, BASE_DN, 2, presentFilter("objectClass"));
    expect(done.code).toBe(50);
    await c.close();
  });

  it("a service bind sees only its own branch", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    const { entries, done } = await c.search(2, BASE_DN, 2, presentFilter("objectClass"));
    expect(done.code).toBe(0);
    const dns = entries.map((e) => e.dn!.toLowerCase());
    expect(dns).toContain(`ou=${SLUG},${BASE_DN}`.toLowerCase());
    expect(dns.some((d) => d.includes(`ou=${SLUG}`))).toBe(true);
    expect(dns.every((d) => d === BASE_DN.toLowerCase() || d.includes(`,ou=${SLUG},`) || d === `ou=${SLUG},${BASE_DN}`.toLowerCase())).toBe(true);
    await c.close();
  });

  it("finds a user by uid and returns inetOrgPerson attributes", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    const { entries, done } = await c.search(2, `ou=people,ou=${SLUG},${BASE_DN}`, 2, eqFilter("uid", "alice"), ["cn", "mail", "uid", "memberof"]);
    expect(done.code).toBe(0);
    expect(entries).toHaveLength(1);
    const attrs = entries[0]!.attrs!;
    expect(attrs.get("uid")).toEqual(["alice"]);
    expect(attrs.get("cn")).toEqual(["Alice Doe"]);
    expect(attrs.get("mail")).toEqual(["alice@example.com"]);
    expect(attrs.get("memberof")!.some((d) => d.toLowerCase() === `cn=eng,ou=groups,ou=${SLUG},${BASE_DN}`.toLowerCase())).toBe(true);
    // unrequested attributes are absent
    expect(attrs.has("employeenumber")).toBe(false);
    await c.close();
  });

  it("user-bound searches see only themselves", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    await c.recv();
    const { entries } = await c.search(3, `ou=people,ou=${SLUG},${BASE_DN}`, 2, presentFilter("objectClass"));
    const dns = entries.map((e) => e.dn!.toLowerCase());
    expect(dns).toEqual([ALICE_DN.toLowerCase()]);
    await c.close();
  });

  it("a base in another app's branch is invisible", async () => {
    const { apiKey } = await setupLdap();
    await writeLdapApp(env, { slug: "other", name: "Other" });
    resetSnapshotCache();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    const { done } = await c.search(2, `ou=other,${BASE_DN}`, 2, presentFilter("objectClass"));
    expect(done.code).toBe(32);
    await c.close();
  });

  it("pages a subtree search with the RFC 2696 control", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    const pagedCtl = (size: number, cookie: Uint8Array) => control(PAGED, seq(integer(size), octetString(cookie)));
    const first = await c.search(2, `ou=${SLUG},${BASE_DN}`, 2, presentFilter("objectClass"), ["cn"], [pagedCtl(2, new Uint8Array(0))]);
    expect(first.done.code).toBe(0);
    expect(first.entries.length).toBe(2);
    const cookie = first.done.controls!.find((x) => x.oid === PAGED)!.value;
    const cookieVal = new BerReader(cookie).readConstructed(0x30);
    cookieVal.readInteger();
    const raw = cookieVal.readOctetString();
    expect(raw.length).toBeGreaterThan(0);
    const second = await c.search(3, `ou=${SLUG},${BASE_DN}`, 2, presentFilter("objectClass"), ["cn"], [pagedCtl(2, raw)]);
    const dns = [...first.entries, ...second.entries].map((e) => e.dn!);
    expect(new Set(dns).size).toBe(dns.length); // no repeats across pages
    // keep paging until the cookie empties
    let doneRes = second.done;
    let lastCookie = raw;
    while (true) {
      const ctrl = doneRes.controls!.find((x) => x.oid === PAGED)!.value;
      const rr = new BerReader(ctrl).readConstructed(0x30);
      rr.readInteger();
      lastCookie = rr.readOctetString();
      if (lastCookie.length === 0) break;
      const next = await c.search(4, `ou=${SLUG},${BASE_DN}`, 2, presentFilter("objectClass"), ["cn"], [pagedCtl(2, lastCookie)]);
      doneRes = next.done;
    }
    await c.close();
  });
});

describe("ldap misc ops", { timeout: 60000 }, () => {
  it("answers whoami with the bound dn", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    await c.recv();
    await c.send(whoamiReq(3));
    const res = await c.recv();
    expect(res.code).toBe(0);
    expect(res.responseValue).toBe(`dn:${ALICE_DN}`);
    await c.close();
  });

  it("refuses writes as read-only and StartTLS outright", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    // modifyRequest
    await c.send(ldapMessage(2, tlv(appC(6), concat(octetString(ALICE_DN), seq()))));
    expect((await c.recv()).code).toBe(53);
    // StartTLS extended -> operationsError then disconnect
    await c.send(ldapMessage(3, tlv(appC(23), tlv(ctx(0), new TextEncoder().encode("1.3.6.1.4.1.1466.20037")))));
    const res = await c.recv();
    expect(res.code).toBe(1);
    await c.close();
  });

  it("compare works on a member attribute", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    const groupDn = `cn=eng,ou=groups,ou=${SLUG},${BASE_DN}`;
    const cmp = (id: number, dn: string, attr: string, value: string) => ldapMessage(id, tlv(appC(14), concat(octetString(dn), seq(octetString(attr), octetString(value)))));
    await c.send(cmp(2, groupDn, "member", ALICE_DN));
    expect((await c.recv()).code).toBe(6);
    await c.send(cmp(3, groupDn, "member", `uid=bob,ou=people,ou=${SLUG},${BASE_DN}`));
    expect((await c.recv()).code).toBe(5);
    // userPassword compare is always refused
    await c.send(cmp(4, ALICE_DN, "userPassword", "correct-horse-9"));
    expect((await c.recv()).code).toBe(53);
    await c.close();
  });

  it("sends a notice of disconnection and closes when LDAP is disabled", async () => {
    const { apiKey } = await bootstrapInstance();
    const c = client();
    const res = await c.recv();
    expect(res.tag).toBe(0x78);
    expect(res.code).toBe(52);
    await c.close();
  });
});

describe("ldap ranged retrieval and sorting", { timeout: 60000 }, () => {
  it("serves member;range=L-H windows on a group", async () => {
    const { apiKey } = await setupLdap();
    // a second member so the ranges actually slice
    await apiCall("/api/v1/users", { token: apiKey, body: { username: "carol", given_name: "Carol", groups: ["Eng"] } });
    await apiCall("/api/v1/users/carol", { token: apiKey, method: "PATCH", body: { status: "active" } });
    resetSnapshotCache();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    const groupDn = `cn=eng,ou=groups,ou=${SLUG},${BASE_DN}`;

    const all = await c.search(2, groupDn, 0, presentFilter("objectClass"), ["member"]);
    const members = all.entries[0]!.attrs!.get("member")!;
    expect(members.length).toBe(2);

    const first = await c.search(3, groupDn, 0, presentFilter("objectClass"), ["member;range=0-0"]);
    expect(first.entries[0]!.attrs!.get("member;range=0-0")).toEqual([members[0]]);

    const rest = await c.search(4, groupDn, 0, presentFilter("objectClass"), ["member;range=1-*"]);
    expect(rest.entries[0]!.attrs!.get("member;range=1-*")).toEqual([members[1]]);

    const past = await c.search(5, groupDn, 0, presentFilter("objectClass"), ["member;range=9-*"]);
    expect(past.entries[0]!.attrs!.get("member;range=9-*")).toEqual([]);
    await c.close();
  });

  it("sorts entries via the RFC 2891 server-side sort control", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    const SORT = "1.2.840.113556.1.4.473";
    const SORTRES = "1.2.840.113556.1.4.474";
    const base = `ou=people,ou=${SLUG},${BASE_DN}`;

    const asc = await c.search(2, base, 2, presentFilter("uid"), ["uid"], [control(SORT, seq(seq(octetString("uid"))))]);
    const uids = asc.entries.map((e) => e.attrs!.get("uid")![0]);
    expect(uids).toEqual([...uids].sort());
    expect(asc.done.controls!.some((x) => x.oid === SORTRES)).toBe(true);

    // [1] reverseOrder IMPLICIT BOOLEAN
    const desc = await c.search(3, base, 2, presentFilter("uid"), ["uid"], [control(SORT, seq(seq(octetString("uid"), tlv(ctx(1), new Uint8Array([0xff])))))]);
    expect(desc.entries.map((e) => e.attrs!.get("uid")![0])).toEqual([...uids].reverse());
    await c.close();
  });
});

describe("ldap password modify (RFC 3062)", { timeout: 60000 }, () => {
  const PWMOD = "1.3.6.1.4.1.4203.1.11.1";
  const pwmodReq = (id: number, fields: { user?: string; old?: string; next?: string }) =>
    ldapMessage(
      id,
      tlv(
        appC(23),
        concat(
          tlv(ctx(0), new TextEncoder().encode(PWMOD)),
          tlv(
            ctx(1),
            seq(
              ...(fields.user !== undefined ? [tlv(ctx(0), new TextEncoder().encode(fields.user))] : []),
              ...(fields.old !== undefined ? [tlv(ctx(1), new TextEncoder().encode(fields.old))] : []),
              ...(fields.next !== undefined ? [tlv(ctx(2), new TextEncoder().encode(fields.next))] : [])
            )
          )
        )
      )
    );

  it("refuses anonymous and service-bound connections", async () => {
    await setupLdap();
    const c = client();
    await c.send(pwmodReq(1, { old: "x", next: "new-password-9" }));
    expect((await c.recv()).code).toBe(50);
    await c.send(bindReq(2, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(pwmodReq(3, { old: "x", next: "new-password-9" }));
    expect((await c.recv()).code).toBe(50);
    await c.close();
  });

  it("changes the bound user's password and lets them rebind with it", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(0);
    await c.send(pwmodReq(3, { user: ALICE_DN, old: "correct-horse-9", next: "rotated-horse-1" }));
    expect((await c.recv()).code).toBe(0);
    // old password is dead, new one binds
    await c.send(bindReq(4, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(49);
    await c.send(bindReq(5, ALICE_DN, "rotated-horse-1"));
    expect((await c.recv()).code).toBe(0);
    await c.close();
  });

  it("rejects a wrong old password, a foreign userIdentity, and a weak new one", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    await c.recv();
    await c.send(pwmodReq(3, { old: "not-the-password", next: "rotated-horse-1" }));
    expect((await c.recv()).code).toBe(49);
    await c.send(pwmodReq(4, { user: `uid=bob,ou=people,ou=${SLUG},${BASE_DN}`, old: "correct-horse-9", next: "rotated-horse-1" }));
    expect((await c.recv()).code).toBe(50);
    await c.send(pwmodReq(5, { old: "correct-horse-9", next: "x" }));
    expect((await c.recv()).code).toBe(53);
    await c.close();
  });
});

describe("ldap session revalidation", { timeout: 60000 }, () => {
  const cmp = (id: number, dn: string, attr: string, value: string) => ldapMessage(id, tlv(appC(14), concat(octetString(dn), seq(octetString(attr), octetString(value)))));

  it("drops to anonymous on a failed bind instead of keeping the prior principal", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    expect((await c.recv()).code).toBe(0);
    // A failed rebind must not retain the service principal (RFC 4511 4.2.1).
    await c.send(bindReq(2, `cn=nope,ou=services,${BASE_DN}`, "flareid_ldap_wrong"));
    expect((await c.recv()).code).toBe(49);
    const { done } = await c.search(3, BASE_DN, 2, presentFilter("objectClass"));
    expect(done.code).toBe(50); // anonymous: no subtree access
    await c.close();
  });

  it("disconnects a service-bound connection when its app is revoked", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    expect((await c.recv()).code).toBe(0);
    await env.DB.prepare("UPDATE ldap_apps SET revoked_at = ? WHERE slug = ?").bind(new Date().toISOString(), SLUG).run();
    resetSnapshotCache();
    await c.send(whoamiReq(2));
    const res = await c.recv();
    expect(res.tag).toBe(0x78); // noticeOfDisconnection
    expect(res.code).toBe(53);
    await c.close();
  });

  it("refuses ops from a user-bound connection once the account is disabled", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(0);
    await env.DB.prepare("UPDATE users SET status = 'disabled' WHERE username = 'alice'").run();
    resetSnapshotCache();
    const { done } = await c.search(3, `ou=people,ou=${SLUG},${BASE_DN}`, 2, presentFilter("objectClass"));
    expect(done.code).toBe(50);
    // Now anonymous - whoami reports an empty authzid.
    await c.send(whoamiReq(4));
    const res = await c.recv();
    expect(res.code).toBe(0);
    expect(res.responseValue).toBe("");
    // And rebinding as the disabled user fails outright.
    await c.send(bindReq(5, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(49);
    await c.close();
  });

  it("disconnects in-flight connections when LDAP is disabled", async () => {
    await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    expect((await c.recv()).code).toBe(0);
    await disableLdap(env);
    resetSnapshotCache();
    await c.send(whoamiReq(2));
    const res = await c.recv();
    expect(res.tag).toBe(0x78); // noticeOfDisconnection
    expect(res.code).toBe(52);
    await c.close();
  });

  it("scopes user-bound compare to their own entry and own groups", async () => {
    const { apiKey } = await setupLdap();
    await apiCall("/api/v1/groups", { token: apiKey, body: { name: "Ops" } });
    resetSnapshotCache();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(0);
    const bobDn = `uid=bob,ou=people,ou=${SLUG},${BASE_DN}`;
    const engDn = `cn=eng,ou=groups,ou=${SLUG},${BASE_DN}`;
    const opsDn = `cn=ops,ou=groups,ou=${SLUG},${BASE_DN}`;
    // Another user's entry is invisible.
    await c.send(cmp(3, bobDn, "uid", "bob"));
    expect((await c.recv()).code).toBe(32);
    // So is a group alice does not belong to.
    await c.send(cmp(4, opsDn, "cn", "ops"));
    expect((await c.recv()).code).toBe(32);
    // Her own entry and own group compare normally, with member reduced to herself.
    await c.send(cmp(5, ALICE_DN, "uid", "alice"));
    expect((await c.recv()).code).toBe(6);
    await c.send(cmp(6, engDn, "member", ALICE_DN));
    expect((await c.recv()).code).toBe(6);
    await c.send(cmp(7, engDn, "member", bobDn));
    expect((await c.recv()).code).toBe(5);
    await c.close();
  });

  it("shows a user-bound search only the groups they belong to", async () => {
    const { apiKey } = await setupLdap();
    await apiCall("/api/v1/groups", { token: apiKey, body: { name: "Ops" } });
    resetSnapshotCache();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(0);
    const { entries } = await c.search(3, `ou=groups,ou=${SLUG},${BASE_DN}`, 2, presentFilter("objectClass"), ["cn"]);
    const dns = entries.map((e) => e.dn!.toLowerCase());
    expect(dns).toEqual([`cn=eng,ou=groups,ou=${SLUG},${BASE_DN}`.toLowerCase()]);
    await c.close();
  });

  it("verifies oldPasswd against the live password, not the bind-time hash", async () => {
    const PWMOD = "1.3.6.1.4.1.4203.1.11.1";
    const pwmod = (id: number, old: string, next: string) =>
      ldapMessage(id, tlv(appC(23), concat(tlv(ctx(0), new TextEncoder().encode(PWMOD)), tlv(ctx(1), seq(tlv(ctx(1), new TextEncoder().encode(old)), tlv(ctx(2), new TextEncoder().encode(next)))))));
    const { apiKey } = await setupLdap();
    const c = client();
    await c.send(bindReq(1, SERVICE_DN, appSecret));
    await c.recv();
    await c.send(bindReq(2, ALICE_DN, "correct-horse-9"));
    expect((await c.recv()).code).toBe(0);
    // An external rotation must invalidate the bind-time credential.
    await apiCall("/api/v1/users/alice/reset-password", { token: apiKey, body: { password: "evicted-horse-3" } });
    await c.send(pwmod(3, "correct-horse-9", "attacker-choice-7"));
    expect((await c.recv()).code).toBe(49);
    await c.send(pwmod(4, "evicted-horse-3", "attacker-choice-7"));
    expect((await c.recv()).code).toBe(0);
    await c.close();
  });

  it("keeps omitted policy fields on a partial app update", async () => {
    const { apiKey } = await setupLdap();
    const grp = await env.DB.prepare("SELECT id FROM groups WHERE name = 'Eng'").first<{ id: number }>();
    const { app } = await writeLdapApp(env, { slug: "partial", name: "Partial", mfa_mode: "otp_required", include_disabled: true, user_group_ids: [grp!.id], exposed_group_ids: [grp!.id] });
    // Update with only name - omitted policy fields must not reset to create defaults.
    const { app: updated } = await writeLdapApp(env, { slug: "partial", name: "Renamed" });
    expect(updated.id).toBe(app.id);
    expect(updated.name).toBe("Renamed");
    expect(updated.mfa_mode).toBe("otp_required");
    expect(updated.include_disabled).toBe(1);
    expect(updated.user_group_ids).toBe(`[${grp!.id}]`);
    expect(updated.exposed_group_ids).toBe(`[${grp!.id}]`);
  });
});
