// BER codec unit tests (LDAP.md section 17.1): round-trips, long-form
// lengths, and rejection of indefinite lengths, truncation and nesting
// tricks, plus a real ldapsearch capture.
import { describe, expect, it } from "vitest";
import { BerReader, BerError, ctx, appC, octetString, integer, enumValue, seq, set, tlv, oidValue, booleanValue } from "../src/ldap/ber.js";
import { decodeMessage, message, bindResponse, RC, OP } from "../src/ldap/protocol.js";

const hex = (s: string) => new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

describe("BER writer", () => {
  it("encodes TLVs minimally", () => {
    expect(toHex(integer(0))).toBe("020100");
    expect(toHex(integer(127))).toBe("02017f");
    expect(toHex(integer(128))).toBe("02020080"); // sign pad
    expect(toHex(integer(256))).toBe("02020100");
    expect(toHex(octetString("hi"))).toBe("04026869");
    expect(toHex(seq(integer(1)))).toBe("3003020101");
  });

  it("encodes OIDs", () => {
    expect(toHex(oidValue("1.2.840.113556.1.4.319"))).toBe("060a2a864886f7140104823f");
    expect(() => oidValue("3.1.2")).toThrow(BerError);
    expect(() => oidValue("1.40")).toThrow(BerError);
  });
});

describe("BER reader", () => {
  it("round-trips nested structures", () => {
    const wire = seq(integer(5), octetString("cn=test"), set(integer(1), integer(2)));
    const r = new BerReader(wire).readConstructed(0x30);
    expect(r.readInteger()).toBe(5);
    expect(r.readString()).toBe("cn=test");
    const s = r.readConstructed(0x31);
    expect(s.readInteger()).toBe(1);
    expect(s.readInteger()).toBe(2);
    expect(r.atEnd()).toBe(true);
  });

  it("reads long-form lengths", () => {
    const big = tlv(0x04, new Uint8Array(300).fill(0x41));
    expect(toHex(big.slice(0, 4))).toBe("0482012c");
    const el = new BerReader(big).readElement();
    expect(el.content.length).toBe(300);
  });

  it("rejects indefinite length, truncation, multi-byte tags and overrun", () => {
    expect(() => new BerReader(hex("3080")).readElement()).toThrow(/indefinite/);
    expect(() => new BerReader(hex("04")).readElement()).toThrow(/truncated/);
    expect(() => new BerReader(hex("1f8101")).readElement()).toThrow(/multi-byte/);
    expect(() => new BerReader(hex("0405abcd")).readElement()).toThrow(/overruns/);
  });
});

// Real wire shapes, as `ldapsearch -x -H ldap://host -D '' -w '' -b '' -s sub '(objectClass=*)'` sends them:
// anonymous bind, messageID 1; subtree search on the root DSE, messageID 2.
const BIND_CAPTURE = hex("300c020101600702010304008000");
const SEARCH_CAPTURE = hex("3025020102632004000a01020a0100020100020100010100870b6f626a656374436c6173733000");

describe("real-capture decode (OpenLDAP ldapsearch)", () => {
  it("decodes an anonymous simple bind", () => {
    const m = decodeMessage(BIND_CAPTURE);
    expect(m.id).toBe(1);
    expect(m.op.kind).toBe("bind");
    if (m.op.kind === "bind") {
      expect(m.op.version).toBe(3);
      expect(m.op.name).toBe("");
      expect(m.op.simple).toEqual(new Uint8Array(0));
    }
  });

  it("decodes a subtree search with present filter", () => {
    const m = decodeMessage(SEARCH_CAPTURE);
    expect(m.id).toBe(2);
    expect(m.op.kind).toBe("search");
    if (m.op.kind === "search") {
      expect(m.op.scope).toBe(2);
      expect(m.op.sizeLimit).toBe(0);
      expect(m.op.timeLimit).toBe(0);
      expect(m.op.typesOnly).toBe(false);
      expect(m.op.attributes).toEqual([]);
      // The present filter arrives as primitive context tag 7 (0x87).
      expect(m.op.filterRaw[0]).toBe(0x87);
    }
  });
});

describe("response encoding", () => {
  it("writes a successful bind response", () => {
    const out = message(1, bindResponse(RC.success, ""));
    const r = new BerReader(out).readConstructed(0x30);
    expect(r.readInteger()).toBe(1);
    const op = r.readElement();
    expect(op.tag).toBe(OP.bindResponse);
    const or = new BerReader(op.content);
    expect(or.readEnumerated()).toBe(0);
  });

  it("context tag helpers", () => {
    expect(ctx(0)).toBe(0x80);
    expect(appC(0)).toBe(0x60);
    expect(appC(24)).toBe(0x78);
  });
});
