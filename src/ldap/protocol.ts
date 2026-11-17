import { BerError, BerReader, appC, ctx, concat, enumValue, integer, octetString, seq, set, tlv } from "./ber.js";

/**
 * LDAPMessage decode/encode, RFC 4511 (LDAP.md sections 5 and 21).
 * Decoding is per-op: operations we never support still get a parsed
 * envelope so the connection can answer them with the right refusal.
 */

// Result codes (section 21).
export const RC = {
  success: 0,
  operationsError: 1,
  protocolError: 2,
  timeLimitExceeded: 3,
  sizeLimitExceeded: 4,
  compareFalse: 5,
  compareTrue: 6,
  authMethodNotSupported: 7,
  unavailableCriticalExtension: 12,
  undefinedAttributeType: 17,
  noSuchObject: 32,
  invalidDNSyntax: 34,
  inappropriateAuthentication: 48,
  invalidCredentials: 49,
  insufficientAccessRights: 50,
  busy: 51,
  unavailable: 52,
  unwillingToPerform: 53,
  other: 80,
} as const;

// Protocol op tags (section 21).
export const OP = {
  bindRequest: appC(0), // 0x60
  bindResponse: appC(1), // 0x61
  unbindRequest: appC(2), // 0x42
  searchRequest: appC(3), // 0x63
  searchResultEntry: appC(4), // 0x64
  searchResultDone: appC(5), // 0x65
  modifyRequest: appC(6),
  modifyResponse: appC(7),
  addRequest: appC(8),
  addResponse: appC(9),
  delRequest: appC(10), // 0x4a
  delResponse: appC(11),
  modifyDnRequest: appC(12),
  modifyDnResponse: appC(13),
  compareRequest: appC(14), // 0x6e
  compareResponse: appC(15), // 0x6f
  abandonRequest: appC(16), // 0x50
  searchResultReference: appC(19),
  extendedRequest: appC(23), // 0x77
  extendedResponse: appC(24), // 0x78
} as const;

export const OID = {
  pagedResults: "1.2.840.113556.1.4.319",
  serverSort: "1.2.840.113556.1.4.473",
  sortResult: "1.2.840.113556.1.4.474",
  manageDsaIt: "2.16.840.1.113730.3.4.2",
  whoami: "1.3.6.1.4.1.4203.1.11.3",
  startTls: "1.3.6.1.4.1.1466.20037",
  passwordModify: "1.3.6.1.4.1.4203.1.11.1",
  noticeOfDisconnection: "1.3.6.1.4.1.1466.20036",
  allOperationalAttrs: "1.3.6.1.4.1.4203.1.5.1",
  matchBitAnd: "1.2.840.113556.1.4.803",
  matchBitOr: "1.2.840.113556.1.4.804",
  matchInChain: "1.2.840.113556.1.4.1941",
} as const;

export interface Control {
  type: string;
  critical: boolean;
  value: Uint8Array | null;
}

export type Scope = 0 | 1 | 2; // base / one / subtree

export type Operation =
  | { kind: "bind"; version: number; name: string; simple: Uint8Array | null }
  | { kind: "unbind" }
  | {
      kind: "search";
      base: string;
      scope: Scope;
      derefAliases: number;
      sizeLimit: number;
      timeLimit: number;
      typesOnly: boolean;
      /** The raw bytes of the filter element (tag included) for filter.ts to parse. */
      filterRaw: Uint8Array;
      attributes: string[];
    }
  | { kind: "compare"; entry: string; attribute: string; value: Uint8Array }
  | { kind: "abandon"; target: number }
  | { kind: "extended"; name: string; value: Uint8Array | null }
  | { kind: "write"; op: string };

export interface LdapMessage {
  id: number;
  op: Operation;
  controls: Control[];
}

/** Decode one complete LDAPMessage (the SEQUENCE's content reader). */
export function decodeMessage(buf: Uint8Array): LdapMessage {
  const r = new BerReader(buf).readConstructed(0x30);
  const id = r.readInteger();
  if (r.atEnd()) throw new BerError("message has no protocolOp");
  const opEl = r.readElement();
  const or = new BerReader(opEl.content);
  let op: Operation;
  switch (opEl.tag) {
    case OP.bindRequest: {
      const version = or.readInteger();
      const name = or.readString();
      const auth = or.readElement();
      op = { kind: "bind", version, name, simple: auth.tag === ctx(0) ? auth.content : null };
      break;
    }
    case OP.unbindRequest:
      op = { kind: "unbind" };
      break;
    case OP.searchRequest: {
      const base = or.readString();
      const scope = or.readEnumerated();
      const derefAliases = or.readEnumerated();
      const sizeLimit = or.readInteger();
      const timeLimit = or.readInteger();
      const typesOnly = or.readBoolean();
      const filterEl = or.readElement();
      // Re-wrap: the AST parser wants a complete TLV.
      const filterRaw = concat(new Uint8Array([filterEl.tag]), encodeLen(filterEl.content.length), filterEl.content);
      const attrs: string[] = [];
      if (!or.atEnd() && or.peekTag() === 0x30) {
        const ar = or.readConstructed(0x30);
        while (!ar.atEnd()) attrs.push(ar.readString());
      }
      if (scope !== 0 && scope !== 1 && scope !== 2) throw new BerError("bad scope");
      op = { kind: "search", base, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filterRaw, attributes: attrs };
      break;
    }
    case OP.compareRequest: {
      const entry = or.readString();
      const ava = or.readConstructed(0x30);
      op = { kind: "compare", entry, attribute: ava.readString(), value: ava.readOctetString() };
      break;
    }
    case OP.abandonRequest:
      op = { kind: "abandon", target: or.readInteger() };
      break;
    case OP.extendedRequest: {
      let name = "";
      let value: Uint8Array | null = null;
      while (!or.atEnd()) {
        const f = or.readElement();
        if (f.tag === ctx(0)) name = new TextDecoder().decode(f.content);
        else if (f.tag === ctx(1)) value = f.content;
      }
      op = { kind: "extended", name, value };
      break;
    }
    case OP.modifyRequest:
      op = { kind: "write", op: "modify" };
      break;
    case OP.addRequest:
      op = { kind: "write", op: "add" };
      break;
    case OP.delRequest:
      op = { kind: "write", op: "delete" };
      break;
    case OP.modifyDnRequest:
      op = { kind: "write", op: "modifyDN" };
      break;
    default:
      throw new BerError(`unknown protocolOp 0x${opEl.tag.toString(16)}`);
  }

  const controls: Control[] = [];
  if (!r.atEnd()) {
    const cr = r.readConstructed(0xa0);
    while (!cr.atEnd()) {
      const c = cr.readConstructed(0x30);
      const type = c.readString();
      let critical = false;
      let value: Uint8Array | null = null;
      while (!c.atEnd()) {
        const f = c.readElement();
        if (f.tag === 0x01) critical = f.content[0] !== 0;
        else if (f.tag === 0x04) value = f.content;
      }
      controls.push({ type, critical, value });
    }
  }
  return { id, op, controls };
}

function encodeLen(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  const out: number[] = [];
  for (let n = len; n > 0; n >>>= 8) out.unshift(n & 0xff);
  return new Uint8Array([0x80 | out.length, ...out]);
}

// ---- encoders ----

export function controlBytes(type: string, value?: Uint8Array): Uint8Array {
  return seq(octetString(type), ...(value ? [octetString(value)] : []));
}

/** A whole LDAPMessage. */
export function message(id: number, op: Uint8Array, responseControls: Uint8Array[] = []): Uint8Array {
  return seq(integer(id), op, ...(responseControls.length ? [tlv(0xa0, concat(...responseControls))] : []));
}

export function ldapResult(opTag: number, code: number, matchedDn: string, diagnostic: string): Uint8Array {
  return tlv(opTag, concat(enumValue(code), octetString(matchedDn), octetString(diagnostic)));
}

export const bindResponse = (code: number, diagnostic: string, matchedDn = "") => ldapResult(OP.bindResponse, code, matchedDn, diagnostic);
export const searchDone = (code: number, diagnostic = "", matchedDn = "") => ldapResult(OP.searchResultDone, code, matchedDn, diagnostic);
export const compareResponse = (code: number, diagnostic = "", matchedDn = "") => ldapResult(OP.compareResponse, code, matchedDn, diagnostic);
export const extendedResponse = (code: number, diagnostic: string, responseName?: string, responseValue?: Uint8Array) =>
  tlv(
    OP.extendedResponse,
    concat(
      enumValue(code),
      octetString(""),
      octetString(diagnostic),
      ...(responseName ? [tlv(ctx(10), new TextEncoder().encode(responseName))] : []),
      ...(responseValue ? [tlv(ctx(11), responseValue)] : [])
    )
  );

/** An attribute's `type + SET OF values` inside a SearchResultEntry or other list. */
export function partialAttribute(type: string, values: (string | Uint8Array)[]): Uint8Array {
  return seq(octetString(type), set(...values.map((v) => octetString(v))));
}

export function searchEntry(dn: string, attrs: Uint8Array[]): Uint8Array {
  return tlv(OP.searchResultEntry, concat(octetString(dn), seq(...attrs)));
}

/** The paged-results response control carrying the cookie for the next call. */
export function pagedResponseControl(cookie: Uint8Array, estimatedTotal = 0): Uint8Array {
  return controlBytes(OID.pagedResults, seq(integer(estimatedTotal), octetString(cookie)));
}

/** Server-side sort result control (RFC 2891): ENUMERATED code + optional [0] attributeType that failed. */
export function sortResultControl(code: number, attributeType?: string): Uint8Array {
  return controlBytes(OID.sortResult, seq(enumValue(code), ...(attributeType ? [tlv(ctx(0), new TextEncoder().encode(attributeType))] : [])));
}

/** Notice of Disconnection: unsolicited ExtendedResponse, messageID 0. */
export function noticeOfDisconnection(code: number = RC.unavailable, diagnostic = ""): Uint8Array {
  return message(0, extendedResponse(code, diagnostic, OID.noticeOfDisconnection));
}

/** Wrap an encoded protocolOp in the rest of a refusal message. */
export function refusal(id: number, opTag: number, code: number, diagnostic: string): Uint8Array {
  return message(id, ldapResult(opTag, code, "", diagnostic));
}
