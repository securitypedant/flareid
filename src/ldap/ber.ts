/**
 * BER/DER reader and writer for the LDAP wire protocol (LDAP.md section 4).
 * Hand-rolled, no dependency - the authentication path shares FlareID's stance
 * on small testable code over imported crypto/protocol stacks.
 *
 * Deliberate restrictions, safe for LDAP (all tags in the protocol are under
 * 31, so multi-byte tag encodings are refused, and indefinite lengths are
 * always a parse error):
 *   - single-byte tags only
 *   - definite lengths only, in short or long form
 *   - no implicit tagging: callers always state the tag they expect
 */

export class BerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BerError";
  }
}

export const TAG_INTEGER = 0x02;
export const TAG_OCTET_STRING = 0x04;
export const TAG_NULL = 0x05;
export const TAG_OID = 0x06;
export const TAG_ENUMERATED = 0x0a;
export const TAG_BOOLEAN = 0x01;
export const TAG_SEQUENCE = 0x30;
export const TAG_SET = 0x31;

/** Context-specific primitive tag byte for tag number n ([n] IMPLICIT). */
export function ctx(tagNo: number): number {
  if (tagNo < 0 || tagNo > 30) throw new BerError(`context tag ${tagNo} out of range`);
  return 0x80 | tagNo;
}

/** Context-specific constructed tag byte ([n] containing elements). */
export function ctxC(tagNo: number): number {
  return ctx(tagNo) | 0x20;
}

/** Application-class constructed tag byte ([APPLICATION n]). */
export function appC(tagNo: number): number {
  if (tagNo < 0 || tagNo > 30) throw new BerError(`application tag ${tagNo} out of range`);
  return 0x40 | 0x20 | tagNo;
}

const te = new TextEncoder();

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  const out: number[] = [];
  for (let n = len; n > 0; n >>>= 8) out.unshift(n & 0xff);
  return new Uint8Array([0x80 | out.length, ...out]);
}

/** One complete TLV. */
export function tlv(tag: number, content: Uint8Array): Uint8Array {
  const len = encodeLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export const seq = (...parts: Uint8Array[]) => tlv(TAG_SEQUENCE, concat(...parts));
export const set = (...parts: Uint8Array[]) => tlv(TAG_SET, concat(...parts));

/** DER integer: minimal two's-complement, non-negative values only (LDAP has none negative that we emit). */
export function integer(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0x7fffffff) throw new BerError(`integer ${n} out of encodable range`);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  if (bytes.length === 0) bytes.push(0);
  if (bytes[0]! & 0x80) bytes.unshift(0); // keep it positive
  return tlv(TAG_INTEGER, new Uint8Array(bytes));
}

export function enumValue(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0x7fffffff) throw new BerError(`enumerated ${n} out of range`);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  if (bytes.length === 0) bytes.push(0);
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return tlv(TAG_ENUMERATED, new Uint8Array(bytes));
}

export function octetString(s: string | Uint8Array): Uint8Array {
  return tlv(TAG_OCTET_STRING, typeof s === "string" ? te.encode(s) : s);
}

export function booleanValue(b: boolean): Uint8Array {
  return tlv(TAG_BOOLEAN, new Uint8Array([b ? 0xff : 0x00]));
}

export function oidValue(oid: string): Uint8Array {
  const parts = oid.split(".").map((p) => {
    if (!/^\d+$/.test(p)) throw new BerError(`bad OID component '${p}'`);
    return Number(p);
  });
  if (parts.length < 2 || parts[0]! > 2 || (parts[0]! < 2 && parts[1]! > 39)) throw new BerError(`bad OID '${oid}'`);
  const body: number[] = [parts[0]! * 40 + parts[1]!];
  for (const comp of parts.slice(2)) {
    // base-128, high bit on all but last
    const enc: number[] = [comp & 0x7f];
    for (let v = comp >>> 7; v > 0; v >>>= 7) enc.unshift(0x80 | (v & 0x7f));
    body.push(...enc);
  }
  return tlv(TAG_OID, new Uint8Array(body));
}

export const nullValue = tlv(TAG_NULL, new Uint8Array(0));

/**
 * One parsed TLV. `tag` is the raw tag byte; `content` is the value octets
 * (the element's own bytes for a primitive, or the concatenated children for
 * a constructed element).
 */
export interface Element {
  tag: number;
  constructed: boolean;
  content: Uint8Array;
}

export class BerReader {
  private at = 0;
  constructor(private buf: Uint8Array) {}

  atEnd(): boolean {
    return this.at >= this.buf.length;
  }

  /** The next element's tag byte, or -1 at end of input. */
  peekTag(): number {
    return this.at < this.buf.length ? this.buf[this.at]! : -1;
  }

  /** Read one TLV and return its content octets. */
  readElement(expectedTag?: number): Element {
    const start = this.at;
    if (this.at >= this.buf.length) throw new BerError("unexpected end of input");
    const tag = this.buf[this.at++]!;
    if ((tag & 0x1f) === 0x1f) throw new BerError("multi-byte tags are not supported");
    if (this.at >= this.buf.length) throw new BerError("truncated length");
    const first = this.buf[this.at++]!;
    let len: number;
    if (first === 0x80) throw new BerError("indefinite length not allowed");
    else if (first < 0x80) len = first;
    else {
      const n = first & 0x7f;
      if (n === 0 || n > 4 || this.at + n > this.buf.length) throw new BerError("bad long-form length");
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + this.buf[this.at++]!;
    }
    if (this.at + len > this.buf.length) throw new BerError("element overruns input");
    const content = this.buf.subarray(this.at, this.at + len);
    this.at += len;
    if (expectedTag !== undefined && tag !== expectedTag) {
      throw new BerError(`tag 0x${tag.toString(16)} at offset ${start}, expected 0x${expectedTag.toString(16)}`);
    }
    return { tag, constructed: (tag & 0x20) !== 0, content };
  }

  /** Read a constructed element and return a reader over its children. */
  readConstructed(expectedTag: number): BerReader {
    const el = this.readElement(expectedTag);
    if (!el.constructed) throw new BerError(`tag 0x${expectedTag.toString(16)} is not constructed`);
    return new BerReader(el.content);
  }

  readInteger(expectedTag = TAG_INTEGER): number {
    const c = this.readElement(expectedTag).content;
    if (c.length === 0 || c.length > 4) throw new BerError("integer length out of range");
    let v = 0;
    for (const b of c) v = v * 256 + b;
    if (c[0]! & 0x80) throw new BerError("negative integers are not expected");
    return v;
  }

  readEnumerated(): number {
    return this.readInteger(TAG_ENUMERATED);
  }

  readBoolean(): boolean {
    const c = this.readElement(TAG_BOOLEAN).content;
    if (c.length !== 1) throw new BerError("bad BOOLEAN");
    return c[0] !== 0;
  }

  readOctetString(expectedTag = TAG_OCTET_STRING): Uint8Array {
    return this.readElement(expectedTag).content;
  }

  readString(expectedTag = TAG_OCTET_STRING): string {
    return new TextDecoder("utf-8").decode(this.readOctetString(expectedTag));
  }

  readOid(): string {
    const c = this.readElement(TAG_OID).content;
    if (c.length === 0) throw new BerError("empty OID");
    const first = c[0]!;
    const out: number[] = [Math.floor(first / 40), first % 40];
    let v = 0;
    for (let i = 1; i < c.length; i++) {
      const b = c[i]!;
      v = v * 128 + (b & 0x7f);
      if (!(b & 0x80)) {
        out.push(v);
        v = 0;
      }
    }
    if (v !== 0) throw new BerError("truncated OID component");
    return out.join(".");
  }
}
