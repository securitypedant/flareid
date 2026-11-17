/**
 * Active Directory compatibility encodings (LDAP.md section 11):
 * objectGUID byte order, objectSid binary layout, and the objectCategory /
 * distinguishedName strings AD-mode filters and clients expect.
 */

/** UUID string -> AD's 16-byte objectGUID (first three fields little-endian). */
export function uuidToGuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new RangeError(`'${uuid}' is not a UUID`);
  const b = new Uint8Array(16);
  for (let i = 0; i < 16; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  // Fields 1-3 (8, 4 and 4 bytes... actually 4+2+2) are stored little-endian.
  const swap = (a: number, c: number) => {
    for (let i = a, j = c; i < j; i++, j--) [b[i], b[j]] = [b[j]!, b[i]!];
  };
  swap(0, 3);
  swap(4, 5);
  swap(6, 7);
  return b;
}

/**
 * Binary SID: revision 1, sub-authority count, 6-byte big-endian identifier
 * authority 5, then 32-bit little-endian sub-authorities.
 * `S-1-5-21-a-b-c` + RID -> bytes.
 */
export function sidToBytes(sid: string): Uint8Array {
  const m = /^S-(\d+)-(\d+)-(\d+)((?:-\d+)*)$/.exec(sid);
  if (!m) throw new RangeError(`'${sid}' is not a SID`);
  const revision = Number(m[1]);
  const ia = Number(m[2]);
  const subs = m[4]!.split("-").filter(Boolean).map(Number);
  const out = new Uint8Array(8 + subs.length * 4);
  out[0] = revision;
  out[1] = subs.length;
  // 6-byte big-endian identifier authority
  for (let i = 0; i < 6; i++) out[2 + i] = Math.floor(ia / 2 ** (8 * (5 - i))) & 0xff;
  subs.forEach((s, i) => {
    const off = 8 + i * 4;
    out[off] = s & 0xff;
    out[off + 1] = (s >>> 8) & 0xff;
    out[off + 2] = (s >>> 16) & 0xff;
    out[off + 3] = (s >>> 24) & 0xff;
  });
  return out;
}

export const USER_RID_BASE = 10000; // users.id + this
export const GROUP_RID_BASE = 100000000; // groups.id + this (AD RIDs are 30-bit)

export function objectCategory(kind: "Person" | "Group", baseDn: string): string {
  return `CN=${kind},CN=Schema,CN=Configuration,${baseDn}`;
}

/** SHA-1 based UUIDv5 (RFC 4122 4.3) for stable group GUIDs. */
export async function uuidV5(namespaceUuid: string, name: string): Promise<string> {
  const ns = uuidToGuidBytes(namespaceUuid); // byte order is irrelevant for hashing, just needs 16 bytes
  const data = new Uint8Array(ns.length + new TextEncoder().encode(name).length);
  data.set(ns);
  data.set(new TextEncoder().encode(name), ns.length);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-1", data));
  hash[6] = (hash[6]! & 0x0f) | 0x50; // version 5
  hash[8] = (hash[8]! & 0x3f) | 0x80; // RFC 4122 variant
  const hex = [...hash.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** ISO 8601 -> LDAP GeneralizedTime (YYYYMMDDHHMMSS.0Z). */
export function toGeneralizedTime(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}.0Z`;
}
