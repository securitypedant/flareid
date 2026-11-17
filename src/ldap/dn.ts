/**
 * Distinguished Name handling, RFC 4514 (LDAP.md section 6).
 *
 * A DN is a list of RDNs; we support only single-attribute RDNs
 * (`uid=alice`), not multi-valued `cn=a+uid=b` - nothing in our tree needs
 * them, and a multi-valued RDN in a client's base DN is a parse error rather
 * than silently treated as one attribute.
 *
 * Comparison is on the normalised form: attribute types lowercased, values
 * compared case-insensitively with insignificant spaces removed and escapes
 * resolved.
 */

export interface Rdn {
  type: string; // lowercased
  value: string; // unescaped, original case
}

export class DnError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DnError";
  }
}

const ESCAPABLE = new Set(['"', "+", ",", ";", "<", ">", "=", "\\"]);

/** Parse a DN string into RDNs, outermost first (`uid=alice` at index 0). Empty string -> []. */
export function parseDn(dn: string): Rdn[] {
  const rdns: Rdn[] = [];
  let i = 0;
  const n = dn.length;
  if (n === 0) return rdns;

  while (i < n) {
    // attribute type: OID (1.2.3) or alpha-led name
    const typeStart = i;
    if (dn[i]! >= "0" && dn[i]! <= "9") {
      while (i < n && /[\d.]/.test(dn[i]!)) i++;
    } else {
      if (!/[A-Za-z]/.test(dn[i]!)) throw new DnError(`bad attribute type in '${dn}'`);
      while (i < n && /[A-Za-z0-9-]/.test(dn[i]!)) i++;
    }
    const type = dn.slice(typeStart, i).toLowerCase();
    while (i < n && dn[i] === " ") i++;
    if (dn[i] !== "=") throw new DnError(`missing '=' in '${dn}'`);
    i++;
    while (i < n && dn[i] === " ") i++;

    // value: until unescaped ',' (or ';' tolerated per RFC 4514 note)
    let value = "";
    if (dn[i] === "#") {
      // BER-encoded value: hex pairs. We can't turn them back into a DN
      // attribute value without a schema - accept and keep the raw form.
      i++;
      const hs = i;
      while (i < n && /[0-9a-fA-F]/.test(dn[i]!)) i++;
      if ((i - hs) % 2 !== 0 || i === hs) throw new DnError(`bad #-value in '${dn}'`);
      value = "#" + dn.slice(hs, i);
    } else {
      let quoted = false;
      if (dn[i] === '"') {
        quoted = true;
        i++;
      }
      let val = "";
      for (;;) {
        if (i >= n) {
          if (quoted) throw new DnError(`unterminated quote in '${dn}'`);
          break;
        }
        const ch = dn[i]!;
        if (quoted) {
          if (ch === '"') {
            i++;
            break;
          }
        } else if (ch === "," || ch === ";") {
          break;
        } else if (ch === "+") {
          throw new DnError(`multi-valued RDNs are not supported ('${dn}')`);
        }
        if (ch === "\\") {
          if (i + 1 >= n) throw new DnError(`trailing backslash in '${dn}'`);
          const next = dn[i + 1]!;
          if (/[0-9a-fA-F]/.test(next) && i + 2 < n && /[0-9a-fA-F]/.test(dn[i + 2]!)) {
            val += String.fromCharCode(parseInt(dn.slice(i + 1, i + 3), 16));
            i += 3;
            continue;
          }
          if (!ESCAPABLE.has(next) && next !== "#" && next !== " ") throw new DnError(`bad escape '\\${next}' in '${dn}'`);
          val += next;
          i += 2;
          continue;
        }
        val += ch;
        i++;
      }
      if (!quoted) val = val.replace(/ +$/, "").replace(/^ +/, ""); // strip insignificant edge spaces
      value = val;
    }
    rdns.push({ type, value });
    while (i < n && dn[i] === " ") i++;
    if (i < n) {
      if (dn[i] !== "," && dn[i] !== ";") throw new DnError(`expected ',' in '${dn}'`);
      i++;
      while (i < n && dn[i] === " ") i++;
      if (i >= n) throw new DnError(`trailing ',' in '${dn}'`);
    }
  }
  return rdns;
}

/** Case-folded, space-collapsed value for equality comparison. */
export function normalizeValue(v: string): string {
  if (v.startsWith("#")) return v.toLowerCase();
  return v.trim().replace(/ +/g, " ").toLowerCase();
}

/** Two RDN lists equal? (Case-insensitive values, normalised spaces.) */
export function dnEquals(a: Rdn[], b: Rdn[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((r, i) => r.type === b[i]!.type && normalizeValue(r.value) === normalizeValue(b[i]!.value));
}

/** Is `candidate` inside (or equal to) the subtree rooted at `base`? */
export function dnWithin(candidate: Rdn[], base: Rdn[]): boolean {
  if (base.length > candidate.length) return false;
  const tail = candidate.slice(candidate.length - base.length);
  return dnEquals(tail, base);
}

/** The entry `n` levels below its subtree root's base: drop the leading RDNs. */
export function dnDropRdns(dn: Rdn[], n: number): Rdn[] {
  return dn.slice(n);
}

/** Escape a value for embedding in a DN (RFC 4514 section 2.4). */
export function escapeDnValue(v: string): string {
  let out = "";
  for (const ch of v) {
    if (ch === " " && (out === "" )) {
      out += "\\ ";
      continue;
    }
    if (ESCAPABLE.has(ch)) out += "\\" + ch;
    else out += ch;
  }
  if (out.endsWith(" ")) out = out.slice(0, -1) + "\\ ";
  if (out.startsWith("#")) out = "\\" + out;
  return out;
}

/** Render RDNs back to a canonical DN string. */
export function formatDn(rdns: Rdn[]): string {
  return rdns.map((r) => `${r.type}=${escapeDnValue(r.value)}`).join(",");
}
