import { randomToken } from "../tokens.js";

/**
 * XML serialization for "canonical by construction" signing - see
 * SAML-implementation.md section 5.
 *
 * Everything emitted here is digested by the service provider *after* it has
 * been parsed and re-canonicalized with exclusive C14N, so the bytes we write
 * must already be canonical: attributes sorted (namespace declarations first),
 * C14N escaping (which differs from HTML escaping in both directions), empty
 * elements as start/end pairs, and no whitespace between elements - a text
 * node is part of the digest.
 */

/** Text-node escaping per C14N: `>` is escaped, `"` is not. */
export function escapeXmlText(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\r/g, "&#xD;");
}

/** Attribute-value escaping per C14N: `"` is escaped, `>` is not. */
export function escapeXmlAttr(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/"/g, "&quot;")
    .replace(/\t/g, "&#x9;")
    .replace(/\n/g, "&#xA;")
    .replace(/\r/g, "&#xD;");
}

/**
 * An element with attributes emitted in exclusive-C14N order: namespace
 * declarations first (sorted by prefix), then ordinary attributes sorted by
 * name. Sorting is bytewise (<), not locale-aware - C14N orders on codepoints.
 * `inner` is concatenated verbatim; callers escape text nodes themselves.
 */
export function el(name: string, attrs: Record<string, string | undefined>, inner = ""): string {
  const byCodepoint = ([a]: [string, string], [b]: [string, string]) => (a < b ? -1 : a > b ? 1 : 0);
  const entries = Object.entries(attrs).filter((kv): kv is [string, string] => kv[1] !== undefined);
  const ns = entries.filter(([k]) => k === "xmlns" || k.startsWith("xmlns:")).sort(byCodepoint);
  const rest = entries.filter(([k]) => k !== "xmlns" && !k.startsWith("xmlns:")).sort(byCodepoint);
  const attrStr = [...ns, ...rest].map(([k, v]) => ` ${k}="${escapeXmlAttr(v)}"`).join("");
  return `<${name}${attrStr}>${inner}</${name}>`;
}

/** xsd:dateTime in UTC with no fractional seconds - some service providers reject them. */
export function samlInstant(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** An xsd:ID may not begin with a digit, hence the underscore. */
export function samlId(): string {
  return `_${randomToken(16)}`;
}

export function b64encode(data: string | ArrayBuffer | Uint8Array): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64decode(encoded: string): Uint8Array {
  const bin = atob(encoded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** The DER bytes of a PEM certificate as a single base64 line - what X509Certificate elements and metadata carry. */
export function pemToBase64Der(pem: string): string {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
}
