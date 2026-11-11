// A software WebAuthn authenticator for tests: P-256, "none" attestation,
// origin https://idp.test (the test issuer).
import { BASE } from "../helpers.js";

const enc = new TextEncoder();
export const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
};
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

// Minimal CBOR: unsigned/negative ints, byte strings, text strings, maps.
function cbor(v: unknown): Uint8Array {
  const head = (major: number, n: number) =>
    n < 24 ? Uint8Array.of((major << 5) | n) : n < 256 ? Uint8Array.of((major << 5) | 24, n) : Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (typeof v === "string") return concat(head(3, enc.encode(v).length), enc.encode(v));
  const entries = v instanceof Map ? [...v.entries()] : Object.entries(v as object);
  return concat(head(5, entries.length), ...entries.flatMap(([k, val]) => [cbor(k), cbor(val)]));
}

function derSig(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0]! & 0x80) v = concat(Uint8Array.of(0), v);
    return concat(Uint8Array.of(0x02, v.length), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

export class SoftAuthenticator {
  credId = crypto.getRandomValues(new Uint8Array(16));
  counter = 0;
  keys!: CryptoKeyPair;
  async init() {
    this.keys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    return this;
  }
  async register(challenge: string) {
    const jwk = (await crypto.subtle.exportKey("jwk", this.keys.publicKey)) as JsonWebKey;
    const cose = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, fromB64u(jwk.x!)], [-3, fromB64u(jwk.y!)]]));
    const authData = concat(await sha256(enc.encode("idp.test")), Uint8Array.of(0x45), new Uint8Array(4), new Uint8Array(16), Uint8Array.of(0, 16), this.credId, cose);
    const clientDataJSON = enc.encode(JSON.stringify({ type: "webauthn.create", challenge, origin: BASE, crossOrigin: false }));
    return {
      id: b64u(this.credId), rawId: b64u(this.credId), type: "public-key", clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(cbor({ fmt: "none", attStmt: {}, authData })), transports: ["internal"] },
    };
  }
  async assert(challenge: string, counter = ++this.counter) {
    const authData = concat(await sha256(enc.encode("idp.test")), Uint8Array.of(0x05), Uint8Array.of(counter >>> 24, (counter >> 16) & 255, (counter >> 8) & 255, counter & 255));
    const clientDataJSON = enc.encode(JSON.stringify({ type: "webauthn.get", challenge, origin: BASE, crossOrigin: false }));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.keys.privateKey, concat(authData, await sha256(clientDataJSON))));
    return {
      id: b64u(this.credId), rawId: b64u(this.credId), type: "public-key", clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(derSig(raw)) },
    };
  }
}

