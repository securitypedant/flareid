// RFC 6238 TOTP for tests (SHA-1, 30 s, 6 digits).
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export async function totp(secret: string, at = Date.now()): Promise<string> {
  let bits = "";
  for (const ch of secret.toUpperCase()) {
    const v = B32.indexOf(ch);
    if (v >= 0) bits += v.toString(2).padStart(5, "0");
  }
  const key = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < key.length; i++) key[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  const counter = new Uint8Array(8);
  let v = Math.floor(at / 30000);
  for (let i = 7; i >= 0; i--) {
    counter[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", k, counter));
  const o = d[d.length - 1]! & 0x0f;
  const n = ((d[o]! & 0x7f) << 24) | (d[o + 1]! << 16) | (d[o + 2]! << 8) | d[o + 3]!;
  return String(n % 1e6).padStart(6, "0");
}
