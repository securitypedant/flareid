import type { Env } from "../env.js";

/**
 * AES-256-GCM sealed text under KEY_ENCRYPTION_KEY - the same construction
 * signing-keys.ts uses for private JWKs (v1.<iv>.<ct>, SHA-256 of the key
 * material as the KEK). For values that must be recoverable by the console,
 * like an LDAP app's bind secret; hash-verified secrets keep their hash too.
 */

const b64 = {
  enc: (b: Uint8Array) => btoa(String.fromCharCode(...b)),
  dec: (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

async function kek(env: Env): Promise<CryptoKey | null> {
  const material = env.KEY_ENCRYPTION_KEY || (env.SIGNING_KEY_PKCS8 ? `flareid kek v1\n${env.SIGNING_KEY_PKCS8}` : null);
  if (!material) return null;
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function sealText(env: Env, text: string): Promise<string | null> {
  const key = await kek(env);
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text)));
  return `v1.${b64.enc(iv)}.${b64.enc(ct)}`;
}

export async function unsealText(env: Env, sealed: string): Promise<string | null> {
  const key = await kek(env);
  if (!key) return null;
  const [v, iv, ct] = sealed.split(".");
  if (v !== "v1" || !iv || !ct) return null;
  try {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(iv) }, key, b64.dec(ct));
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

/** Seals when a KEK is configured; plaintext otherwise, so a deployment without key material keeps working. */
export async function sealMaybe(env: Env, value: string): Promise<string> {
  // Empty stays empty - a cleared credential would otherwise store a sealed
  // blob that reads back as a secret.
  if (!value) return value;
  // Idempotent: an already-sealed value (a merged "keep the stored secret"
  // update carries the stored ciphertext through) is left untouched rather
  // than sealed a second time.
  if (value.startsWith("v1.") && (await unsealText(env, value)) !== null) return value;
  return (await sealText(env, value)) ?? value;
}

/**
 * Reads a column that may hold either a sealed `v1.` blob or a plaintext value
 * written before sealing reached it - a lazy migration: the next write seals.
 */
export async function unsealMaybe(env: Env, value: string | null | undefined): Promise<string | null> {
  if (!value) return null;
  if (!value.startsWith("v1.")) return value;
  return unsealText(env, value);
}
