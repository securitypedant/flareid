#!/usr/bin/env node
// Generates an RS256 keypair to IMPORT as FlareID's first id_token signing key.
// Optional: without one, the Worker generates its RS256 and ES256 keys in D1
// on first use (src/lib/signing-keys.ts), encrypted with KEY_ENCRYPTION_KEY,
// and they are rotated from Admin -> Security - so most deployments never run
// this.
//
// Use it only when the key must exist before the Worker does (to hand its
// public half to a relying party in advance, say):
// - the private key (PKCS8 PEM) as a Worker secret: wrangler secret put SIGNING_KEY_PKCS8
// - the public JWK in wrangler.jsonc vars.SIGNING_PUBLIC_JWK (a JSON string),
//   with vars.SIGNING_KEY_ID as its kid.
// They are read only while D1 holds no RS256 key; after the first import, rotate
// in the console rather than by changing these.

import { generateKeyPair, exportJWK, exportPKCS8 } from "jose";

const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });

const pkcs8Pem = await exportPKCS8(privateKey);
const publicJwk = await exportJWK(publicKey);

console.log("=== Private key (set as a secret) ===");
console.log("wrangler secret put SIGNING_KEY_PKCS8");
console.log("--- paste this when prompted ---");
console.log(pkcs8Pem);

console.log("=== Public JWK (paste into wrangler.jsonc vars.SIGNING_PUBLIC_JWK) ===");
console.log(JSON.stringify(JSON.stringify(publicJwk)));
