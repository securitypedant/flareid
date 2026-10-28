#!/usr/bin/env node
// Generates the RS256 signing keypair for FlareID's id_tokens.
// Run once (and again to rotate): node scripts/generate-keypair.mjs
//
// - The private key (PKCS8 PEM) must be set as a Worker secret:
//     wrangler secret put SIGNING_KEY_PKCS8
// - The public key (JWK) is NOT secret - paste it into wrangler.jsonc's
//   `vars.SIGNING_PUBLIC_JWK` (as a JSON string) so /jwks.json can serve it
//   without needing to touch the private key at request time.
//
// To ROTATE without breaking in-flight tokens (they're short-lived, ~10m):
//   1. Copy the CURRENT vars.SIGNING_PUBLIC_JWK / vars.SIGNING_KEY_ID into
//      vars.SIGNING_PUBLIC_JWK_PREVIOUS / vars.SIGNING_KEY_ID_PREVIOUS.
//   2. Run this script again, set the new private key as SIGNING_KEY_PKCS8,
//      and put the new public JWK in vars.SIGNING_PUBLIC_JWK.
//   3. Bump vars.SIGNING_KEY_ID to a new value (e.g. flareid-key-2).
//   4. Deploy. /jwks.json now publishes both keys, so tokens signed with the
//      old key right before the rotation still verify until they expire.
//   5. After a safe window (a few hours is plenty given ~10m token expiry),
//      remove SIGNING_PUBLIC_JWK_PREVIOUS / SIGNING_KEY_ID_PREVIOUS and deploy again.

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
