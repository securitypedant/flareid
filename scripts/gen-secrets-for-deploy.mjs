#!/usr/bin/env node
// Machine-readable variant of generate-keypair.mjs, for deploy-all.mjs: generates
// a fresh RS256 signing keypair and writes the two pieces the script needs as
// plain files instead of human-oriented console output.
//
// Usage: node scripts/gen-secrets-for-deploy.mjs <outputDir>
//   <outputDir>/.signing-key.pem           - PKCS8 private key PEM (set as SIGNING_KEY_PKCS8 secret)
//   <outputDir>/.signing-public-jwk.txt    - double-JSON-encoded public JWK, ready to paste
//                                            as-is into wrangler.jsonc's SIGNING_PUBLIC_JWK value

import { generateKeyPair, exportJWK, exportPKCS8 } from "jose";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const outDir = process.argv[2] || ".";

const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
const pkcs8Pem = await exportPKCS8(privateKey);
const publicJwk = await exportJWK(publicKey);

writeFileSync(resolve(outDir, ".signing-key.pem"), pkcs8Pem);
// Double-encoded: this is a valid JSON *string literal* (with surrounding quotes
// and inner quotes escaped) ready to drop straight into wrangler.jsonc as-is.
writeFileSync(resolve(outDir, ".signing-public-jwk.txt"), JSON.stringify(JSON.stringify(publicJwk)));

console.log(`Wrote ${outDir}/.signing-key.pem and ${outDir}/.signing-public-jwk.txt`);
