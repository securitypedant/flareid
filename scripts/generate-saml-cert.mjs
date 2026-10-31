#!/usr/bin/env node
// Generates the RSA signing keypair and self-signed X.509 certificate FlareID
// uses to sign SAML responses and assertions.
//
// Run once (and again to rotate): node scripts/generate-saml-cert.mjs
//
// Certificate generation cannot happen inside the Worker - Workers (and
// node:crypto everywhere) can consume X.509 but not mint it - so this is an
// offline step, exactly like scripts/generate-keypair.mjs for the OIDC key.
//
// Two outputs:
//   - the private key (PKCS8 PEM) -> wrangler secret put SAML_SIGNING_KEY_PKCS8
//   - the certificate (PEM)       -> wrangler.jsonc vars.SAML_SIGNING_CERT
//     It is NOT a secret: it is embedded in every signed response's KeyInfo
//     and published at /saml/metadata.
//
// With --out-dir <dir>, writes machine-readable files instead of printing, for
// scripts/deploy.mjs:
//   <dir>/.saml-key.pem   - PKCS8 private key PEM
//   <dir>/.saml-cert.pem  - certificate PEM
//
// NOTE on expiry: the certificate is minted valid for 10 years. When it
// expires every SAML login breaks until it is regenerated and the SPs are
// updated - the admin UI warns 30 days out.
//
// Uses node-forge (a devDependency): it never ships to the Worker, it is a
// build-time tool only.

import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import forge from "node-forge";

const outDir = process.argv.indexOf("--out-dir") !== -1 ? process.argv[process.argv.indexOf("--out-dir") + 1] : null;
const VALID_YEARS = 10;

const keys = forge.pki.rsa.generateKeyPair(3072);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = "01";
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + VALID_YEARS);
const attrs = [{ name: "commonName", value: "FlareID SAML signing" }];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.sign(keys.privateKey, forge.md.sha256.create());

const certPem = forge.pki.certificateToPem(cert);
// wrapRsaPrivateKey converts the PKCS#1 RSAPrivateKey into a PKCS#8
// PrivateKeyInfo - the format Web Crypto's importPKCS8 expects.
const keyPem = forge.pki.privateKeyInfoToPem(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keys.privateKey)));

if (outDir) {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, ".saml-key.pem"), keyPem);
  writeFileSync(resolve(outDir, ".saml-cert.pem"), certPem);
} else {
  console.log("=== Private key (set as a secret) ===");
  console.log("wrangler secret put SAML_SIGNING_KEY_PKCS8");
  console.log("--- paste this when prompted ---");
  console.log(keyPem);

  console.log("=== Certificate (paste into wrangler.jsonc vars.SAML_SIGNING_CERT) ===");
  console.log(JSON.stringify(certPem));
}
