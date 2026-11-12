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
// Two outputs, both set as Worker secrets:
//   - the private key (PKCS8 PEM) -> wrangler secret put SAML_SIGNING_KEY_PKCS8
//   - the certificate (PEM)       -> wrangler secret put SAML_SIGNING_CERT
//     The certificate is not confidential - it is embedded in every signed
//     response's KeyInfo and published at /saml/metadata - but keeping it out
//     of wrangler.jsonc keeps that file deployable by anyone as it stands.
//
// Without --out-dir, writes saml-key.pem and saml-cert.pem to a new private
// temporary directory and prints the two commands that set them; delete the
// directory afterwards (the key must not linger on disk).
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

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
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
  // Files rather than paste-at-a-prompt: a multi-line PEM pasted into
  // `wrangler secret put` keeps only its first line in some terminals.
  const dir = mkdtempSync(join(tmpdir(), "flareid-saml-"));
  writeFileSync(join(dir, "saml-key.pem"), keyPem, { mode: 0o600 });
  writeFileSync(join(dir, "saml-cert.pem"), certPem);
  console.log(`Wrote the SAML signing key and certificate to ${dir}. Set both as Worker secrets:

  npx wrangler secret put SAML_SIGNING_KEY_PKCS8 < ${join(dir, "saml-key.pem")}
  npx wrangler secret put SAML_SIGNING_CERT < ${join(dir, "saml-cert.pem")}

(or paste each file's contents into Settings -> Variables and Secrets in the
dashboard), then delete the directory:

  rm -r ${dir}

For local development, put both in .dev.vars instead, as quoted multi-line values.`);
}
