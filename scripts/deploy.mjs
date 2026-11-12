#!/usr/bin/env node
// Deploys FlareID from a bare clone into a Cloudflare account, from a
// terminal - the alternative to the Deploy to Cloudflare button (README).
//
//   npm install
//   npx wrangler login          # or set CLOUDFLARE_API_TOKEN
//   npm run deploy:cli
//
// What it does: creates the D1 database and KV namespace, applies the
// migrations, sets the BOOTSTRAP_TOKEN and KEY_ENCRYPTION_KEY secrets, mints
// a SAML signing key and certificate (both secrets), pins the issuer when it
// is known up front, deploys, and prints where to finish setup.
//
// (`npm run deploy` is the plain migrate-and-deploy the button's Workers
// Builds runs; it creates nothing.)
//
// IT WRITES TO wrangler.jsonc, AND THAT IS DELIBERATE
//
// The D1 and KV ids, the Worker name and - with ZONE_NAME or
// FLAREID_ISSUER_URL - the issuer end up in that file, because they are what
// the Worker is deployed with and they differ per account. Expect a dirty
// working tree afterwards; it is not a bug.
//
// Configuration, all optional, from the environment:
//   CLOUDFLARE_ACCOUNT_ID      required if your token can see more than one account
//   CLOUDFLARE_API_TOKEN       alternative to `wrangler login`; required for a custom domain
//   ZONE_NAME                  with it, FlareID gets a custom domain at
//                              <FLAREID_SUBDOMAIN>.<ZONE_NAME> and that becomes its issuer
//   FLAREID_SUBDOMAIN          default "idp"
//   FLAREID_ISSUER_URL         set the issuer explicitly, overriding the above
//   FLAREID_WORKER_NAME        default "flareid-idp"
//
// Without ZONE_NAME or FLAREID_ISSUER_URL, ISSUER_URL stays empty and the
// issuer is fixed by first-run setup to the origin it is completed on (see
// src/lib/issuer.ts) - so add any custom domain before running setup.
//
// Signing keys are not made here: the Worker generates them in D1 on first
// use, encrypted with KEY_ENCRYPTION_KEY. Rotate them in Admin -> Security.
//
// Token permissions, if you are using one:
//   Account > Workers Scripts > Edit     (deploy, secrets, KV)
//   Account > D1 > Edit
//   Zone > Zone > Read                   } only for the custom domain
//   Zone > DNS > Edit                    }

import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { ROOT, WRANGLER_CONFIG } from "./lib/paths.mjs";
import { blank, detail, error, lines, log, warn } from "./lib/log.mjs";
import { runOrExit } from "./lib/run.mjs";
import {
  applyMigrations,
  deployWorker,
  ensureD1,
  ensureKv,
  hasSecret,
  patchJsonField,
  setSecret,
  setSecretOnce,
} from "./lib/wrangler.mjs";

const accountId = process.env.CLOUDFLARE_ACCOUNT_ID ?? "";
const apiToken = process.env.CLOUDFLARE_API_TOKEN ?? "";
const zoneName = process.env.ZONE_NAME ?? "";
const subdomain = process.env.FLAREID_SUBDOMAIN || "idp";
const workerName = process.env.FLAREID_WORKER_NAME || "flareid-idp";
const explicitIssuer = process.env.FLAREID_ISSUER_URL ?? "";

const DB_NAME = "flareid-db";
const KV_NAME = "flareid-idp-sessions";

/** Patches wrangler.jsonc, exiting if the field is not there to patch. */
function patch(field, value, occurrence = 0) {
  if (!patchJsonField(WRANGLER_CONFIG, field, value, occurrence)) {
    error(`Field "${field}" (occurrence ${occurrence}) not found in ${WRANGLER_CONFIG}.`);
    error("Has wrangler.jsonc been edited into a shape this script no longer recognises?");
    process.exit(1);
  }
}

async function cfApi(path, { method = "GET", body } = {}) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers: { Authorization: `Bearer ${apiToken}`, "Content-Type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  try {
    return await response.json();
  } catch {
    return { success: false, errors: [{ message: `HTTP ${response.status}` }] };
  }
}

/**
 * Attaches the custom domain.
 *
 * Returns false rather than exiting: a deployed IdP on a workers.dev hostname
 * is still a working IdP, so this is worth reporting and carrying on from.
 */
async function attachCustomDomain(hostname) {
  if (!apiToken) {
    warn("CLOUDFLARE_API_TOKEN is not set, so the custom domain cannot be attached.");
    warn(`Attach it by hand (Workers & Pages > ${workerName} > Settings > Domains & Routes >`);
    warn("Add Custom Domain), or re-run with a token.");
    return false;
  }
  if (!accountId) {
    warn("CLOUDFLARE_ACCOUNT_ID is not set, so the custom domain cannot be attached.");
    return false;
  }

  const zones = await cfApi(`/zones?name=${encodeURIComponent(zoneName)}`);
  const zone = zones.success ? (zones.result ?? []).find((z) => z.name === zoneName) : undefined;
  if (!zone) {
    error(`No zone named '${zoneName}' in this account, or the token cannot read zones.`);
    return false;
  }

  const attached = await cfApi(`/accounts/${accountId}/workers/domains/records`, {
    method: "PUT",
    body: { hostname, service: workerName, environment: "production", zone_id: zone.id },
  });
  if (attached.success) {
    detail("attached");
    return true;
  }

  // Only benign if it is already attached to this same Worker, so check rather
  // than pattern-matching the error message - "already has externally managed
  // DNS records" reads like success and is not.
  const records = await cfApi(`/accounts/${accountId}/workers/domains/records`);
  const existing = records.success ? (records.result ?? []).find((r) => r.hostname === hostname) : undefined;
  if (existing?.service === workerName) {
    detail(`already attached to ${workerName}, leaving as-is`);
    return true;
  }

  error(`Could not attach ${hostname}:`);
  console.error(JSON.stringify(attached.errors ?? attached, null, 2));
  if (existing?.service) error(`(it is currently attached to '${existing.service}')`);
  return false;
}

async function main() {
  if (!existsSync(join(ROOT, "package.json"))) {
    error("Run this from the FlareID repository (scripts/deploy.mjs).");
    process.exit(1);
  }

  if (accountId) process.env.CLOUDFLARE_ACCOUNT_ID = accountId;

  log("Typecheck");
  await runOrExit("npm", ["run", "typecheck"], { cwd: ROOT }, "typecheck");

  log("Worker name, D1 and KV");
  patch("name", workerName);
  patch("database_id", await ensureD1(ROOT, DB_NAME));
  patch("id", await ensureKv(ROOT, KV_NAME));

  log("Migrations");
  // By binding name, as the deploy script does: the database's name may differ.
  await applyMigrations(ROOT, "DB");

  log("Secrets");
  // Encrypts the signing keys in D1, so it must never change once keys exist.
  // A deployment that already has SIGNING_KEY_PKCS8 encrypted its keys with a
  // key derived from that instead (signing-keys.ts); adding this now would
  // make them unreadable, so it is only ever set on a fresh install.
  if (!(await hasSecret(ROOT, "KEY_ENCRYPTION_KEY")) && !(await hasSecret(ROOT, "SIGNING_KEY_PKCS8"))) {
    await setSecret(ROOT, "KEY_ENCRYPTION_KEY", randomBytes(48).toString("base64"));
  } else {
    detail("KEY_ENCRYPTION_KEY (or SIGNING_KEY_PKCS8) already set, leaving it - it must never change");
  }

  // Printed at the end, so it has to be known here. Regenerated on every run
  // when it is missing; left alone when it is already set, because a lab or a
  // CI job may be holding the current value.
  const bootstrapToken = randomBytes(32).toString("hex");
  const bootstrapIsNew = await setSecretOnce(ROOT, "BOOTSTRAP_TOKEN", bootstrapToken, {
    reason: "re-run with it deleted to mint a new one",
  });

  // Private keys are generated into a private temporary directory outside the
  // repository and removed on every exit path - including the process.exit()
  // calls in setSecret/patch, which skip finally blocks, hence the exit hook.
  // They used to be written to the repo root and deleted only on success, so a
  // failed deploy could leave the live SAML signing key in the working tree.
  const keyDir = mkdtempSync(join(tmpdir(), "flareid-keys-"));
  const removeKeys = () => rmSync(keyDir, { recursive: true, force: true });
  process.on("exit", removeKeys);

  // SAML needs a certificate, not just a keypair: service providers consume a
  // cert, and it is embedded in every signed response's KeyInfo. Minted once
  // and left alone afterwards - rotating breaks SAML logins until every SP is
  // updated, so there is deliberately no FORCE_ROTATE flag here.
  //
  // Both halves are secrets, so wrangler.jsonc carries nothing per-deployment.
  // The key is set last because its presence is what a re-run takes to mean
  // "done": a failure in between regenerates both.
  if (!(await hasSecret(ROOT, "SAML_SIGNING_KEY_PKCS8"))) {
    detail("generating a SAML signing certificate (RSA-3072, 10y)...");
    await runOrExit("node", ["scripts/generate-saml-cert.mjs", "--out-dir", keyDir], { cwd: ROOT }, "SAML certificate generation");

    const samlKeyPath = join(keyDir, ".saml-key.pem");
    const samlCertPath = join(keyDir, ".saml-cert.pem");
    await setSecret(ROOT, "SAML_SIGNING_CERT", readFileSync(samlCertPath, "utf8").trim());
    await setSecret(ROOT, "SAML_SIGNING_KEY_PKCS8", readFileSync(samlKeyPath, "utf8"));
  } else if (!(await hasSecret(ROOT, "SAML_SIGNING_CERT"))) {
    warn("SAML_SIGNING_KEY_PKCS8 is set but the SAML_SIGNING_CERT secret is not, so SAML answers 503.");
    warn("Set the matching certificate: npx wrangler secret put SAML_SIGNING_CERT < saml-cert.pem");
  } else {
    detail("SAML_SIGNING_KEY_PKCS8 and SAML_SIGNING_CERT already set, leaving them");
  }

  let issuer;
  if (explicitIssuer || zoneName) {
    // The hostname is known before the deploy, so ISSUER_URL is pinned and the
    // Worker never exists claiming an issuer it is not served from.
    issuer = explicitIssuer || `https://${subdomain}.${zoneName}`;
    log(`Issuer ${issuer}`);
    patch("ISSUER_URL", issuer);

    log("Deploy");
    await deployWorker(ROOT);

    if (zoneName && !explicitIssuer) {
      log(`Custom domain: ${subdomain}.${zoneName} -> ${workerName}`);
      await attachCustomDomain(`${subdomain}.${zoneName}`);
    }
  } else {
    // No zone and no explicit issuer: ISSUER_URL stays empty and setup fixes
    // the issuer to the workers.dev origin it is completed on.
    log("Deploy");
    issuer = await deployWorker(ROOT);
    if (!issuer) {
      warn("The deploy did not report a workers.dev URL. Open /setup on whichever hostname serves the Worker.");
      issuer = "https://<your-worker>.<your-subdomain>.workers.dev";
    }
  }

  summary(issuer, bootstrapIsNew ? bootstrapToken : null);
}

function summary(issuer, bootstrapToken) {
  blank();
  lines(`======================================================================
FlareID is deployed at ${issuer}
======================================================================

OIDC endpoints:
  discovery   ${issuer}/.well-known/openid-configuration
  jwks        ${issuer}/jwks.json
  authorize   ${issuer}/authorize
  token       ${issuer}/token
  userinfo    ${issuer}/userinfo

There are no users yet, and no default password - that is deliberate. Create
the first administrator in a browser, with the bootstrap token below:

  ${issuer}/setup

or over the API:

  curl -X POST ${issuer}/api/v1/setup \\
    -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{"domain":"example.com","admin":{"username":"admin"},"complete":true}'

(which answers with a generated administrator password). Then sign in at
${issuer}/login; an administrator is made to enrol a second factor first.

Completing setup fixes the issuer to the address it was completed on, unless
ISSUER_URL is pinned in wrangler.jsonc. The bootstrap token stops working once
setup completes, except for the break-glass route documented in docs/api.md.
Mint an ordinary API key from Admin -> Integrations for anything ongoing.`);

  if (bootstrapToken) {
    blank();
    lines(`----------------------------------------------------------------------
BOOTSTRAP_TOKEN (shown once - it is a Worker secret from here on)

  ${bootstrapToken}
----------------------------------------------------------------------`);
  } else {
    blank();
    lines(`BOOTSTRAP_TOKEN was already set, so it is not reprinted - a secret cannot
be read back out of a Worker. If you no longer have it:

  npx wrangler secret delete BOOTSTRAP_TOKEN && npm run deploy:cli`);
  }

  if (!zoneName && !explicitIssuer) {
    blank();
    lines(`----------------------------------------------------------------------
One thing to check, because it is silent when it bites. Some accounts have
Access or Gateway protection over all *.workers.dev hostnames, which answers
unauthenticated requests with 'error code: 1050'. That is fatal for an IdP:
browsers and relying parties have to reach it BEFORE they are authenticated,
so it fails in the middle of a login rather than at deploy time.

Open ${issuer}/.well-known/openid-configuration in a private window now.
JSON means you are fine. If you get 1050, either add an Access bypass policy
for this hostname, or re-run with ZONE_NAME set to put it on a custom domain.
----------------------------------------------------------------------`);
  }
}

await main();
