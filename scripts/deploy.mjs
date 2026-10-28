#!/usr/bin/env node
// Deploys FlareID from a bare clone into a Cloudflare account.
//
//   npm install
//   npx wrangler login          # or set CLOUDFLARE_API_TOKEN
//   npm run deploy
//
// What it does: creates the D1 database and KV namespace, applies the
// migrations, generates an RS256 signing keypair, sets the three secrets,
// decides on an issuer, deploys, and prints the one command you need to
// configure the result.
//
// IT WRITES TO wrangler.jsonc, AND THAT IS DELIBERATE
//
// The account id, the D1 and KV ids, the issuer URL and the signing key's
// public half all end up in that file, because they are what the Worker is
// deployed with and they differ per account. Expect a dirty working tree
// afterwards; it is not a bug.
//
// Configuration, all optional, from the environment:
//   CLOUDFLARE_ACCOUNT_ID      required if your token can see more than one account
//   CLOUDFLARE_API_TOKEN       alternative to `wrangler login`; required for a custom domain
//   ZONE_NAME                  with it, FlareID gets a custom domain at
//                              <FLAREID_SUBDOMAIN>.<ZONE_NAME> and that becomes its issuer
//   FLAREID_SUBDOMAIN          default "idp"
//   FLAREID_ISSUER_URL         set the issuer explicitly, overriding the above
//   FLAREID_WORKER_NAME        default "flareid-idp"
//   FORCE_ROTATE_SIGNING_KEY   "true" to mint a new signing keypair on a redeploy.
//                              Off by default: rotating invalidates every id_token
//                              already issued and every relying party has to refetch
//                              the JWKS.
//
// Token permissions, if you are using one:
//   Account > Workers Scripts > Edit     (deploy, secrets, KV)
//   Account > D1 > Edit
//   Zone > Zone > Read                   } only for the custom domain
//   Zone > DNS > Edit                    }

import { existsSync, readFileSync, rmSync } from "node:fs";
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
const rotateSigningKey = /^(1|true|yes)$/i.test(process.env.FORCE_ROTATE_SIGNING_KEY ?? "");

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
  await applyMigrations(ROOT, DB_NAME);

  log("Secrets");
  await setSecretOnce(ROOT, "COOKIE_ENCRYPTION_KEY", randomBytes(32).toString("hex"), {
    reason: "rotating it signs everyone out",
  });

  // Printed at the end, so it has to be known here. Regenerated on every run
  // when it is missing; left alone when it is already set, because a lab or a
  // CI job may be holding the current value.
  const bootstrapToken = randomBytes(32).toString("hex");
  const bootstrapIsNew = await setSecretOnce(ROOT, "BOOTSTRAP_TOKEN", bootstrapToken, {
    reason: "re-run with it deleted to mint a new one",
  });

  if (rotateSigningKey || !(await hasSecret(ROOT, "SIGNING_KEY_PKCS8"))) {
    detail("generating an RS256 signing keypair...");
    await runOrExit("node", ["scripts/gen-secrets-for-deploy.mjs", "."], { cwd: ROOT }, "signing key generation");

    const keyPath = join(ROOT, ".signing-key.pem");
    const jwkPath = join(ROOT, ".signing-public-jwk.txt");
    await setSecret(ROOT, "SIGNING_KEY_PKCS8", readFileSync(keyPath, "utf8"));
    // Arrives pre-escaped as a JSON string literal, which patchJsonField uses
    // verbatim when it is already quoted.
    patch("SIGNING_PUBLIC_JWK", readFileSync(jwkPath, "utf8").trim());
    patch("SIGNING_KEY_ID", "flareid-key-1");
    rmSync(keyPath, { force: true });
    rmSync(jwkPath, { force: true });
  } else {
    detail("SIGNING_KEY_PKCS8 already set, leaving it (FORCE_ROTATE_SIGNING_KEY=true to rotate)");
  }

  let issuer;
  if (explicitIssuer || zoneName) {
    // The hostname is known before the deploy, so ISSUER_URL can be baked in
    // and the Worker never exists claiming an issuer it is not served from.
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
    // No zone and no explicit issuer, so the issuer is the workers.dev URL -
    // which is not known until after a deploy. Hence two: the first to learn
    // the hostname, the second to bake it in. The issuer in an id_token has to
    // match exactly, and a relying party will reject the token rather than tell
    // you why.
    log("Deploy (first pass, to discover the workers.dev hostname)");
    const workersDevUrl = await deployWorker(ROOT, { quiet: true });
    if (!workersDevUrl) {
      error("The deploy did not report a workers.dev URL, so the issuer cannot be set");
      error("automatically. Set ZONE_NAME or FLAREID_ISSUER_URL and re-run.");
      process.exit(1);
    }
    issuer = workersDevUrl;
    log(`Issuer ${issuer} - deploying again to bake it in`);
    patch("ISSUER_URL", issuer);
    await deployWorker(ROOT);
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
the first administrator with the bootstrap token:

  curl -X POST ${issuer}/api/v1/setup \\
    -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{"domain":"example.com","admin":{"username":"admin"},"complete":true}'

It answers with the generated administrator password. Sign in at
${issuer}/login and go to /admin from there.

The bootstrap token stops working once setup completes, except for the
break-glass route documented in docs/api.md. Mint an ordinary API key from
Admin -> Integrations for anything ongoing.`);

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

  npx wrangler secret delete BOOTSTRAP_TOKEN && npm run deploy`);
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
