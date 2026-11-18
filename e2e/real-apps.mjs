// Seeds the e2e instance for the real-app lab (e2e/compose.yml): users,
// groups, one OIDC client per app, and the SAML SP registration. Writes the
// per-app env/config files into e2e/state/ that compose consumes.
//
//   node e2e/real-apps.mjs            # seed everything
//   BASE=http://localhost:8787 node e2e/real-apps.mjs
//
// Idempotent: re-running upserts clients (same client_id each run gets a new
// secret, so state files are always rewritten).

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = (process.env.BASE ?? "http://localhost:8787").replace(/\/$/, "");
const BOOTSTRAP = process.env.BOOTSTRAP_TOKEN ?? "e2e-bootstrap-token";
const STATE = join(dirname(fileURLToPath(import.meta.url)), "state");
const PW = "Lab-User-Pw-4";

async function api(path, key, { method = "GET", body } = {}) {
  const r = await fetch(`${BASE}/api/v1${path}`, {
    method,
    headers: { Authorization: `Bearer ${key}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${JSON.stringify(j)}`);
  return j;
}

async function apiKey() {
  // Reuse a saved key when the instance is already set up.
  const saved = join(STATE, "lab-key.json");
  try { return JSON.parse(readFileSync(saved, "utf8")).key; } catch { /* fresh */ }
  const minted = await api("/api-keys", BOOTSTRAP, { method: "POST", body: { name: "e2e-lab", scopes: ["*"] } });
  await api("/setup", minted.token, {
    method: "POST",
    body: { domain: "example.com", admin: { username: "admin", password: PW, display_name: "Lab Admin" }, require_mfa: false, admin_mfa: false, complete: true },
  });
  mkdirSync(STATE, { recursive: true });
  writeFileSync(saved, JSON.stringify({ key: minted.token }));
  console.log(`admin password for the lab: ${PW}`);
  return minted.token;
}

const key = await apiKey();

// -- Users and groups ---------------------------------------------------------
for (const u of [
  { username: "ada", given_name: "Ada", family_name: "Chen", email: "ada@example.com" },
  { username: "grace", given_name: "Grace", family_name: "Hopper", email: "grace@example.com" },
  { username: "linus", given_name: "Linus", family_name: "Torvalds", email: "linus@example.com" },
]) {
  try {
    await api("/users", key, { method: "POST", body: { ...u, password: PW, status: "active" } });
  } catch (e) { if (!String(e).includes("409")) throw e; }
}
const groups = await api("/groups", key);
const gid = (name) => groups.groups.find((g) => g.name === name)?.id;
for (const g of ["Grafana Admins", "Engineering", "BookStack Editors"]) {
  if (!gid(g)) await api("/groups", key, { method: "POST", body: { name: g } });
}
const fresh = await api("/groups", key);
const fg = (name) => fresh.groups.find((g) => g.name === name)?.id;
const put = (g, users) => api(`/groups/${g}/members`, key, { method: "POST", body: { usernames: users } }).catch(() => {});
await put(fg("Grafana Admins"), ["grace"]);
await put(fg("Engineering"), ["ada", "linus"]);
await put(fg("BookStack Editors"), ["ada"]);

// -- OIDC clients --------------------------------------------------------------
async function client(name, redirectUris) {
  const cid = `lab-${name.replace(/[^a-z0-9]/gi, "-").toLowerCase()}`;
  const secret = `lab-${cryptoRandom()}`;
  const j = await api("/clients", key, {
    method: "POST",
    body: { name, client_id: cid, client_secret: secret, redirect_uris: redirectUris, trusted: true },
  });
  return j.client_id ? { id: cid, secret } : { id: cid, secret };
}
function cryptoRandom() {
  return [...crypto.getRandomValues(new Uint8Array(18))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const o2p = await client("oauth2-proxy", ["http://localhost:4180/oauth2/callback"]);
const gra = await client("Grafana", ["http://localhost:3000/login/generic_oauth"]);
const bks = await client("BookStack", ["http://localhost:6875/oidc/callback"]);

writeFileSync(join(STATE, "oauth2-proxy.env"), `OAUTH2_PROXY_CLIENT_ID=${o2p.id}\nOAUTH2_PROXY_CLIENT_SECRET=${o2p.secret}\n`);
writeFileSync(join(STATE, "grafana.env"), `GF_AUTH_GENERIC_OAUTH_CLIENT_ID=${gra.id}\nGF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=${gra.secret}\n`);
writeFileSync(join(STATE, "bookstack.env"), `OIDC_CLIENT_ID=${bks.id}\nOIDC_CLIENT_SECRET=${bks.secret}\n`);

// -- SAML -----------------------------------------------------------------------
// Register SimpleSAMLphp's SP and write its config. ACS is the caddy https
// endpoint (FlareID requires https ACS URLs).
const SSP_ENTITY = "https://simplesamlphp.lab/sp";
try {
  await api("/saml/service-providers", key, {
    method: "POST",
    body: { entity_id: SSP_ENTITY, name: "SimpleSAMLphp (lab)", acs_urls: ["https://localhost:8443/simplesaml/module.php/saml/sp/saml2-acs.php/flareid"], default_acs_url: "https://localhost:8443/simplesaml/module.php/saml/sp/saml2-acs.php/flareid" },
  });
  console.log("registered SimpleSAMLphp SP (serve it https via the caddy profile)");
} catch (e) {
  console.log(`SAML SP registration skipped: ${e.message}`);
}

mkdirSync(join(STATE, "simplesamlphp"), { recursive: true });
writeFileSync(join(STATE, "Caddyfile"), `{
	auto_https disable_redirects
}
https://localhost:8443 {
	tls internal
	reverse_proxy simplesamlphp:80
}
`);
writeFileSync(join(STATE, "simplesamlphp", "authsources.php"), `<?php
$config = [
    'default-sp' => ['saml:SP', 'entityID' => '${SSP_ENTITY}', 'idp' => '${BASE}', 'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    'flareid' => ['saml:SP', 'entityID' => '${SSP_ENTITY}', 'idp' => '${BASE}'],
];
`);
// SimpleSAMLphp wants the IdP as a PHP array + a PEM in its cert dir.
const idpCert = await fetch(`${BASE}/saml/cert.pem`).then(async (r) => (r.ok ? await r.text() : null)).catch(() => null);
if (idpCert) {
  writeFileSync(join(STATE, "simplesamlphp", "flareid-signing.pem"), idpCert);
  writeFileSync(join(STATE, "simplesamlphp", "saml20-idp-remote.php"), `<?php
$metadata['${BASE}'] = [
    'entityid' => '${BASE}',
    'SingleSignOnService' => '${BASE}/saml/sso',
    'SingleLogoutService' => '${BASE}/saml/slo',
    'certificate' => 'flareid-signing.pem',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
];
`);
} else {
  writeFileSync(join(STATE, "simplesamlphp", "saml20-idp-remote.php"), `<?php
// FlareID answered /saml/cert.pem without a cert: SAML secrets are not set.
// Generate them (npm run saml:keygen, or openssl) and pass SAML_SIGNING_CERT /
// SAML_SIGNING_KEY_PKCS8 to the flareid service, then re-run this seed.
`);
}

console.log(`\nSeeded lab users: ada, grace, linus (password ${PW})`);
console.log(`Wrote client config to ${STATE}/{oauth2-proxy,grafana,bookstack}.env`);
console.log("SAML config under e2e/state/ - enable with --profile saml\n");
