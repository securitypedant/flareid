// Seeds a FlareID instance for the OpenID Foundation conformance suite and
// writes the suite's plan config (conformance/suite-config.json, git-ignored).
//
// Idempotent: the two clients and the "conformance" user are upserted, and the
// user gets a fresh random password every run (which also ends its old sessions).
//
//   FLAREID_ISSUER        e.g. https://idp.tmesandbox.com
//   FLAREID_API_KEY       key with clients:write and directory:write
//   CONFORMANCE_SERVER    default https://www.certification.openid.net/
//   CONFORMANCE_ALIAS     default flareid-ci (the suite's callback path uses it)
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";

const issuer = (process.env.FLAREID_ISSUER ?? "").replace(/\/$/, "");
const key = process.env.FLAREID_API_KEY ?? "";
if (!issuer || !key) {
  console.error("FLAREID_ISSUER and FLAREID_API_KEY are required");
  process.exit(2);
}
const suite = (process.env.CONFORMANCE_SERVER ?? "https://www.certification.openid.net/").replace(/\/?$/, "/");
const alias = process.env.CONFORMANCE_ALIAS ?? "flareid-ci";
const base = `${suite}test/a/${alias}/`;

async function api(path, body) {
  const r = await fetch(`${issuer}/api/v1${path}`, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${path}: ${r.status} ${JSON.stringify(j)}`);
  return j;
}

const secret = () => randomBytes(24).toString("base64url");
const clients = [];
for (const n of [1, 2]) {
  const c = { client_id: `conformance-${alias}-${n}`, client_secret: secret() };
  await api("/clients", {
    name: `OIDF conformance (${alias}) ${n}`,
    ...c,
    trusted: true,
    redirect_uris: [`${base}callback`],
    post_logout_redirect_uris: [`${base}post_logout_redirect`],
    frontchannel_logout_uri: `${base}frontchannel_logout`,
  });
  clients.push(c);
}

const password = `Cf-${secret()}`;
const domain = new URL(issuer).hostname;
const imported = await api("/directory/import", {
  version: 1,
  users: [{ username: "conformance", given_name: "Conformance", family_name: "Suite", email: `conformance@${domain}`, status: "active", password }],
});
if (imported.errors?.length) throw new Error(`user import: ${JSON.stringify(imported.errors)}`);
const upn = `conformance@${imported.domain ?? domain}`;

const login = {
  match: `${issuer}/authorize*`,
  tasks: [
    {
      task: "Sign in",
      match: `${issuer}/authorize*`,
      optional: true,
      commands: [
        ["text", "name", "upn", upn],
        ["text", "name", "password", password],
        ["click", "css", "button[type=submit].primary"],
      ],
    },
    // prompt=consent shows the consent screen even for a trusted client.
    { task: "Consent", match: `${issuer}/consent/*`, optional: true, commands: [["click", "css", "button[name=decision][value=allow]"]] },
    { task: "Verify complete", match: `${base}callback*`, commands: [["wait", "id", "submission_complete", 10]] },
  ],
};

const config = {
  alias,
  description: `FlareID ${issuer}`,
  server: { discoveryUrl: `${issuer}/.well-known/openid-configuration` },
  client: { ...clients[0], scope: "openid email profile" },
  client2: { ...clients[1], scope: "openid email profile" },
  client_secret_post: { ...clients[0] },
  browser: [login],
  override: {},
};
writeFileSync(new URL("../conformance/suite-config.json", import.meta.url), JSON.stringify(config, null, 2));
console.log(`seeded ${clients.length} clients and ${upn}; wrote conformance/suite-config.json (alias ${alias})`);
