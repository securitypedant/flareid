import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { TEST_SIGNING_KEY_PKCS8 } from "./test/fixtures/signing-key.js";
import { TEST_SAML_IDP_CERT_PEM, TEST_SAML_IDP_KEY_PKCS8 } from "./test/fixtures/saml-keys.js";

const here = dirname(fileURLToPath(import.meta.url));

// Read once, here, rather than in each test: the migrations are handed to the
// Worker as a binding and applied by test/apply-migrations.ts, so the schema
// under test is the schema that ships - there is no second copy to keep in
// step.
const migrations = await readD1Migrations(resolve(here, "migrations"));

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.test.jsonc" },
      miniflare: {
        // A stand-in SCIM server at https://scim.test, so the provisioning paths
        // can be exercised without the network. Creates answer with an id and
        // everything else succeeds; any other host is passed through.
        outboundService: async (request: Request) => {
          const url = new URL(request.url);
          if (url.hostname !== "scim.test") return fetch(request);
          if (request.method === "POST") {
            return new Response(JSON.stringify({ id: crypto.randomUUID() }), { status: 201, headers: { "Content-Type": "application/scim+json" } });
          }
          if (request.method === "DELETE") return new Response(null, { status: 204 });
          return new Response(JSON.stringify({ Resources: [], totalResults: 0 }), { status: 200, headers: { "Content-Type": "application/scim+json" } });
        },
        bindings: {
          TEST_MIGRATIONS: migrations,
          // Set here rather than in wrangler.test.jsonc because these are
          // secrets in every real deployment, and a committed Worker config is
          // the wrong place for one even when the value is fake.
          SIGNING_KEY_PKCS8: TEST_SIGNING_KEY_PKCS8,
          KEY_ENCRYPTION_KEY: "test-key-encryption-key-not-secret",
          COOKIE_ENCRYPTION_KEY: "test-cookie-key",
          BOOTSTRAP_TOKEN: "test-bootstrap-token",
          SAML_SIGNING_KEY_PKCS8: TEST_SAML_IDP_KEY_PKCS8,
          SAML_SIGNING_CERT: TEST_SAML_IDP_CERT_PEM,
        },
      },
    }),
  ],
  test: {
    setupFiles: ["./test/apply-migrations.ts"],
  },
});
