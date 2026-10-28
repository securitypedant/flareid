import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { TEST_SIGNING_KEY_PKCS8 } from "./test/fixtures/signing-key.js";

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
        bindings: {
          TEST_MIGRATIONS: migrations,
          // Set here rather than in wrangler.test.jsonc because these are
          // secrets in every real deployment, and a committed Worker config is
          // the wrong place for one even when the value is fake.
          SIGNING_KEY_PKCS8: TEST_SIGNING_KEY_PKCS8,
          COOKIE_ENCRYPTION_KEY: "test-cookie-key",
          BOOTSTRAP_TOKEN: "test-bootstrap-token",
        },
      },
    }),
  ],
  test: {
    setupFiles: ["./test/apply-migrations.ts"],
  },
});
