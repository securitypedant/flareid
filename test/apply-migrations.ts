import { applyD1Migrations, env } from "cloudflare:test";

// Runs once per test file, before any test in it. The migrations arrive as a
// binding from vitest.config.ts, which means the schema under test is the
// schema that ships - there is no second copy to keep in step.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
