import type { D1Migration } from "@cloudflare/vitest-plugin";
import type { Env as WorkerEnv } from "../src/env.js";

// Tells `cloudflare:test` what its `env` actually holds. The plugin types it as
// `Cloudflare.Env`, the global interface `wrangler types` would normally
// generate, so that is what has to be augmented - FlareID declares its bindings
// by hand in src/env.ts instead, and this is where the two meet.
//
// `declare global` is needed because the imports above make this file a module,
// and a bare `declare namespace` in a module is module-scoped.
declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      /** The migration list, handed in as a binding by vitest.config.ts. */
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}
