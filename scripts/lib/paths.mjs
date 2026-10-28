import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The repository root - two levels up from scripts/lib. */
export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

export const WRANGLER_CONFIG = resolve(ROOT, "wrangler.jsonc");
