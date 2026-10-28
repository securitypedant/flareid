// Subprocess helpers, for the one external program this needs: wrangler. There
// is no API that replaces it - it builds and uploads Workers, applies D1
// migrations and manages secrets.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { ROOT } from "./paths.mjs";

/**
 * Runs a command, streaming its output, and resolves with its exit code.
 *
 * `shell: false`, always: passing an argv array removes every question about
 * quoting, and with it the class of bug where a value containing a space breaks
 * a command.
 *
 * stdin is never inherited. Capturing output while a child prompts hides the
 * prompt from view but still blocks on it, so a script can hang on something
 * invisible; "ignore" makes that impossible.
 */
export function run(command, args = [], { cwd = ROOT, env = {}, quiet = false, input } = {}) {
  return new Promise((resolvePromise) => {
    const stdin = input === undefined ? "ignore" : "pipe";
    const child = spawn(resolveCommand(command, cwd), args, {
      cwd,
      env: { ...process.env, CI: "true", ...env },
      stdio: quiet ? [stdin, "pipe", "pipe"] : [stdin, "inherit", "inherit"],
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    if (quiet) {
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
    }

    if (input !== undefined) {
      // No trailing newline is added - wrangler would store it as part of the
      // secret.
      child.stdin.on("error", () => {});
      child.stdin.end(input);
    }

    child.on("error", (err) => resolvePromise({ code: 127, stdout, stderr: stderr + err.message }));
    child.on("close", (code) => resolvePromise({ code: code ?? 1, stdout, stderr }));
  });
}

/** Runs a command and exits if it fails, for steps nothing can continue past. */
export async function runOrExit(command, args, options, context) {
  const result = await run(command, args, options);
  if (result.code !== 0) {
    console.error(`\n${context ?? `${command} ${args.join(" ")}`} failed (exit ${result.code}).`);
    if (result.stderr) console.error(result.stderr);
    process.exit(result.code);
  }
  return result;
}

/** Captures a command's stdout, for the few places that parse it. */
export async function capture(command, args, options = {}) {
  const result = await run(command, args, { ...options, quiet: true });
  return { ...result, stdout: result.stdout.trim() };
}

/**
 * Finds the binary the way `npx` would: walk up looking for node_modules/.bin,
 * then fall back to PATH. Resolving only against the repository root would
 * silently use whatever global wrangler happened to be installed, which may be
 * a different version from the one this project pins.
 *
 * On Windows an npm-installed binary is a `.cmd` shim, which `spawn` without a
 * shell cannot exec by bare name - hence the extensions.
 */
function resolveCommand(command, cwd = ROOT) {
  const extensions = process.platform === "win32" ? [".cmd", ".exe", ""] : [""];

  let dir = resolve(cwd);
  for (;;) {
    for (const extension of extensions) {
      const candidate = join(dir, "node_modules", ".bin", command + extension);
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return process.platform === "win32" ? `${command}.cmd` : command;
}
