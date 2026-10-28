// Operator output: a blank line, a cyan `==> ` heading, then two-space
// indented detail. Colour is dropped when NO_COLOR is set or stdout is not a
// terminal, so a redirected log does not fill with escape sequences.

const useColour = process.stdout.isTTY && !process.env.NO_COLOR;
const cyan = (s) => (useColour ? `\u001b[1;36m${s}\u001b[0m` : s);
const red = (s) => (useColour ? `\u001b[1;31m${s}\u001b[0m` : s);
const yellow = (s) => (useColour ? `\u001b[1;33m${s}\u001b[0m` : s);

/** A section heading. */
export function log(message) {
  console.log(`\n${cyan(`==> ${message}`)}`);
}

/** Indented detail under a heading. */
export function detail(message = "") {
  console.log(message === "" ? "" : `  ${message}`);
}

export function blank() {
  console.log("");
}

/** A warning, to stderr - so a run with stdout redirected still shows problems. */
export function warn(message) {
  console.error(`  ${yellow(message)}`);
}

/** An error, to stderr. Does not exit; the caller decides. */
export function error(message) {
  console.error(`  ${red(message)}`);
}

/** A block of indented lines, for the long epilogues. */
export function lines(text) {
  for (const line of text.split("\n")) detail(line);
}
