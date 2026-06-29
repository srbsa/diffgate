// Release-gate hygiene check. A stray NUL byte in a source/text file silently flips git into treating
// the whole file as BINARY — no line diffs, which is especially corrosive for a diff-review engine that
// reviews its own changes. Two such files shipped undetected before 0.7.2 (treesitter.ts comment,
// session.ts hash separator). This test fails the suite if any tracked text file carries a NUL, so it
// can never recur silently. When a NUL is genuinely needed in a string, write the escape `"\u0000"`.
import test from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

// Extensions that are legitimately binary and expected to contain NUL bytes — skip them.
const BINARY_EXT = new Set([
  ".wasm", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp",
  ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".zip", ".gz",
  ".tgz", ".bz2", ".7z", ".vsix", ".node", ".wat", ".bin",
]);

test("no tracked text file contains a NUL byte (binary-flag guard)", () => {
  let tracked;
  try {
    tracked = execSync("git ls-files -z", { cwd: path.resolve(import.meta.dirname, ".."), maxBuffer: 64 * 1024 * 1024 })
      .toString("utf8").split("\0").filter(Boolean);
  } catch {
    return; // not a git checkout (e.g. published tarball) — nothing to guard
  }
  const offenders = [];
  for (const rel of tracked) {
    if (BINARY_EXT.has(path.extname(rel).toLowerCase())) continue;
    let buf;
    try {
      buf = readFileSync(path.resolve(import.meta.dirname, "..", rel));
    } catch {
      continue; // submodule pointer / unreadable — not our concern here
    }
    if (buf.includes(0)) offenders.push(rel);
  }
  assert.deepEqual(offenders, [], `NUL byte(s) found in tracked text file(s): ${offenders.join(", ")}. ` +
    `Write the escape "\\u0000" instead of a raw NUL byte.`);
});
