import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync, spawnSync } from "child_process";

import { isGitIgnoredPath } from "../dist/core/index.js";

const CLI = path.join(process.cwd(), "dist", "cli.js");

function runGit(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
}

// Fresh repo per case: isGitIgnoredPath caches the ignored set briefly per repo root, so
// mutating one repo's tracking state within a test would read stale entries.
function makeRepo(gitignore) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grg-ign-"));
  runGit(tmp, "init", "-q");
  runGit(tmp, "config", "user.email", "t@t.dev");
  runGit(tmp, "config", "user.name", "Test");
  if (gitignore) fs.writeFileSync(path.join(tmp, ".gitignore"), gitignore);
  return tmp;
}

test("isGitIgnoredPath: gitignored .env is ignored; tracked/untracked files are not", () => {
  const tmp = makeRepo(".env\nsecrets/\n");
  fs.writeFileSync(path.join(tmp, ".env"), "OPENAI_API_KEY=x\n");
  fs.writeFileSync(path.join(tmp, "app.js"), "const x = 1;\n");
  fs.mkdirSync(path.join(tmp, "secrets"));
  fs.writeFileSync(path.join(tmp, "secrets", "key.txt"), "k\n");
  runGit(tmp, "add", "app.js", ".gitignore");
  runGit(tmp, "commit", "-q", "-m", "base");

  assert.equal(isGitIgnoredPath(tmp, path.join(tmp, ".env")), true, "gitignored .env");
  assert.equal(isGitIgnoredPath(tmp, path.join(tmp, "secrets", "key.txt")), true, "file in gitignored dir");
  assert.equal(isGitIgnoredPath(tmp, path.join(tmp, "app.js")), false, "tracked file");
  assert.equal(isGitIgnoredPath(tmp, path.join(tmp, "new.js")), false, "untracked but not ignored");
});

test("isGitIgnoredPath: tracked file matching a .gitignore pattern is NOT ignored", () => {
  // Committing a .env force-adds it past .gitignore — it can reach a commit, so it stays in scope.
  const tmp = makeRepo(".env\n");
  fs.writeFileSync(path.join(tmp, ".env"), "OPENAI_API_KEY=x\n");
  runGit(tmp, "add", "-f", ".env");
  runGit(tmp, "commit", "-q", "-m", "oops");
  assert.equal(isGitIgnoredPath(tmp, path.join(tmp, ".env")), false);
});

test("isGitIgnoredPath: outside a git repo nothing is git-ignored (fail open)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grg-norepo-"));
  fs.writeFileSync(path.join(tmp, ".env"), "OPENAI_API_KEY=x\n");
  assert.equal(isGitIgnoredPath(tmp, path.join(tmp, ".env")), false);
});

test("scan walker skips a gitignored .env holding a real-format key", () => {
  const key = "sk-proj-" + "Ab1".repeat(10); // OpenAI project-key format — always high-confidence
  const tmp = makeRepo(".env\n");
  fs.writeFileSync(path.join(tmp, ".env"), `OPENAI_API_KEY=${key}\n`);
  fs.writeFileSync(path.join(tmp, "app.js"), "const x = 1;\n");
  runGit(tmp, "add", "app.js", ".gitignore");
  runGit(tmp, "commit", "-q", "-m", "base");

  const out = spawnSync(process.execPath, [CLI, "scan", ".", "--json"], { cwd: tmp, encoding: "utf-8" });
  assert.ok(!out.stdout.includes("hardcoded-secret"), "gitignored .env must not be scanned");

  // Same key in a tracked file must still fire — the skip is gitignore-driven, not .env-driven.
  fs.writeFileSync(path.join(tmp, "config.js"), `const k = "${key}";\n`);
  runGit(tmp, "add", "config.js");
  const out2 = spawnSync(process.execPath, [CLI, "scan", ".", "--json"], { cwd: tmp, encoding: "utf-8" });
  assert.ok(out2.stdout.includes("hardcoded-secret"), "tracked file with the same key still fires");
});
