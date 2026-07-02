import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";

import { reviewHistory, listCommits, isCommitish } from "../dist/core/index.js";

function runGit(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
}

// A repo with: A = clean (root), B = adds a hardcoded secret, C = clean, plus an
// AI-co-authored commit D so author/ai filtering can be exercised.
function makeRepo() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grg-hist-"));
  runGit(tmp, "init", "-q");
  runGit(tmp, "config", "user.email", "t@t.dev");
  runGit(tmp, "config", "user.name", "Test");

  // Non-exported so the root commit is genuinely clean (a new exported symbol would fire
  // public-api-change — real engine behavior, but not what these tests are exercising).
  fs.writeFileSync(path.join(tmp, "math.js"), `function add(a, b) {\n  return a + b;\n}\n`);
  runGit(tmp, "add", "-A");
  runGit(tmp, "commit", "-q", "-m", "A: base");

  fs.writeFileSync(path.join(tmp, "config.js"), `const apiKey = "supersecretvalue123";\n`);
  runGit(tmp, "add", "-A");
  runGit(tmp, "commit", "-q", "-m", "B: add config");

  fs.writeFileSync(path.join(tmp, "readme.txt"), `hello world\n`);
  runGit(tmp, "add", "-A");
  runGit(tmp, "commit", "-q", "-m", "C: docs");

  // AI-co-authored, clean change.
  fs.writeFileSync(path.join(tmp, "math.js"), `function add(a, b) {\n  return a + b;\n}\n// note\n`);
  runGit(tmp, "add", "-A");
  runGit(tmp, "commit", "-q", "-m", "D: tweak\n\nCo-Authored-By: Claude <noreply@anthropic.com>");

  return tmp;
}

test("reviewHistory attributes findings to the right commit", () => {
  const tmp = makeRepo();
  try {
    const result = reviewHistory(tmp, { limit: 10 });
    assert.equal(result.scanned, 4, "should scan all 4 commits");
    assert.equal(result.withFindings, 1, "only commit B has a finding");
    const flagged = result.commits.filter((r) => r.files.length > 0);
    assert.equal(flagged.length, 1);
    assert.match(flagged[0].commit.subject, /^B:/);
    const ruleIds = flagged[0].files.flatMap((f) => f.findings.map((fd) => fd.ruleId));
    assert.ok(ruleIds.includes("hardcoded-secret"), "expected hardcoded-secret on commit B");
    assert.equal(flagged[0].blocking, true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("root commit (no parent) is reviewable", () => {
  const tmp = makeRepo();
  try {
    const rootSha = runGit(tmp, "rev-list", "--max-parents=0", "HEAD").trim();
    const result = reviewHistory(tmp, { commit: rootSha });
    assert.equal(result.scanned, 1);
    // math.js at the root commit is clean, and the diff-vs-empty-tree must not throw.
    assert.equal(result.withFindings, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("--author and --ai filtering match co-author trailers", () => {
  const tmp = makeRepo();
  try {
    const ai = listCommits(tmp, { ai: true });
    assert.equal(ai.length, 1, "one AI-co-authored commit");
    assert.match(ai[0].subject, /^D:/);
    assert.deepEqual(ai[0].coAuthors.length > 0, true);

    const byName = listCommits(tmp, { author: "claude" });
    assert.equal(byName.length, 1, "case-insensitive author match on co-author trailer");

    const none = listCommits(tmp, { author: "nobody-xyz" });
    assert.equal(none.length, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("--limit caps the number of commits", () => {
  const tmp = makeRepo();
  try {
    assert.equal(listCommits(tmp, { limit: 2 }).length, 2);
    assert.equal(reviewHistory(tmp, { limit: 2 }).scanned, 2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("isCommitish distinguishes a sha from a path", () => {
  const tmp = makeRepo();
  try {
    const head = runGit(tmp, "rev-parse", "HEAD").trim();
    assert.equal(isCommitish(tmp, head), true);
    assert.equal(isCommitish(tmp, head.slice(0, 8)), true);
    assert.equal(isCommitish(tmp, "not-a-ref-xyz"), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
