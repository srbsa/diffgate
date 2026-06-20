import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "cli.js");

function runGit(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
}

// Run the CLI, capturing stdout even when it exits non-zero (the gate exits 1 on orange).
// HOME is pinned to the temp dir so the host's real ~/.codegraph index never leaks into the test.
function runCli(cwd, args) {
  const env = { ...process.env, NO_COLOR: "1", HOME: cwd, USERPROFILE: cwd };
  try {
    return { code: 0, out: execFileSync("node", [CLI, ...args], { cwd, encoding: "utf-8", env }) };
  } catch (e) {
    return { code: e.status ?? 1, out: (e.stdout || "") + (e.stderr || "") };
  }
}

// A fake `codegraph-server` that records its invocation and emits an index confirmation.
function writeFakeServer(dir) {
  const logPath = path.join(dir, "invoked.log");
  const bin = path.join(dir, "fake-codegraph-server");
  fs.writeFileSync(
    bin,
    `#!/bin/sh\necho "$@" >> "${logPath}"\necho '{"indexed": 7}'\n`,
    { mode: 0o755 }
  );
  return { bin, logPath };
}

test("graph status --json reports disabled state", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dg-graphcli-"));
  try {
    fs.writeFileSync(path.join(tmp, ".diffgate.json"), JSON.stringify({ graph: { enabled: false } }));
    const { out } = runCli(tmp, ["graph", "status", "--json"]);
    const status = JSON.parse(out);
    assert.equal(status.enabled, false);
    assert.equal(status.indexed, false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("graph index runs the configured server and reports success", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dg-graphcli-"));
  try {
    const { bin, logPath } = writeFakeServer(tmp);
    fs.writeFileSync(path.join(tmp, ".diffgate.json"), JSON.stringify({ graph: { enabled: "auto", command: bin } }));
    const { code, out } = runCli(tmp, ["graph", "index"]);
    assert.equal(code, 0);
    assert.match(out, /Indexed/);
    assert.ok(fs.existsSync(logPath), "the fake server was actually invoked");
    assert.match(fs.readFileSync(logPath, "utf-8"), /--run-tool reindex_workspace/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("graph index prints install help when the binary is missing", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dg-graphcli-"));
  try {
    fs.writeFileSync(path.join(tmp, ".diffgate.json"), JSON.stringify({ graph: { command: "/no/such/codegraph-xyz" } }));
    const { code, out } = runCli(tmp, ["graph", "index"]);
    assert.equal(code, 1);
    assert.match(out, /not found on PATH/);
    assert.match(out, /Install CodeGraph/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check shows the graph adoption tip when unindexed and a public-surface change exists", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dg-graphcli-"));
  try {
    runGit(tmp, "init", "-q");
    runGit(tmp, "config", "user.email", "t@t.dev");
    runGit(tmp, "config", "user.name", "T");
    // graph enabled (auto) but pointed at a non-existent binary → unindexed.
    fs.writeFileSync(path.join(tmp, ".diffgate.json"), JSON.stringify({ graph: { command: "/no/such/codegraph-xyz" } }));
    const file = path.join(tmp, "api.js");
    fs.writeFileSync(file, "export function getThing(id){ return id; }\n");
    runGit(tmp, "add", "-A");
    runGit(tmp, "commit", "-q", "-m", "base");
    fs.writeFileSync(file, "export function getThing(id, extra){ return id + extra; }\n");

    const { out } = runCli(tmp, ["check", "--working"]);
    assert.match(out, /Cross-file blast radius is off/, "tip shown for a public-surface diff");
    assert.match(out, /install CodeGraph/i);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check does NOT show the graph tip when graphing is disabled", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dg-graphcli-"));
  try {
    runGit(tmp, "init", "-q");
    runGit(tmp, "config", "user.email", "t@t.dev");
    runGit(tmp, "config", "user.name", "T");
    fs.writeFileSync(path.join(tmp, ".diffgate.json"), JSON.stringify({ graph: { enabled: false } }));
    const file = path.join(tmp, "api.js");
    fs.writeFileSync(file, "export function getThing(id){ return id; }\n");
    runGit(tmp, "add", "-A");
    runGit(tmp, "commit", "-q", "-m", "base");
    fs.writeFileSync(file, "export function getThing(id, extra){ return id + extra; }\n");

    const { out } = runCli(tmp, ["check", "--working"]);
    assert.doesNotMatch(out, /Cross-file blast radius is off/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
