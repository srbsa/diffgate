// Live CodeGraph integration test (plan §4.3). Opt-in: runs only when DIFFGATE_CODEGRAPH_E2E=1
// AND a codegraph-server binary is found, so the default suite + CI never depend on the binary.
//
//   DIFFGATE_CODEGRAPH_E2E=1 npm run test:e2e
//   (optionally DIFFGATE_CODEGRAPH_BIN=/abs/path/to/codegraph-server)
//
// This drives the engine's REAL CLI provider (defaultRunner → `codegraph-server --graph-only
// --run-tool`) against a freshly indexed Flask fixture. It is the test the canned-shape unit
// fixtures could not be — it is what surfaced the production bugs the fakes hid (the file:// URI
// requirement, the nested-symbol envelope, the cold-index "Could not find starting node" verdict).
//
// Environment note: `--graph-only` one-shot indexing can READ a uri+line-resolvable graph but does
// not always BUILD one from cold — in production CodeGraph's daemon/extension builds the full index
// and the engine reads it. So entry-point discovery (which needs no uri+line lookup) is asserted
// unconditionally, while the reachability assertions self-skip when this environment's index can't
// resolve uri+line. Point the test at an already-indexed workspace (MCP/daemon warm) to exercise them.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

import { makeCodeGraphProvider } from "../dist/core/index.js";

/** Locate a codegraph-server binary: explicit env, then PATH, then the VS Code extension install. */
function findBinary() {
  const env = process.env.DIFFGATE_CODEGRAPH_BIN;
  if (env && fs.existsSync(env)) return env;
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (dir && fs.existsSync(path.join(dir, "codegraph-server"))) return path.join(dir, "codegraph-server");
  }
  const ext = path.join(os.homedir(), ".vscode", "extensions");
  try {
    for (const d of fs.readdirSync(ext)) {
      if (!/codegraph/i.test(d)) continue;
      const binDir = path.join(ext, d, "bin");
      if (!fs.existsSync(binDir)) continue;
      for (const f of fs.readdirSync(binDir)) if (/^codegraph-server/.test(f)) return path.join(binDir, f);
    }
  } catch { /* none */ }
  return null;
}

const BIN = findBinary();
const ENABLED = process.env.DIFFGATE_CODEGRAPH_E2E === "1" && !!BIN;
const reason = process.env.DIFFGATE_CODEGRAPH_E2E !== "1" ? "set DIFFGATE_CODEGRAPH_E2E=1 to run" : "no codegraph-server binary found";

const FIXTURE = `from flask import Flask, request
import sqlite3

app = Flask(__name__)
db = sqlite3.connect("app.db")


def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query).fetchone()


def lookup_helper(name):
    q = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(q).fetchone()


@app.route("/user/<user_id>")
def user_route(user_id):
    return get_user(user_id)


def admin_cli(name):
    return lookup_helper(name)
`;

function runTool(dir, tool, args) {
  try {
    return execFileSync(BIN, ["--graph-only", "--run-tool", `codegraph_${tool}`, "--tool-args", JSON.stringify(args)],
      { cwd: dir, encoding: "utf-8", timeout: 30000 });
  } catch { return null; }
}

let dir;
let resolves = false; // whether this environment's index resolves uri+line lookups for the fixture
test.before(() => {
  if (!ENABLED) return;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "diffgate-cg-e2e-"));
  fs.writeFileSync(path.join(dir, "app.py"), FIXTURE);
  runTool(dir, "reindex_workspace", {});            // best-effort full structural build
  // Probe: can get_callers resolve the enclosing function from uri+line in this environment?
  const probe = runTool(dir, "get_callers", { uri: `file://${path.join(dir, "app.py")}`, line: 8, depth: 6 });
  try { resolves = !!(probe && JSON.parse(probe).symbol_name); } catch { resolves = false; }
});
test.after(() => { if (dir) fs.rmSync(dir, { recursive: true, force: true }); });

// Works cold — find_entry_points needs no uri+line resolution. Asserts the REAL binary output flows
// through normalizeEntryPoints correctly (the nested symbol.name / entry_type envelope).
test("live: Flask route is discovered as an http_handler with method+route (real normalize path)", { skip: ENABLED ? false : reason }, () => {
  const out = runTool(dir, "find_entry_points", { entryType: "http_handler" });
  assert.ok(out, "binary answered");
  const eps = JSON.parse(out);
  const route = eps.find((e) => (e.symbol?.name || e.name) === "user_route");
  assert.ok(route, "user_route discovered");
  assert.equal(route.entry_type, "http_handler");
  assert.equal(route.route, "/user/<user_id>");
  // And the engine's provider must surface it (not "[object Object]").
  const provider = makeCodeGraphProvider(dir, { command: BIN, timeoutMs: 20000, reachabilityTimeoutMs: 20000 });
  const v = provider.reachability({ symbol: "user_route", file: "app.py", line: 19, cwd: dir });
  // user_route IS the handler, so even resolving only its own name it is reachable (depth 0).
  if (v) assert.ok(v.entryPoints.every((e) => e.name && !/\[object Object\]/.test(e.name)), "no [object Object] names");
});

test("live: sink reached from an HTTP handler is reachable", { skip: ENABLED ? false : reason }, (t) => {
  if (!resolves) { t.skip("graph-only one-shot can't resolve uri+line on this freshly-built index — needs CodeGraph's full indexer (MCP/daemon) warm"); return; }
  const provider = makeCodeGraphProvider(dir, { command: BIN, timeoutMs: 20000, reachabilityTimeoutMs: 20000 });
  const v = provider.reachability({ symbol: "", file: "app.py", line: 9, cwd: dir });
  assert.ok(v, "verdict produced");
  assert.equal(v.reachable, true, "get_user is reachable from the @app.route handler user_route");
  assert.ok(v.entryPoints.some((e) => e.name === "user_route" && e.kind === "http_handler"), "names the HTTP handler");
  assert.ok(Array.isArray(v.path) && v.path.length >= 2, "attaches the sink→handler trace");
});

test("live: sink reached only from a CLI command is NOT reachable (no false escalation)", { skip: ENABLED ? false : reason }, (t) => {
  if (!resolves) { t.skip("graph-only one-shot can't resolve uri+line on this freshly-built index"); return; }
  const provider = makeCodeGraphProvider(dir, { command: BIN, timeoutMs: 20000, reachabilityTimeoutMs: 20000 });
  const v = provider.reachability({ symbol: "", file: "app.py", line: 15, cwd: dir });
  assert.ok(v, "verdict produced");
  assert.equal(v.reachable, false, "admin_cli is a cli_command, not an untrusted entry point");
  assert.deepEqual(v.entryPoints, []);
});
