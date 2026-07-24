import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { execFileSync } from "child_process";
import { initTreeSitter } from "../dist/core/parsers/treesitter.js";
import { buildCallGraph, getCallers, resolveEnclosingFunction } from "../dist/core/graph/callgraph.js";
import { detectEntryPoints } from "../dist/core/graph/entry-points.js";

function runGit(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
}

test.before(async () => {
  await initTreeSitter(["python", "go", "java"]);
});

function makeTempRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-test-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, "utf-8");
  }
  return dir;
}

test("buildCallGraph extracts Python functions and call sites", () => {
  const dir = makeTempRepo({
    "app.py": `
@app.route("/user")
def get_user():
    return query_db("SELECT * FROM users")

def query_db(sql):
    execute_sql(sql)

def execute_sql(sql):
    pass
`
  });

  try {
    const graph = buildCallGraph(dir, {
      entryPointDetector: (tree, file, lang) => {
        const eps = detectEntryPoints(tree, file, lang);
        return eps.map((e) => e.qualName);
      }
    });

    assert.ok(graph.functions.has("get_user"));
    assert.ok(graph.functions.has("query_db"));
    assert.ok(graph.functions.has("execute_sql"));

    const queryDbCallers = getCallers(graph, "query_db");
    assert.equal(queryDbCallers.length, 1);
    assert.equal(queryDbCallers[0].callerQualName, "get_user");

    const execSqlCallers = getCallers(graph, "execute_sql");
    assert.equal(execSqlCallers.length, 1);
    assert.equal(execSqlCallers[0].callerQualName, "query_db");

    assert.ok(graph.entryPointNames.has("get_user"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("buildCallGraph extracts Go functions and call sites", () => {
  const dir = makeTempRepo({
    "main.go": `
package main

import "net/http"

func handleUser(w http.ResponseWriter, r *http.Request) {
    data := fetchUser()
    w.Write(data)
}

func fetchUser() string {
    return "user"
}
`
  });

  try {
    const graph = buildCallGraph(dir);

    assert.ok(graph.functions.has("handleUser"));
    assert.ok(graph.functions.has("fetchUser"));

    const callers = getCallers(graph, "fetchUser");
    assert.equal(callers.length, 1);
    assert.equal(callers[0].callerQualName, "handleUser");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("buildCallGraph extracts JS/TS functions and call sites (Babel, not tree-sitter)", () => {
  const dir = makeTempRepo({
    "api.js": `
export function existingHelper(a) { return a + 1; }
export function brandNewPublicThing(a, b) { return existingHelper(a) + b; }
`,
    "consumer.js": `
import { brandNewPublicThing } from "./api.js";
export function run() { return brandNewPublicThing(1, 2); }
`
  });

  try {
    const graph = buildCallGraph(dir);
    assert.ok(graph.functions.has("brandNewPublicThing"));
    assert.ok(graph.functions.has("existingHelper"));

    const callers = getCallers(graph, "brandNewPublicThing");
    assert.equal(callers.length, 1);
    assert.equal(callers[0].callerQualName, "run");
    assert.equal(callers[0].file, path.join(dir, "consumer.js"));

    const helperCallers = getCallers(graph, "existingHelper");
    assert.equal(helperCallers.length, 1);
    assert.equal(helperCallers[0].callerQualName, "brandNewPublicThing");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("buildCallGraph tracks method/arrow-const bindings and calls through them (JS)", () => {
  const dir = makeTempRepo({
    "svc.js": `
const helper = (x) => x + 1;
class Widget {
  render() { return helper(1); }
}
export function build() { return new Widget().render(); }
`
  });

  try {
    const graph = buildCallGraph(dir);
    assert.ok(graph.functions.has("helper"));
    assert.ok(graph.functions.has("render"));

    const helperCallers = getCallers(graph, "helper");
    assert.equal(helperCallers.length, 1);
    assert.equal(helperCallers[0].callerQualName, "render");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("buildCallGraph skips files matched by .gitignore", () => {
  const dir = makeTempRepo({
    "kept.py": "def brandNewPublicThing():\n    pass\n",
  });
  const ignoredDir = path.join(dir, "ignored_dir");
  fs.mkdirSync(ignoredDir, { recursive: true });
  fs.writeFileSync(path.join(ignoredDir, "junk.py"), "def brandNewOtherThing():\n    pass\n");
  fs.writeFileSync(path.join(dir, ".gitignore"), "ignored_dir/\n");

  runGit(dir, "init", "-q");
  runGit(dir, "config", "user.email", "t@t.dev");
  runGit(dir, "config", "user.name", "T");
  runGit(dir, "add", "kept.py", ".gitignore");
  runGit(dir, "commit", "-q", "-m", "base");

  try {
    const graph = buildCallGraph(dir);
    assert.ok(graph.functions.has("brandNewPublicThing"), "tracked file is still walked");
    assert.ok(!graph.functions.has("brandNewOtherThing"), "gitignored file must not be parsed into the graph");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("buildCallGraph respects config.ignore globs (a dir name not in the built-in skip list)", () => {
  const dir = makeTempRepo({
    "kept.py": "def brandNewPublicThing():\n    pass\n",
    "legacy_stuff/lib.py": "def brandNewOtherThing():\n    pass\n",
  });

  try {
    const withoutIgnore = buildCallGraph(dir);
    assert.ok(withoutIgnore.functions.has("brandNewOtherThing"), "sanity: not skipped by default");

    const graph = buildCallGraph(dir, { config: { ignore: ["**/legacy_stuff/**"] } });
    assert.ok(graph.functions.has("brandNewPublicThing"));
    assert.ok(!graph.functions.has("brandNewOtherThing"), "config.ignore glob must be respected");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("resolveEnclosingFunction returns narrowest function for a line", () => {
  const dir = makeTempRepo({
    "service.py": `
def outer():
    x = 1
    def inner():
        y = 2
    return x
`
  });

  try {
    const graph = buildCallGraph(dir);
    const innerFn = resolveEnclosingFunction(graph, path.join(dir, "service.py"), 4);
    assert.ok(innerFn);
    assert.equal(innerFn.name, "inner");

    const outerFn = resolveEnclosingFunction(graph, path.join(dir, "service.py"), 2);
    assert.ok(outerFn);
    assert.equal(outerFn.name, "outer");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
