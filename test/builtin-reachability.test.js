import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { initTreeSitter } from "../dist/core/parsers/treesitter.js";
import { makeBuiltinProvider } from "../dist/core/graph/builtin.js";

test.before(async () => {
  await initTreeSitter(["python", "go", "java", "ruby"]);
});

function makeTempRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "builtin-reach-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, "utf-8");
  }
  return dir;
}

test("BuiltinGraphProvider detects reachable sink from Python Flask route", () => {
  const dir = makeTempRepo({
    "app.py": `
@app.route("/user")
def user_handler():
    return query_user()

def query_user():
    return run_query("SELECT * FROM users")

def run_query(sql):
    db.execute(sql)
`
  });

  try {
    const provider = makeBuiltinProvider(dir, {
      enabled: "auto",
      provider: "builtin",
      reachabilityMaxDepth: 6
    });

    const sinkFile = path.join(dir, "app.py");
    // Line 10 is inside run_query
    const verdict = provider.reachability({
      symbol: "execute",
      file: sinkFile,
      line: 10,
      cwd: dir,
      untrustedKinds: ["http_handler"]
    });

    assert.ok(verdict);
    assert.equal(verdict.reachable, true);
    assert.equal(verdict.entryPoints.length, 1);
    assert.equal(verdict.entryPoints[0].name, "user_handler");
    assert.equal(verdict.entryPoints[0].route, "/user");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("BuiltinGraphProvider returns reachable:false when sink has no path to entry point", () => {
  const dir = makeTempRepo({
    "cron.py": `
def background_job():
    process_data()

def process_data():
    raw_execute("DELETE FROM logs")

def raw_execute(sql):
    db.execute(sql)
`
  });

  try {
    const provider = makeBuiltinProvider(dir, {
      enabled: "auto",
      provider: "builtin",
      reachabilityMaxDepth: 6
    });

    const sinkFile = path.join(dir, "cron.py");
    // Line 9 is inside raw_execute
    const verdict = provider.reachability({
      symbol: "execute",
      file: sinkFile,
      line: 9,
      cwd: dir,
      untrustedKinds: ["http_handler"]
    });

    assert.ok(verdict);
    assert.equal(verdict.reachable, false);
    assert.equal(verdict.entryPoints.length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("BuiltinGraphProvider returns impact caller count and test gaps", () => {
  const dir = makeTempRepo({
    "utils.py": `
def helper():
    pass
`,
    "main.py": `
from utils import helper

def run():
    helper()
`
  });

  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    const impact = provider.impact({
      symbol: "helper",
      file: path.join(dir, "utils.py"),
      line: 2,
      cwd: dir
    });

    assert.ok(impact);
    assert.equal(impact.callerCount, 1);
    assert.equal(impact.callers[0].file, path.join(dir, "main.py"));
    assert.equal(impact.testGaps.length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("BuiltinGraphProvider.impact returns null (unknown) for a language with no call-graph coverage", () => {
  const dir = makeTempRepo({ "main.rs": "fn thing() {}\n" });
  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    const impact = provider.impact({ symbol: "thing", file: path.join(dir, "main.rs"), line: 1, cwd: dir });
    assert.equal(impact, null, "no Rust coverage -> unknown, not a false callerCount:0");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("BuiltinGraphProvider.impact marks a bare-name match ambiguous when >1 definition shares the name", () => {
  const dir = makeTempRepo({
    "repo.py": `
class UserRepo:
    def save(self, u):
        return u

class AuditLog:
    def save(self, e):
        return e

def unrelated():
    AuditLog().save("x")
    AuditLog().save("y")
`
  });
  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    const impact = provider.impact({ symbol: "save", file: path.join(dir, "repo.py"), line: 3, cwd: dir });
    assert.ok(impact);
    assert.equal(impact.ambiguous, true);
    assert.equal(impact.callerCount, 2, "still reports the (unreliable) count for visibility");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("E2E pipeline: a JS/TS signature-drift finding with a real cross-file caller is NOT de-escalated", async () => {
  // This is the regression the builtin-provider swap introduced: JS/TS had zero call-graph
  // coverage, so every symbol looked like callerCount:0 and got silently down-tiered to yellow
  // even when a real caller existed — a false pass on a breaking signature change.
  const { analyze, attachImpact, DEFAULT_CONFIG } = await import("../dist/core/index.js");

  const dir = makeTempRepo({
    "api.js": `export function existingHelper(a) { return a + 1; }\nexport function brandNewPublicThing(a, b) { return existingHelper(a) + b; }\n`,
    "consumer.js": `import { brandNewPublicThing } from "./api.js";\nexport function run() { return brandNewPublicThing(1, 2); }\n`,
  });

  try {
    const filePath = path.join(dir, "api.js");
    const prev = "export function existingHelper(a) { return a + 1; }\nexport function brandNewPublicThing(a, b) { return existingHelper(a) + b; }\n";
    const content = "export function existingHelper(a) { return a + 1; }\nexport function brandNewPublicThing(a, b, c) { return existingHelper(a) + b + c; }\n";
    const res = analyze({ filePath, content, previousContent: prev, config: DEFAULT_CONFIG });
    const drift = res.findings.find((f) => f.ruleId === "signature-drift");
    assert.ok(drift, "sanity: signature-drift fired");

    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin", escalateThreshold: 1 });
    const [out] = attachImpact([res], { cwd: dir, config: DEFAULT_CONFIG, graph: provider });
    const f = out.findings.find((f) => f.ruleId === "signature-drift");

    assert.equal(f.impact.callerCount, 1, "consumer.js really does call brandNewPublicThing");
    assert.notEqual(f.tierAdjusted, "deescalated", "a real caller must not be reported as unused");
    assert.equal(f.tier, "orange");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("E2E pipeline: an ambiguous bare-name match does not escalate or de-escalate a finding's tier", async () => {
  const { analyze, attachImpact, DEFAULT_CONFIG } = await import("../dist/core/index.js");

  const dir = makeTempRepo({
    "a.js": `export function process(x) { return x + 1; }\n`,
    "b.js": `export function process(x) { return x - 1; }\n`,
  });

  try {
    const filePath = path.join(dir, "a.js");
    const content = fs.readFileSync(filePath, "utf-8");
    const res = analyze({ filePath, content, config: DEFAULT_CONFIG });
    assert.ok(res.findings.some((f) => f.ruleId === "public-api-change"), "sanity: rule fired");

    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin", escalateThreshold: 1 });
    const [out] = attachImpact([res], { cwd: dir, config: DEFAULT_CONFIG, graph: provider });
    const f = out.findings.find((f) => f.ruleId === "public-api-change");

    assert.ok(f.impact.ambiguous, "two files define `process` -> ambiguous bare-name match");
    assert.equal(f.tierAdjusted, undefined, "ambiguous match must not escalate/de-escalate the tier");
    assert.equal(f.tier, "orange", "tier stays whatever the rule assigned");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("BuiltinGraphProvider.reachability resolves a Sinatra route with no wrapping named function (depth 0)", () => {
  const dir = makeTempRepo({
    "app.rb": `
require 'sinatra'
get '/u' do
  User.where("SELECT * FROM users WHERE id = #{params[:id]}")
end
`
  });
  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    const verdict = provider.reachability({
      symbol: "where", file: path.join(dir, "app.rb"), line: 4, cwd: dir, untrustedKinds: ["http_handler"]
    });
    assert.ok(verdict);
    assert.equal(verdict.reachable, true);
    assert.equal(verdict.depth, 0);
    assert.equal(verdict.entryPoints[0].route, "/u");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("BuiltinGraphProvider.reachability resolves a Sinatra route through a helper function (multi-hop)", () => {
  const dir = makeTempRepo({
    "app.rb": `
require 'sinatra'
get '/u' do
  lookup(params[:id])
end
def lookup(id)
  User.where("SELECT * FROM users WHERE id = #{id}")
end
`
  });
  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    const verdict = provider.reachability({
      symbol: "where", file: path.join(dir, "app.rb"), line: 7, cwd: dir, untrustedKinds: ["http_handler"]
    });
    assert.ok(verdict);
    assert.equal(verdict.reachable, true);
    assert.equal(verdict.entryPoints[0].route, "/u");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("E2E pipeline: BuiltinGraphProvider escalates reachable Python SQLi candidate to blocking orange", async () => {
  const { analyze, attachReachability, labelTrust, DEFAULT_CONFIG } = await import("../dist/core/index.js");

  const dir = makeTempRepo({
    "app.py": `from flask import Flask, request
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
`
  });

  const config = { ...DEFAULT_CONFIG, graph: { ...DEFAULT_CONFIG.graph, reachabilityDeescalate: true } };

  try {
    const filePath = path.join(dir, "app.py");
    const content = fs.readFileSync(filePath, "utf-8");
    const res = analyze({ filePath, content, config });

    const graph = makeBuiltinProvider(dir, config.graph);
    let [out] = attachReachability([res], { cwd: dir, config, graph });
    [out] = labelTrust([out]);

    const inGetUser = out.findings.find((f) => f.line >= 8 && f.line <= 11 && f.reachability);
    const inHelper = out.findings.find((f) => f.line >= 13 && f.line <= 16 && f.reachability);

    assert.ok(inGetUser, "finding in get_user was routed through reachability");
    assert.equal(inGetUser.reachability.reachable, true);
    assert.equal(inGetUser.blocking, true, "reachable from handler → escalated to blocking");
    assert.equal(inGetUser.tier, "orange");

    assert.ok(inHelper, "finding in lookup_helper was routed through reachability");
    assert.equal(inHelper.reachability.reachable, false);
    assert.equal(inHelper.blocking, false, "unreachable helper stays advisory — no false block");

    assert.equal(out.blocking, true, "the file gate blocks overall due to the reachable sink");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test("JS/TS entry points: express routes make sinks reachable, unrelated code stays advisory", () => {
  const dir = makeTempRepo({
    "src/routes.js": `
const app = require("express")();

app.get("/users/:id", async (req, res) => {
  res.json(await db.query("SELECT * FROM users WHERE id = " + req.params.id));
});

app.post("/search", handleSearch);

function handleSearch(req, res) {
  return runQuery(req.body.q);
}

function runQuery(q) {
  return db.query("SELECT * FROM t WHERE x = '" + q + "'");
}

function offGraph(q) {
  return db.query("SELECT * FROM t WHERE x = '" + q + "'");
}
`
  });

  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin", reachabilityMaxDepth: 6 });
    const file = path.join(dir, "src/routes.js");
    const at = (line) => provider.reachability({ symbol: "query", file, line, cwd: dir });

    // Inline arrow handler: no named function to match, matched by the handler's body range.
    const inline = at(5);
    assert.equal(inline.reachable, true);
    assert.equal(inline.entryPoints[0].route, "GET /users/:id");

    // Handler passed by reference, one hop from the sink.
    const viaChain = at(16);
    assert.equal(viaChain.reachable, true);
    assert.equal(viaChain.entryPoints[0].route, "POST /search");

    // Nothing routes to this one — must not be escalated.
    assert.equal(at(20).reachable, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("JS handler exports (Next.js route, lambda) count as entry points", () => {
  const dir = makeTempRepo({
    "app/api/items/route.ts": `
export async function GET(req: Request) {
  return db.query("SELECT * FROM items WHERE id = " + new URL(req.url).searchParams.get("id"));
}
`,
    "functions/ingest.js": `
exports.handler = async (event) => {
  return db.query("SELECT * FROM t WHERE k = '" + event.key + "'");
};
`
  });

  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    assert.equal(
      provider.reachability({ symbol: "query", file: path.join(dir, "app/api/items/route.ts"), line: 3, cwd: dir }).reachable,
      true
    );
    assert.equal(
      provider.reachability({ symbol: "query", file: path.join(dir, "functions/ingest.js"), line: 3, cwd: dir }).reachable,
      true
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("no verdict for languages the graph cannot parse (unknown, never 'unreachable')", () => {
  const dir = makeTempRepo({
    "main.rs": `fn handler(q: &str) { db.query(&format!("SELECT * FROM t WHERE x = '{}'", q)); }\n`
  });

  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    assert.equal(provider.reachability({ symbol: "query", file: path.join(dir, "main.rs"), line: 1, cwd: dir }), null);
    assert.equal(provider.impact({ symbol: "handler", file: path.join(dir, "main.rs"), line: 1, cwd: dir }), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a budget-truncated graph reports unknown, not a false negative", () => {
  const files = { "src/sink.js": `function sink(q) { return db.query("SELECT " + q); }\n` };
  for (let i = 0; i < 12; i++) files[`src/f${i}.js`] = `function f${i}() { return ${i}; }\n`;
  const dir = makeTempRepo(files);

  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" }, {}, { maxFiles: 2 });
    assert.equal(provider.reachability({ symbol: "query", file: path.join(dir, "src/sink.js"), line: 1, cwd: dir }), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("non-request event listeners are not untrusted entry points (no false escalation)", () => {
  const dir = makeTempRepo({
    "src/lifecycle.js": `
process.on("exit", () => {
  db.query("DELETE FROM sessions WHERE id = '" + cachedId + "'");
});

socket.on("message", (msg) => {
  db.query("SELECT * FROM t WHERE k = '" + msg.key + "'");
});
`
  });

  try {
    const provider = makeBuiltinProvider(dir, { enabled: "auto", provider: "builtin" });
    const file = path.join(dir, "src/lifecycle.js");
    // Unknown (no enclosing named function, and the hook is not an entry point) — the point is that
    // it is never claimed reachable, which would escalate it to a blocking finding.
    const exitHook = provider.reachability({ symbol: "query", file, line: 3, cwd: dir });
    assert.notEqual(exitHook?.reachable, true, "process exit hook carries no outside input");
    assert.equal(provider.reachability({ symbol: "query", file, line: 7, cwd: dir }).reachable, true,
      "socket message handler does");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
