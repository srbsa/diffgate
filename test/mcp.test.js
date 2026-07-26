import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { Readable, Writable, PassThrough } from "stream";
import { execSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  createReader,
  createWriter,
  dispatchMessage,
  handleAnalyze,
  handleCheckStaged,
  handleCapabilities,
  handleDeepReview,
  handleGuidelines,
  handleFeedback,
  negotiateProtocol,
  TOOL_DEFS,
  PROMPT_DEFS,
  RESOURCE_DEFS,
  RESOURCE_TEMPLATE_DEFS,
  listPrompts,
  getPrompt,
  listResources,
  listResourceTemplates,
  readResource,
  RpcError,
} from "../dist/mcp.js";

// Drive dispatchMessage and capture everything it writes back (one entry per `send`).
async function dispatch(msg) {
  const sent = [];
  await dispatchMessage(msg, (obj) => sent.push(obj));
  return sent;
}

// A throwaway git repo with committed baseline files, so working-tree edits form a real diff.
function gitRepo(committed = {}) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "grg-mcp-git-")));
  const g = (args) => execSync(`git ${args}`, { cwd: dir, stdio: "pipe" });
  g("init -q");
  g("config user.email t@example.com");
  g("config user.name t");
  g("config commit.gpgsign false");
  for (const [name, content] of Object.entries(committed)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  if (Object.keys(committed).length) { g("add -A"); g('commit -q -m base'); }
  return dir;
}

function tmpDir(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "grg-mcp-"));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

// Build a legacy Content-Length-framed MCP message for testing reader back-compat.
function frame(obj) {
  const body = JSON.stringify(obj);
  const len = Buffer.byteLength(body, "utf-8");
  return Buffer.from(`Content-Length: ${len}\r\n\r\n${body}`);
}

// Build a spec-compliant newline-delimited MCP message.
function line(obj) {
  return Buffer.from(JSON.stringify(obj) + "\n");
}

// --- framing tests -----------------------------------------------------------

test("createReader parses a single framed message", (t, done) => {
  const stream = new PassThrough();
  const reader = createReader(stream);
  reader.onMessage((msg) => {
    assert.equal(msg.method, "tools/list");
    assert.equal(msg.id, 42);
    done();
  });
  stream.push(frame({ jsonrpc: "2.0", id: 42, method: "tools/list" }));
});

test("createReader handles messages split across chunks", (t, done) => {
  const stream = new PassThrough();
  const reader = createReader(stream);
  let received = 0;
  reader.onMessage(() => {
    received++;
    if (received === 2) done();
  });
  const buf = Buffer.concat([
    frame({ jsonrpc: "2.0", id: 1, method: "ping" }),
    frame({ jsonrpc: "2.0", id: 2, method: "ping" }),
  ]);
  // deliver in two arbitrary chunks
  stream.push(buf.slice(0, 20));
  stream.push(buf.slice(20));
});

test("createReader parses spec newline-delimited JSON", (t, done) => {
  const stream = new PassThrough();
  const reader = createReader(stream);
  reader.onMessage((msg) => {
    assert.equal(msg.method, "initialize");
    assert.equal(msg.id, 7);
    done();
  });
  stream.push(line({ jsonrpc: "2.0", id: 7, method: "initialize" }));
});

test("createReader parses newline-delimited messages split across chunks", (t, done) => {
  const stream = new PassThrough();
  const reader = createReader(stream);
  let received = 0;
  reader.onMessage(() => { if (++received === 2) done(); });
  const buf = Buffer.concat([
    line({ jsonrpc: "2.0", id: 1, method: "ping" }),
    line({ jsonrpc: "2.0", id: 2, method: "ping" }),
  ]);
  stream.push(buf.slice(0, 18));
  stream.push(buf.slice(18));
});

test("createReader accepts a newline message immediately after a legacy frame", (t, done) => {
  const stream = new PassThrough();
  const reader = createReader(stream);
  const got = [];
  reader.onMessage((msg) => {
    got.push(msg.id);
    if (got.length === 2) { assert.deepEqual(got, [1, 2]); done(); }
  });
  stream.push(Buffer.concat([
    frame({ jsonrpc: "2.0", id: 1, method: "ping" }),
    line({ jsonrpc: "2.0", id: 2, method: "ping" }),
  ]));
});

test("createWriter emits spec newline-delimited JSON (no Content-Length header)", () => {
  const chunks = [];
  const stream = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } });
  const send = createWriter(stream);
  send({ jsonrpc: "2.0", id: 1, result: { ok: true } });
  const out = chunks.join("");
  assert.doesNotMatch(out, /Content-Length:/, "must not use LSP framing");
  assert.ok(out.endsWith("\n"), "message terminated by a newline");
  assert.equal((out.match(/\n/g) || []).length, 1, "no embedded newlines");
  assert.deepEqual(JSON.parse(out.trim()), { jsonrpc: "2.0", id: 1, result: { ok: true } });
});

test("negotiateProtocol echoes a supported version, else falls back to preferred", () => {
  assert.equal(negotiateProtocol("2025-11-25"), "2025-11-25");
  assert.equal(negotiateProtocol("2024-11-05"), "2024-11-05");
  assert.equal(negotiateProtocol("1999-01-01"), "2025-06-18");
  assert.equal(negotiateProtocol(undefined), "2025-06-18");
});

// --- tools/list --------------------------------------------------------------

test("TOOL_DEFS exposes all tools with required inputSchema", () => {
  const names = TOOL_DEFS.map((t) => t.name);
  assert.ok(names.includes("diffgate_analyze"));
  assert.ok(names.includes("diffgate_check_staged"));
  assert.ok(names.includes("diffgate_deep_review"));
  assert.ok(names.includes("diffgate_explain"));
  assert.ok(names.includes("diffgate_guidelines"));
  for (const t of TOOL_DEFS) {
    assert.ok(t.inputSchema, `${t.name} must have inputSchema`);
    assert.ok(t.description, `${t.name} must have description`);
  }
});

// --- handleAnalyze -----------------------------------------------------------

test("handleAnalyze detects hardcoded secret via content parameter (unsaved file)", async () => {
  const dir = tmpDir({});
  const content = `const key = "sk_live_abcdef0123456789abcd";\n`;
  try {
    const result = await handleAnalyze({
      filePath: path.join(dir, "config.js"),
      content,
      cwd: dir,
    });
    assert.ok(result.findings.length > 0, "should find the hardcoded secret");
    assert.ok(
      result.findings.some((f) => f.ruleId === "hardcoded-secret"),
      "hardcoded-secret rule should fire"
    );
    assert.equal(result.findings.find((f) => f.ruleId === "hardcoded-secret").tier, "orange");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze reads file from disk when content is omitted", async () => {
  const dir = tmpDir({
    "secret.js": `const key = "sk_live_abcdef0123456789abcd";\n`,
  });
  try {
    const result = await handleAnalyze({
      filePath: "secret.js",
      cwd: dir,
    });
    assert.ok(result.findings.some((f) => f.ruleId === "hardcoded-secret"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze returns no findings for safe content", async () => {
  const dir = tmpDir({});
  const content = `function add(a, b) { return a + b; }\n`;
  try {
    const result = await handleAnalyze({
      filePath: path.join(dir, "math.js"),
      content,
      cwd: dir,
    });
    assert.equal(result.findings.length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze attaches blast radius + pre-edit context via an injected graph", async () => {
  const dir = tmpDir({});
  const content = `export function getThing(id) { return id; }\n`;
  let editCtxCalls = 0;
  const graph = {
    id: "fake",
    impact: () => ({
      symbol: "getThing", callerCount: 4, callers: [{ file: "a.js" }, { file: "b.js" }],
      reachable: true, testGaps: [], reviewers: ["alice"], source: "codegraph", truncated: false,
    }),
    editContext: () => { editCtxCalls++; return { callers: [{ file: "a.js", line: 3 }], tests: [], history: ["alice — edited"], source: "codegraph" }; },
  };
  try {
    const result = await handleAnalyze({ filePath: path.join(dir, "api.js"), content, cwd: dir }, { graph });
    const f = result.findings.find((x) => x.ruleId === "public-api-change");
    assert.equal(f.tierAdjusted, "escalated");
    assert.equal(f.impact.callerCount, 4);
    assert.equal(editCtxCalls, 1, "edit context fetched for the escalated finding");
    assert.equal(f.editContext.history[0], "alice — edited");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze records a graph-aware taint verdict on an injection finding", async () => {
  const dir = tmpDir({});
  const content = "function q(req){ return db.query(`SELECT * FROM u WHERE id=${req.query.id}`); }\n";
  const graph = {
    id: "fake",
    impact: () => null,
    security: () => ({ tainted: true, dataFlow: [{ symbol: "req.query.id" }, { symbol: "db.query" }], source: "codegraph" }),
  };
  try {
    const result = await handleAnalyze({ filePath: path.join(dir, "db.js"), content, cwd: dir }, { graph });
    const f = result.findings.find((x) => x.ruleId === "sql-injection");
    assert.ok(f, "sql-injection fired");
    assert.equal(f.security.tainted, true);
    assert.match(f.message, /Taint path/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze is a clean no-op when the injected graph is null", async () => {
  const dir = tmpDir({});
  const content = `export function getThing(id) { return id; }\n`;
  try {
    const result = await handleAnalyze({ filePath: path.join(dir, "api.js"), content, cwd: dir }, { graph: null });
    const f = result.findings.find((x) => x.ruleId === "public-api-change");
    assert.ok(f, "finding still present");
    assert.equal(f.impact, undefined, "no graph → no impact");
    assert.equal(f.tierAdjusted, undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze labels trust and embeds a compact capability hint", async () => {
  // Disable the graph in config so the capability hint is deterministic regardless of whether the
  // host has CodeGraph installed/indexed (codeGraphAvailable now also detects ~/.codegraph/projects).
  const dir = tmpDir({ ".diffgate.json": JSON.stringify({ graph: { enabled: false } }) });
  const content = `const key = "sk_live_abcdef0123456789abcd";\n`;
  try {
    const result = await handleAnalyze({ filePath: path.join(dir, "config.js"), content, cwd: dir }, { graph: null });
    const f = result.findings.find((x) => x.ruleId === "hardcoded-secret");
    assert.equal(f.trust, "confirmed", "non-security deterministic rule → confirmed");
    assert.ok(result._diffgate, "carries a capability hint");
    assert.deepEqual(Object.keys(result._diffgate).sort(), ["agentMode", "graph", "llm"]);
    assert.equal(result._diffgate.graph, false, "no graph injected");
    assert.equal(result._diffgate.agentMode, "advisory");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze: injection with no graph is labeled trust:'unconfirmed'", async () => {
  const dir = tmpDir({});
  const content = "function q(req){ return db.query(`SELECT * FROM u WHERE id=${req.query.id}`); }\n";
  try {
    const result = await handleAnalyze({ filePath: path.join(dir, "db.js"), content, cwd: dir }, { graph: null });
    const f = result.findings.find((x) => x.ruleId === "sql-injection");
    assert.equal(f.trust, "unconfirmed", "no taint analysis → unconfirmed");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleAnalyze confirms single-caller-abstraction via the graph when the pack is opted in", async () => {
  const dir = gitRepo({ "a.py": "x = 1\n" });
  fs.writeFileSync(
    path.join(dir, "a.py"),
    "x = 1\n\nclass PaymentGateway:\n    def charge(self, amount):\n        return amount\n"
  );
  fs.writeFileSync(path.join(dir, ".diffgate.json"), JSON.stringify({ rules: { structural: true } }));
  try {
    const withGraph = await handleAnalyze(
      { filePath: "a.py", cwd: dir },
      { graph: { id: "fake", impact: () => ({ callerCount: 0, source: "fake", ambiguous: false, testGaps: [], refs: [] }) } }
    );
    assert.ok(
      withGraph.findings.some((f) => f.ruleId === "single-caller-abstraction"),
      "0 callers confirmed by the graph → kept"
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Regression: handleAnalyze used to build its own pipeline (attachImpact, attachSecurity, ...)
// without ever calling attachStructuralImpact, so a repo that opted into the "structural" pack got
// an UNCONFIRMED "speculative abstraction" finding straight from the detector — no graph backing it
// at all. reviewChanges() (the CLI/gate path) always called the confirmation pass; handleAnalyze
// (the diffgate_analyze MCP tool VS Code and agents call directly) did not.
test("handleAnalyze drops single-caller-abstraction when there is no graph to confirm it", async () => {
  const dir = gitRepo({ "a.py": "x = 1\n" });
  fs.writeFileSync(
    path.join(dir, "a.py"),
    "x = 1\n\nclass PaymentGateway:\n    def charge(self, amount):\n        return amount\n"
  );
  fs.writeFileSync(path.join(dir, ".diffgate.json"), JSON.stringify({ rules: { structural: true } }));
  try {
    const result = await handleAnalyze({ filePath: "a.py", cwd: dir }, { graph: null });
    assert.ok(
      !result.findings.some((f) => f.ruleId === "single-caller-abstraction"),
      "no graph → the detector's optimistic finding must be dropped, not leaked"
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- handleCheckStaged -------------------------------------------------------

test("handleCheckStaged errors on a non-git dir instead of a false 'clean'", async () => {
  const dir = tmpDir({});
  try {
    await assert.rejects(() => handleCheckStaged({ cwd: dir }), /Not a git repository/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleCheckStaged returns { files, tier, counts, blocking } shape", async () => {
  const dir = tmpDir({});
  execSync("git init -q", { cwd: dir });
  const result = await handleCheckStaged({ cwd: dir });
  assert.ok("files" in result, "should have files");
  assert.ok("tier" in result, "should have tier");
  assert.ok("counts" in result, "should have counts");
  assert.ok("blocking" in result, "should have blocking");
  assert.ok(result._diffgate, "carries a capability hint");
  assert.ok(!("config" in result), "omits resolved config from the MCP payload");
  assert.ok(!("agentBudget" in result), "no budget alert when there are no findings");
});

test("handleCheckStaged flags an over-budget finding after escalateAfterTurns checks", async () => {
  const dir = tmpDir({});
  execSync("git init -q", { cwd: dir });
  fs.writeFileSync(path.join(dir, "config.js"), `const key = "sk_live_abcdef0123456789abcd";\n`);
  try {
    const r1 = await handleCheckStaged({ cwd: dir });
    assert.ok(
      r1.files.some((f) => f.findings.some((x) => x.ruleId === "hardcoded-secret")),
      "the secret is found"
    );
    assert.ok(!("agentBudget" in r1), "1st check: under the budget, no alert");

    // The same finding survives a 2nd gate check (default escalateAfterTurns=2) → budget alert.
    const r2 = await handleCheckStaged({ cwd: dir });
    assert.ok(r2.agentBudget, "2nd check: finding outlasted the budget → agentBudget present");
    assert.equal(r2.agentBudget.overBudget[0].rule, "hardcoded-secret");
    assert.equal(r2.agentBudget.overBudget[0].turns, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleCheckStaged includes an agent autonomy verdict (rung per finding + overall)", async () => {
  const dir = tmpDir({});
  execSync("git init -q", { cwd: dir });
  fs.writeFileSync(path.join(dir, "config.js"), `const key = "sk_live_abcdef0123456789abcd";\n`);
  try {
    const r = await handleCheckStaged({ cwd: dir });
    assert.ok(r.verdict, "carries an autonomy verdict block");
    assert.equal(r.verdict.mode, "advisory", "advisory-by-default");
    // hardcoded-secret is a blocking rule → block rung → overall blocked.
    assert.equal(r.verdict.verdict, "blocked");
    const vf = r.verdict.findings.find((f) => f.rule === "hardcoded-secret");
    assert.ok(vf, "the secret appears in the verdict findings");
    assert.equal(vf.rung, "block");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleCheckStaged verdict is 'pass' with no findings", async () => {
  const dir = tmpDir({});
  execSync("git init -q", { cwd: dir });
  try {
    const r = await handleCheckStaged({ cwd: dir });
    assert.ok(r.verdict, "verdict present even on a clean diff");
    assert.equal(r.verdict.verdict, "pass");
    assert.deepEqual(r.verdict.findings, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleCheckStaged threads the over-budget set into the verdict (agrees with the CLI)", async () => {
  const dir = tmpDir({});
  execSync("git init -q", { cwd: dir });
  fs.writeFileSync(path.join(dir, "config.js"), `const key = "sk_live_abcdef0123456789abcd";\n`);
  try {
    const r1 = await handleCheckStaged({ cwd: dir });
    assert.equal(r1.verdict.escalations, 0, "1st check: under budget, nothing escalated");

    // 2nd check: the finding outlasts escalateAfterTurns. The SAME overBudget set drives both the
    // standalone agentBudget alert and the verdict's escalation accounting — so MCP and CLI agree.
    const r2 = await handleCheckStaged({ cwd: dir });
    assert.equal(r2.verdict.escalations, 1, "over-budget finding counted in the verdict");
    const vf = r2.verdict.findings.find((f) => f.rule === "hardcoded-secret");
    assert.equal(vf.overBudget, true, "the over-budget finding is marked in the verdict");
    assert.ok(r2.agentBudget, "and the standalone agentBudget alert still fires");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- handleCapabilities ------------------------------------------------------

test("handleCapabilities reports layers, tools, and the agent budget", async () => {
  // Graph off in config → caps.graph.available is deterministic on any host (incl. one with CodeGraph).
  const dir = tmpDir({ ".diffgate.json": JSON.stringify({ graph: { enabled: false } }) });
  const caps = await handleCapabilities({ cwd: dir });
  assert.equal(caps.core, true);
  assert.equal(caps.graph.available, false);
  assert.equal(caps.llm.available, false);
  assert.ok(caps.availableTools.includes("diffgate_capabilities"));
  assert.ok(!caps.availableTools.includes("diffgate_explain"), "explain hidden with no LLM");
  assert.ok(caps.unavailableTools.includes("diffgate_explain"));
  assert.equal(caps.agent.mode, "advisory");
  assert.equal(caps.agent.maxFixesPerTurn, 3);
  assert.ok(Array.isArray(caps.protocol) && caps.protocol.length > 0);
});

test("diffgate_capabilities is advertised in TOOL_DEFS", () => {
  assert.ok(TOOL_DEFS.some((t) => t.name === "diffgate_capabilities"));
});

// --- handleDeepReview --------------------------------------------------------

// --- prompts -----------------------------------------------------------------

test("listPrompts advertises the agent-workflow prompts with arguments", () => {
  const { prompts } = listPrompts();
  const names = prompts.map((p) => p.name);
  assert.deepEqual(names.sort(), ["review-workflow", "setup-diffgate", "triage-finding"]);
  for (const p of prompts) {
    assert.ok(p.title && p.description, `${p.name} has title + description`);
    assert.ok(Array.isArray(p.arguments), `${p.name} declares arguments[]`);
  }
  assert.equal(PROMPT_DEFS.length, 3);
});

test("getPrompt(review-workflow) returns a user message tuned to repo capabilities", () => {
  const dir = tmpDir({});
  try {
    const res = getPrompt("review-workflow", { mode: "staged" }, { cwd: dir });
    assert.ok(res.description);
    assert.equal(res.messages.length, 1);
    assert.equal(res.messages[0].role, "user");
    const text = res.messages[0].content.text;
    assert.match(text, /diffgate_capabilities/);
    assert.match(text, /diffgate_check_staged\{mode:"staged"\}/);
    assert.match(text, /diffgate_feedback/);
    assert.match(text, /maxFixesPerTurn=3/, "embeds the resolved budget");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("getPrompt(triage-finding) gives rung + trust specific guidance", () => {
  const res = getPrompt("triage-finding", { ruleId: "sql-injection", tier: "orange", trust: "unconfirmed", rung: "escalate" });
  const text = res.messages[0].content.text;
  assert.match(text, /ESCALATE/);
  assert.match(text, /do NOT silently 'fix'/i);
  assert.match(text, /diffgate_feedback\{ ruleId:"sql-injection"/);
});

test("getPrompt(setup-diffgate) includes AI config only when a provider is given", () => {
  const withAi = getPrompt("setup-diffgate", { aiProvider: "anthropic" }).messages[0].content.text;
  assert.match(withAi, /"provider": "anthropic"/);
  assert.match(withAi, /claude-sonnet-4-6/);
  const noAi = getPrompt("setup-diffgate", {}).messages[0].content.text;
  assert.doesNotMatch(noAi, /"ai":/);
  assert.match(noAi, /host mode/);
});

test("getPrompt throws RpcError(-32602) for an unknown prompt", () => {
  assert.throws(() => getPrompt("nope", {}), (e) => e instanceof RpcError && e.code === -32602);
});

// --- resources ---------------------------------------------------------------

test("listResources + listResourceTemplates advertise the context views", () => {
  const { resources } = listResources();
  const uris = resources.map((r) => r.uri).sort();
  assert.deepEqual(uris, ["diffgate://capabilities", "diffgate://learnings", "diffgate://protocol", "diffgate://rules"]);
  for (const r of resources) assert.ok(r.name && r.title && r.mimeType, `${r.uri} fully described`);
  const { resourceTemplates } = listResourceTemplates();
  assert.equal(resourceTemplates[0].uriTemplate, "diffgate://rules/{ruleId}");
  assert.equal(RESOURCE_DEFS.length, 4);
  assert.equal(RESOURCE_TEMPLATE_DEFS.length, 1);
});

test("readResource(diffgate://rules) returns the active rule catalog as JSON", () => {
  const dir = tmpDir({});
  try {
    const res = readResource("diffgate://rules", { cwd: dir });
    assert.equal(res.contents[0].mimeType, "application/json");
    const catalog = JSON.parse(res.contents[0].text);
    assert.ok(Array.isArray(catalog) && catalog.length > 0);
    const secret = catalog.find((r) => r.id === "hardcoded-secret");
    assert.equal(secret.tier, "orange");
    assert.equal(secret.blocking, true);
    assert.equal(secret.pack, "web-security");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("readResource(diffgate://capabilities | protocol | learnings)", () => {
  const dir = tmpDir({});
  try {
    const caps = JSON.parse(readResource("diffgate://capabilities", { cwd: dir }).contents[0].text);
    assert.equal(caps.core, true);

    const proto = readResource("diffgate://protocol", { cwd: dir });
    assert.equal(proto.contents[0].mimeType, "text/markdown");
    assert.match(proto.contents[0].text, /# DiffGate agent protocol/);

    const learnings = JSON.parse(readResource("diffgate://learnings", { cwd: dir }).contents[0].text);
    assert.ok(Array.isArray(learnings.entries), "learnings store has entries[]");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("readResource(diffgate://rules/{id}) resolves the template; missing → RpcError(-32002)", () => {
  const dir = tmpDir({});
  try {
    const one = JSON.parse(readResource("diffgate://rules/hardcoded-secret", { cwd: dir }).contents[0].text);
    assert.equal(one.id, "hardcoded-secret");
    assert.throws(
      () => readResource("diffgate://rules/does-not-exist", { cwd: dir }),
      (e) => e instanceof RpcError && e.code === -32002
    );
    assert.throws(
      () => readResource("diffgate://bogus", { cwd: dir }),
      (e) => e instanceof RpcError && e.code === -32002
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleDeepReview throws when AI is not configured", async () => {
  const dir = tmpDir({});
  const finding = { tier: "orange", ruleId: "hardcoded-secret", title: "Secret", message: "m", code: "x" };
  await assert.rejects(
    () => handleDeepReview({ finding, filePath: "f.js", cwd: dir }),
    /AI is not configured/
  );
});

test("handleDeepReview uses injected fetchImpl and returns verdict", async () => {
  process.env.OPENAI_API_KEY = "sk-test";
  const dir = tmpDir({ "caller.js": "foo();\n" });
  const aiConfig = { enabled: true, provider: "openai", model: "gpt-4o-mini", maxTokens: 512, temperature: 0 };
  const responses = [
    { choices: [{ message: { content: "**Verdict:** likely-safe\n**Why:** no callers found." } }] },
  ];
  let i = 0;
  const fetchImpl = async () => {
    const r = responses[Math.min(i++, responses.length - 1)];
    return { ok: true, status: 200, json: async () => r, text: async () => "" };
  };
  try {
    const result = await handleDeepReview(
      {
        finding: { tier: "orange", ruleId: "public-api-change", title: "Export", message: "m", code: "x" },
        filePath: "thing.js",
        snippet: "export function foo() {}",
        language: "javascript",
        cwd: dir,
      },
      { fetchImpl, config: { ai: aiConfig } }
    );
    assert.match(result.verdict, /likely-safe/);
    assert.ok(Array.isArray(result.toolSteps));
  } finally {
    delete process.env.OPENAI_API_KEY;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- dispatchMessage: the JSON-RPC routing the transport feeds every client message into ---------
// The handlers are unit-tested above; these exercise the *wiring* (method routing, error codes,
// the tools/call result envelope) that every MCP client actually drives.

test("dispatch initialize → negotiated protocol + serverInfo + capabilities", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].id, 1);
  assert.equal(sent[0].result.protocolVersion, "2024-11-05", "echoes a supported requested version");
  assert.equal(sent[0].result.serverInfo.name, "diffgate");
  for (const cap of ["tools", "prompts", "resources"]) {
    assert.ok(cap in sent[0].result.capabilities, `advertises ${cap} capability`);
  }
});

test("dispatch ping → empty result", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 9, method: "ping" });
  assert.deepEqual(sent, [{ jsonrpc: "2.0", id: 9, result: {} }]);
});

test("dispatch tools/list → the full TOOL_DEFS", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  assert.equal(sent[0].result.tools.length, TOOL_DEFS.length);
  assert.deepEqual(sent[0].result.tools.map((t) => t.name).sort(), TOOL_DEFS.map((t) => t.name).sort());
});

test("dispatch initialized / notifications are silent (no id → no reply)", async () => {
  assert.deepEqual(await dispatch({ jsonrpc: "2.0", method: "initialized" }), []);
  assert.deepEqual(await dispatch({ jsonrpc: "2.0", method: "notifications/initialized" }), []);
  // An unknown *notification* (e.g. cancellation) must NOT draw a "method not found" error.
  assert.deepEqual(await dispatch({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } }), []);
});

test("dispatch unknown method WITH an id → -32601 Method not found", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 5, method: "totally/unknown" });
  assert.equal(sent[0].error.code, -32601);
  assert.match(sent[0].error.message, /Method not found/);
});

test("dispatch tools/call unknown tool → -32601 Unknown tool", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "diffgate_nope", arguments: {} } });
  assert.equal(sent[0].error.code, -32601);
  assert.match(sent[0].error.message, /Unknown tool: diffgate_nope/);
});

test("dispatch tools/call success → text-content envelope with isError:false", async () => {
  const dir = tmpDir({});
  const sent = await dispatch({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "diffgate_capabilities", arguments: { cwd: dir } } });
  assert.equal(sent[0].result.isError, false);
  assert.equal(sent[0].result.content[0].type, "text");
  const payload = JSON.parse(sent[0].result.content[0].text);
  assert.ok(payload.version, "capabilities payload round-trips through the envelope");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("dispatch tools/call where the handler throws → graceful isError:true (no crash)", async () => {
  // diffgate_analyze with no filePath / nonexistent file: the handler throws; the loop must
  // convert it to a tool error envelope, never let it escape and kill the server.
  const dir = tmpDir({});
  const sent = await dispatch({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "diffgate_analyze", arguments: { filePath: path.join(dir, "does-not-exist.js"), cwd: dir } } });
  assert.equal(sent[0].result.isError, true);
  assert.match(sent[0].result.content[0].text, /^Error:/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("dispatch tools/call diffgate_analyze with NO filePath → isError, not a thrown crash", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "diffgate_analyze", arguments: {} } });
  assert.equal(sent[0].result.isError, true);
});

test("dispatch tools/call with no params at all → unknown-tool error, no throw", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 12, method: "tools/call" });
  assert.equal(sent[0].error.code, -32601);
});

test("dispatch prompts/get unknown → RpcError(-32602) surfaced as a JSON-RPC error", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 13, method: "prompts/get", params: { name: "no-such-prompt" } });
  assert.equal(sent[0].error.code, -32602);
});

test("dispatch resources/read unknown uri → RpcError(-32002)", async () => {
  const sent = await dispatch({ jsonrpc: "2.0", id: 14, method: "resources/read", params: { uri: "diffgate://nope" } });
  assert.equal(sent[0].error.code, -32002);
});

test("dispatch prompts/list and resources/list route to the catalogs", async () => {
  const p = await dispatch({ jsonrpc: "2.0", id: 15, method: "prompts/list" });
  assert.ok(Array.isArray(p[0].result.prompts) && p[0].result.prompts.length > 0);
  const r = await dispatch({ jsonrpc: "2.0", id: 16, method: "resources/list" });
  assert.equal(r[0].result.resources.length, RESOURCE_DEFS.length);
  const rt = await dispatch({ jsonrpc: "2.0", id: 17, method: "resources/templates/list" });
  assert.equal(rt[0].result.resourceTemplates.length, RESOURCE_TEMPLATE_DEFS.length);
});

// KNOWN GAP (flagged, not fixed): we advertise 2024-11-05 / 2025-03-26, which permit JSON-RPC
// batch *arrays*. createReader parses one and hands the array to dispatchMessage, which reads
// method=undefined / id=undefined and drops it silently. 2025-06-18 (our preferred) removed
// batching, so modern clients never hit this — but this test pins the current behavior so the
// decision (handle batches vs. drop pre-2025-06-18 from SUPPORTED_PROTOCOLS) is deliberate.
test("dispatch of a JSON-RPC batch array is currently a silent no-op (documented limitation)", async () => {
  const batch = [
    { jsonrpc: "2.0", id: 1, method: "ping" },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
  ];
  assert.deepEqual(await dispatch(batch), [], "batching is not yet supported");
});

// --- the three tools that had no direct coverage --------------------------------------------------

test("handleGuidelines: host mode (no AI) returns groups for the agent to self-evaluate", async () => {
  const dir = gitRepo({ "AGENTS.md": "# Rules\n- Never log secrets.\n" });
  try {
    fs.writeFileSync(path.join(dir, "app.js"), "function f() {\n  console.log(secret);\n}\n");
    const res = await handleGuidelines({ cwd: dir, mode: "working" });
    assert.equal(res.mode, "host", "no provider configured → self-review (host) mode");
    assert.ok(res.payload.groups.length >= 1, "the changed file is grouped under its guideline set");
    assert.match(res.payload.groups[0].guidelines, /Never log secrets/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleGuidelines: clean repo with no guideline files → model mode, no findings", async () => {
  const dir = gitRepo();
  try {
    const res = await handleGuidelines({ cwd: dir, mode: "working" });
    assert.equal(res.mode, "model");
    assert.deepEqual(res.findings, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleFeedback: 'dismiss' records a learning and persists it to .diffgate/learnings.json", async () => {
  const dir = gitRepo();
  try {
    const out = await handleFeedback({ ruleId: "hardcoded-secret", code: 'const k = "x";', verdict: "dismiss", note: "test key", cwd: dir });
    assert.ok(out.recorded, "returns the recorded entry");
    assert.equal(out.recorded.ruleId, "hardcoded-secret");
    assert.equal(out.recorded.verdict, "dismiss");
    const learnings = JSON.parse(fs.readFileSync(path.join(dir, ".diffgate", "learnings.json"), "utf-8"));
    assert.ok(learnings.entries.some((e) => e.ruleId === "hardcoded-secret"), "persisted to disk");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("handleFeedback round-trips through dispatch tools/call", async () => {
  const dir = gitRepo();
  try {
    const sent = await dispatch({ jsonrpc: "2.0", id: 20, method: "tools/call", params: { name: "diffgate_feedback", arguments: { ruleId: "sql-injection", code: "q", verdict: "confirm", cwd: dir } } });
    assert.equal(sent[0].result.isError, false);
    const payload = JSON.parse(sent[0].result.content[0].text);
    assert.equal(payload.recorded.verdict, "confirm");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- createReader: malformed / adversarial framing ------------------------------------------------

test("createReader silently drops a non-JSON line and still parses the next valid one", (t, done) => {
  const stream = new PassThrough();
  const reader = createReader(stream);
  const got = [];
  reader.onMessage((msg) => {
    got.push(msg.id);
    // Only the valid message should ever surface; the garbage line must not throw or emit.
    assert.equal(msg.id, 99);
    done();
  });
  stream.push(Buffer.from("this is not json\n"));
  stream.push(line({ jsonrpc: "2.0", id: 99, method: "ping" }));
});

// --- real subprocess: the actual `diffgate mcp` binary over stdio ---------------------------------
// Proves runMcpServer wires stdin→reader→dispatch→writer→stdout for real, not just the extracted
// function. Guards against transport regressions (framing, buffering, process not staying alive).
test("runMcpServer subprocess: initialize + tools/list over real stdio", (t, done) => {
  const cliPath = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
  const proc = spawn(process.execPath, [cliPath, "mcp"], { stdio: ["pipe", "pipe", "pipe"], cwd: tmpDir({}) });
  const responses = [];
  let buf = "";
  const timer = setTimeout(() => { proc.kill(); done(new Error("MCP subprocess did not respond within 10s")); }, 10000);

  proc.stdout.on("data", (d) => {
    buf += d.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const s = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (s) responses.push(JSON.parse(s));
    }
    if (responses.length >= 2) {
      clearTimeout(timer);
      try {
        const init = responses.find((r) => r.id === 1);
        const tools = responses.find((r) => r.id === 2);
        assert.equal(init.result.serverInfo.name, "diffgate");
        assert.ok(Array.isArray(tools.result.tools) && tools.result.tools.length > 0);
        done();
      } catch (e) {
        done(e);
      } finally {
        proc.kill();
      }
    }
  });

  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }) + "\n");
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
});
