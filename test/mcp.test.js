import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { Readable, Writable, PassThrough } from "stream";

import {
  createReader,
  createWriter,
  handleAnalyze,
  handleCheckStaged,
  handleCapabilities,
  handleDeepReview,
  TOOL_DEFS,
} from "../dist/mcp.js";

function tmpDir(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "grg-mcp-"));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

// Build a framed MCP message (Content-Length + body) for testing the reader.
function frame(obj) {
  const body = JSON.stringify(obj);
  const len = Buffer.byteLength(body, "utf-8");
  return Buffer.from(`Content-Length: ${len}\r\n\r\n${body}`);
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

test("createWriter emits a correct Content-Length frame", () => {
  const chunks = [];
  const stream = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } });
  const send = createWriter(stream);
  send({ jsonrpc: "2.0", id: 1, result: { ok: true } });
  const out = chunks.join("");
  assert.match(out, /Content-Length: \d+\r\n\r\n/);
  const body = out.replace(/^.*\r\n\r\n/, "");
  assert.deepEqual(JSON.parse(body), { jsonrpc: "2.0", id: 1, result: { ok: true } });
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
  const dir = tmpDir({});
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

// --- handleCheckStaged -------------------------------------------------------

test("handleCheckStaged returns { files, tier, counts, blocking } shape", async () => {
  const dir = tmpDir({});
  const result = await handleCheckStaged({ cwd: dir });
  assert.ok("files" in result, "should have files");
  assert.ok("tier" in result, "should have tier");
  assert.ok("counts" in result, "should have counts");
  assert.ok("blocking" in result, "should have blocking");
  assert.ok(result._diffgate, "carries a capability hint");
  assert.ok(!("config" in result), "omits resolved config from the MCP payload");
});

// --- handleCapabilities ------------------------------------------------------

test("handleCapabilities reports layers, tools, and the agent budget", async () => {
  const dir = tmpDir({});
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
