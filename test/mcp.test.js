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

// --- handleCheckStaged -------------------------------------------------------

test("handleCheckStaged returns { files, tier, counts, blocking } shape", async () => {
  const dir = tmpDir({});
  const result = await handleCheckStaged({ cwd: dir });
  assert.ok("files" in result, "should have files");
  assert.ok("tier" in result, "should have tier");
  assert.ok("counts" in result, "should have counts");
  assert.ok("blocking" in result, "should have blocking");
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
