import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";

import { TOOLS } from "../dist/core/agent/tools.js";
import { deepReview } from "../dist/core/agent/index.js";

const readTool = TOOLS.find((t) => t.name === "read_file");
const grepTool = TOOLS.find((t) => t.name === "grep");

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "grg-agent-"));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

function queuedFetch(responses, cap) {
  let i = 0;
  return async (url, opts) => {
    cap.calls.push({ url, body: JSON.parse(opts.body) });
    const r = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return { ok: true, status: 200, json: async () => r, text: async () => "" };
  };
}

test("read_file reads a range and refuses path traversal", () => {
  const dir = tmpRepo({ "foo.js": "line one\nline two\nline three\n" });
  try {
    const out = readTool.run({ path: "foo.js", startLine: 1, endLine: 2 }, { cwd: dir });
    assert.match(out, /1: line one/);
    assert.match(out, /2: line two/);
    assert.doesNotMatch(out, /line three/);
    assert.throws(() => readTool.run({ path: "../../../etc/passwd" }, { cwd: dir }), /escapes/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("grep finds matches (JS fallback when not a git repo)", () => {
  const dir = tmpRepo({ "a.js": "const x = processPayment(1);\n", "b.js": "nothing here\n" });
  try {
    const parsed = JSON.parse(grepTool.run({ pattern: "processPayment" }, { cwd: dir }));
    assert.ok(parsed.matches.length >= 1);
    assert.equal(parsed.matches[0].file, "a.js");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("deepReview drives an OpenAI tool loop and returns a verdict", async () => {
  process.env.OPENAI_API_KEY = "sk-test";
  const dir = tmpRepo({ "caller.js": "import { processPayment } from './pay';\nprocessPayment(1);\n" });
  const cap = { calls: [] };
  const responses = [
    { choices: [{ message: { content: "", tool_calls: [{ id: "c1", function: { name: "grep", arguments: JSON.stringify({ pattern: "processPayment" }) } }] } }] },
    { choices: [{ message: { content: "**Verdict:** confirmed-risk\n**Why:** caller.js calls it." } }] },
  ];
  try {
    const res = await deepReview({
      finding: { tier: "orange", ruleId: "signature-drift", title: "Sig change", message: "m", code: "x" },
      filePath: "pay.js",
      snippet: "export function processPayment(a, b) {}",
      language: "javascript",
      cwd: dir,
      config: { ai: { enabled: true, provider: "openai", model: "m" } },
      fetchImpl: queuedFetch(responses, cap),
    });
    assert.match(res.verdict, /confirmed-risk/);
    assert.equal(res.verdictClass, "confirmed-risk");
    assert.equal(res.transcript.length, 1);
    assert.equal(res.transcript[0].name, "grep");
    // the 2nd request must carry the tool result back to the model
    assert.ok(cap.calls[1].body.messages.some((m) => m.role === "tool"));
  } finally {
    delete process.env.OPENAI_API_KEY;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("deepReview drives an Anthropic tool loop and returns a verdict", async () => {
  process.env.ANTHROPIC_API_KEY = "ak-test";
  const dir = tmpRepo({ "caller.js": "useThing();\n" });
  const cap = { calls: [] };
  const responses = [
    { content: [{ type: "tool_use", id: "t1", name: "read_file", input: { path: "caller.js" } }], stop_reason: "tool_use" },
    { content: [{ type: "text", text: "**Verdict:** likely-safe" }], stop_reason: "end_turn" },
  ];
  try {
    const res = await deepReview({
      finding: { tier: "orange", ruleId: "public-api-change", title: "Export", message: "m", code: "x" },
      filePath: "thing.js",
      snippet: "export function useThing() {}",
      language: "javascript",
      cwd: dir,
      config: { ai: { enabled: true, provider: "anthropic", model: "claude-x" } },
      fetchImpl: queuedFetch(responses, cap),
    });
    assert.match(res.verdict, /likely-safe/);
    assert.equal(res.verdictClass, "likely-safe");
    assert.equal(res.transcript[0].name, "read_file");
    // the 2nd request must carry a tool_result block back
    assert.ok(
      cap.calls[1].body.messages.some(
        (m) => Array.isArray(m.content) && m.content.some((c) => c.type === "tool_result")
      )
    );
  } finally {
    delete process.env.ANTHROPIC_API_KEY;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
