import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";

import { applyDepthCap, resolveGuidelinesForFile, evaluateGuidelines } from "../dist/core/guidelines/index.js";
import { DEFAULT_CONFIG } from "../dist/core/index.js";

function fakeFetch(captured, content) {
  return async (url, opts) => {
    captured.url = url;
    captured.body = JSON.parse(opts.body);
    return { ok: true, status: 200, json: async () => ({ model: "q", choices: [{ message: { content } }] }), text: async () => "" };
  };
}

function tmpTree(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "grg-gl-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

test("applyDepthCap keeps nearest N-1 + repo-root, drops the middle", () => {
  const nearestFirst = ["a/b/c/AGENTS.md", "a/b/AGENTS.md", "a/AGENTS.md", "AGENTS.md"];
  const { kept, dropped } = applyDepthCap(nearestFirst, 3);
  assert.deepEqual(kept, ["a/b/c/AGENTS.md", "a/b/AGENTS.md", "AGENTS.md"]);
  assert.deepEqual(dropped, ["a/AGENTS.md"]);
});

test("applyDepthCap is a no-op when within the cap", () => {
  const files = ["a/AGENTS.md", "AGENTS.md"];
  const { kept, dropped } = applyDepthCap(files, 3);
  assert.deepEqual(kept, files);
  assert.deepEqual(dropped, []);
});

test("resolveGuidelinesForFile walks up the tree and respects the depth cap", () => {
  const root = tmpTree({
    "AGENTS.md": "# Style\nRoot rule.",
    "a/AGENTS.md": "# Style\nMid rule.",
    "a/b/AGENTS.md": "# Style\nInner rule.",
    "a/b/c/AGENTS.md": "# Style\nDeepest rule.",
    "a/b/c/file.ts": "const x = 1;",
  });
  const config = { ...DEFAULT_CONFIG, guidelines: { ...DEFAULT_CONFIG.guidelines, maxDepth: 3 } };
  const rs = resolveGuidelinesForFile(path.join(root, "a/b/c/file.ts"), root, config);
  assert.ok(rs);
  assert.deepEqual(rs.sources, ["a/b/c/AGENTS.md", "a/b/AGENTS.md", "AGENTS.md"]);
  assert.deepEqual(rs.dropped, ["a/AGENTS.md"]);
  assert.match(rs.text, /Deepest rule/);
  assert.match(rs.text, /Root rule/);
  assert.doesNotMatch(rs.text, /Mid rule/);
});

test("resolveGuidelinesForFile returns null when disabled or no files apply", () => {
  const root = tmpTree({ "x.ts": "const y = 2;" });
  const config = { ...DEFAULT_CONFIG };
  assert.equal(resolveGuidelinesForFile(path.join(root, "x.ts"), root, config), null);
  const off = { ...DEFAULT_CONFIG, guidelines: { ...DEFAULT_CONFIG.guidelines, enabled: false } };
  const root2 = tmpTree({ "AGENTS.md": "rule", "x.ts": "const y = 2;" });
  assert.equal(resolveGuidelinesForFile(path.join(root2, "x.ts"), root2, off), null);
});

test("evaluateGuidelines host backend returns materials for the agent (no model)", async () => {
  const root = tmpTree({ "AGENTS.md": "# Security\nNever log secrets.", "x.ts": "console.log(token)" });
  const config = { ...DEFAULT_CONFIG, guidelines: { ...DEFAULT_CONFIG.guidelines, evaluator: "host" } };
  const res = await evaluateGuidelines({
    root, config,
    files: [{ filePath: path.join(root, "x.ts"), rel: "x.ts", language: "javascript", content: "console.log(token)", changedLines: [1] }],
  });
  assert.equal(res.mode, "host");
  assert.equal(res.payload.groups.length, 1);
  assert.deepEqual(res.payload.groups[0].sources, ["AGENTS.md"]);
  assert.match(res.payload.groups[0].guidelines, /Never log secrets/);
  assert.equal(res.payload.groups[0].hunks.length, 1);
  // Host mode is a self-review, never an independent gate.
  assert.equal(res.payload.independent, false);
  assert.equal(res.payload.advisory, true);
  // Structural restatement so a harness can honor the constraint without parsing prose.
  assert.equal(res.payload.blocking, false);
  assert.match(res.payload.reason, /never block/i);
  assert.match(res.payload.instructions, /SELF-REVIEW/);
  assert.match(res.payload.instructions, /do not block/i);
});

test("evaluateGuidelines model backend parses findings and caps tier", async () => {
  const root = tmpTree({ "AGENTS.md": "# Style\nUse const.", "x.ts": "var z = 3;" });
  const cap = {};
  const config = {
    ...DEFAULT_CONFIG,
    guidelines: { ...DEFAULT_CONFIG.guidelines, evaluator: "model", tier: "yellow" },
    ai: { ...DEFAULT_CONFIG.ai, enabled: true, provider: "lmstudio", model: "q" },
  };
  const content = '[{"file":"x.ts","line":1,"title":"prefer const","message":"replace var with const","severity":"error"}]';
  const res = await evaluateGuidelines({
    root, config,
    files: [{ filePath: path.join(root, "x.ts"), rel: "x.ts", language: "javascript", content: "var z = 3;", changedLines: [1] }],
    fetchImpl: fakeFetch(cap, content),
  });
  assert.equal(res.mode, "model");
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].ruleId, "guideline");
  assert.equal(res.findings[0].tier, "yellow", "error severity capped to configured yellow");
  assert.equal(res.findings[0].blocking, false);
  assert.match(res.findings[0].message, /per AGENTS\.md/);
  // the guideline text was sent to the model
  assert.match(cap.body.messages[1].content, /Use const/);
});
