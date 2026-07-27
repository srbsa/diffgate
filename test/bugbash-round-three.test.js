// Bug-bash round three — regression tests for the feature-audit and security-audit fixes.
//
// Every test here pins a defect that shipped *green*: the suite passed while the code was wrong,
// because no test exercised the path. The C# `pass-through-wrapper` bug is the clearest case — the
// rule could never match a C# method call for two independent reasons, and nothing noticed because
// `test/structural-*.test.js` contained no C# case at all. So each test below is written as the
// mutation that would have caught the original bug, not as a restatement of the fix.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";

import { analyze, initTreeSitter, treeSitterReady, DEFAULT_CONFIG } from "../dist/core/index.js";
import { resolveProvider } from "../dist/core/llm/registry.js";
import { isAiAvailable, complete } from "../dist/core/llm/index.js";
import { dispatchMessage, handleAnalyze } from "../dist/mcp.js";
import { detectEntryPoints, detectJsEntryPoints } from "../dist/core/graph/entry-points.js";
import { computeTreeComplexity, profileFor } from "../dist/core/complexity.js";
import { parseTs } from "../dist/core/parsers/treesitter.js";
import { parseJs } from "../dist/core/parsers/javascript.js";

await initTreeSitter();

const skipUnless = (lang) => {
  if (treeSitterReady(lang)) return false;
  console.log(`tree-sitter grammar for ${lang} unavailable — skipping`);
  return true;
};

const withRule = (ruleId) => ({ ...DEFAULT_CONFIG, rules: { ...DEFAULT_CONFIG.rules, [ruleId]: { enabled: true } } });
const allLines = (src) => new Set(src.split("\n").map((_, i) => i + 1));
const findingsFor = (src, filePath, ruleId, config = DEFAULT_CONFIG) =>
  analyze({ filePath, content: src, changedLines: allLines(src), config }).findings.filter((f) => f.ruleId === ruleId);

// ===========================================================================
// #2 / #11 — C# was structurally invisible: wrong call node type, and every
// argument wrapped in an `argument` node the identifier check never unwrapped.
// ===========================================================================

test("C#: pass-through-wrapper fires (invocation_expression + argument unwrap)", () => {
  if (skipUnless("csharp")) return;
  const src = `class A {\n    public int Wrap(int x) { return Inner(x); }\n}`;
  assert.equal(findingsFor(src, "a.cs", "pass-through-wrapper").length, 1);
});

test("C#: pass-through-wrapper stays quiet when the call reshapes its arguments", () => {
  if (skipUnless("csharp")) return;
  const src = `class A {\n    public int Wrap(int x) { return Inner(x + 1); }\n}`;
  assert.equal(findingsFor(src, "a.cs", "pass-through-wrapper").length, 0);
});

test("C#: a constructor's complexity is scored (constructor_declaration)", () => {
  if (skipUnless("csharp")) return;
  // Deep nesting inside a constructor — invisible while functionTypes was method_declaration only.
  const src = `class A {
    public A(int x) {
        if (x > 0) {
            if (x > 1) {
                if (x > 2) {
                    if (x > 3) {
                        if (x > 4) { Bar(); }
                    }
                }
            }
        }
    }
}`;
  assert.equal(findingsFor(src, "a.cs", "deep-nesting").length, 1);
});

// ===========================================================================
// #9 / #10 — `match` is the same construct as `switch`, which every other
// profile already scored. Both scored a flat zero.
// ===========================================================================

// Asserted as a differential against the same function with the `match` removed, rather than
// against a threshold: a threshold test passes for the wrong reason if some *other* construct in
// the fixture carries the score. The delta isolates `match` itself, which is what regressed.
const metricsOf = (src, lang) => computeTreeComplexity(parseTs(src, lang), profileFor(lang))[0].metrics;

test("Python: match_statement contributes cognitive complexity and a nesting level", () => {
  if (skipUnless("python")) return;
  const withMatch = metricsOf(`def f(x):\n    match x:\n        case 1:\n            return 2\n        case _:\n            return 3\n`, "python");
  const without = metricsOf(`def f(x):\n    return 3\n`, "python");
  assert.equal(withMatch.cognitive - without.cognitive, 1, "match scores exactly once, like switch");
  assert.equal(withMatch.nesting - without.nesting, 1, "match opens one nesting level");
});

test("PHP: match_expression contributes cognitive complexity and a nesting level", () => {
  if (skipUnless("php")) return;
  const withMatch = metricsOf(`<?php\nfunction f($x) {\n  return match($x) { 1 => 2, default => 3 };\n}\n`, "php");
  const without = metricsOf(`<?php\nfunction f($x) {\n  return 3;\n}\n`, "php");
  assert.equal(withMatch.cognitive - without.cognitive, 1, "match scores exactly once, like switch");
  assert.equal(withMatch.nesting - without.nesting, 1, "match opens one nesting level");
});

// ===========================================================================
// #8 — diff-churn-ratio existed only on the Babel backend; 7 languages had no
// implementation at all while the changelog claimed all 8.
// ===========================================================================

test("diff-churn-ratio fires on a tree-sitter language (Python)", () => {
  if (skipUnless("python")) return;
  const lines = ["def f():"];
  for (let i = 0; i < 30; i++) lines.push(`    # comment ${i}`);
  lines.push("    return 1");
  const src = lines.join("\n");
  assert.equal(findingsFor(src, "sparse.py", "diff-churn-ratio", withRule("diff-churn-ratio")).length, 1);
});

// ===========================================================================
// #3 — ts-over-generic counted every node whose type name contained "Type",
// so array/tuple/union/function types each added a phantom level.
// ===========================================================================

const overGeneric = (src) => findingsFor(src, "t.ts", "ts-over-generic", withRule("ts-over-generic"));

test("ts-over-generic: nested ARRAY types are not generic nesting", () => {
  assert.equal(overGeneric("type A = string[][][][];").length, 0);
});

test("ts-over-generic: a union inside an array is not generic nesting", () => {
  assert.equal(overGeneric("type A = (A | B | C | D)[];").length, 0);
});

test("ts-over-generic: a curried function type is not generic nesting", () => {
  assert.equal(overGeneric("type F = (a: string) => (b: number) => Item;").length, 0);
});

test("ts-over-generic: genuine deep generic instantiation still fires", () => {
  const hits = overGeneric("type M = Map<string, Promise<Array<Set<number>>>>;");
  assert.equal(hits.length, 1);
  assert.match(hits[0].message, /4 levels/);
});

// ===========================================================================
// #4 / #5 / #15 — class and object methods, and functions bound through a
// member expression or a private name, were skipped by the Babel-path rules.
// ===========================================================================

test("pass-through-wrapper: fires on a ClassMethod and an ObjectMethod", () => {
  const src = `class A { foo(x) { return bar(x); } }\nconst o = { baz(x) { return qux(x); } };\n`;
  assert.equal(findingsFor(src, "a.js", "pass-through-wrapper").length, 2);
});

test("pass-through-wrapper: fires on member-expression and private-name bindings", () => {
  const src = `class A { constructor(){ this.foo = (x) => bar(x); } #priv(x) { return zap(x); } }\nconst o = {}; o.hop = (x) => skip(x);\n`;
  const symbols = findingsFor(src, "b.js", "pass-through-wrapper").map((f) => f.symbol).sort();
  assert.deepEqual(symbols, ["foo", "hop", "priv"]);
});

// ===========================================================================
// #1 — a user's explicit tier/blocking override was silently discarded by a
// rule's own per-finding tier adjustment.
// ===========================================================================

const GUARDED_TRAVERSAL = `
const path = require('path');
function handler(req) {
  const safe = path.basename(req.query.file);
  fs.readFileSync(path.join('/data', safe));
}
`;

test("a rule's dynamic de-escalation applies when the user has NOT pinned the tier", () => {
  const hits = findingsFor(GUARDED_TRAVERSAL, "a.js", "path-traversal");
  assert.ok(hits.length > 0);
  assert.ok(hits.every((f) => f.tier === "yellow" && f.tierAdjusted === "deescalated"));
});

test("an explicit config tier override survives a rule's dynamic de-escalation", () => {
  const config = { ...DEFAULT_CONFIG, rules: { ...DEFAULT_CONFIG.rules, "path-traversal": { tier: "orange" } } };
  const hits = findingsFor(GUARDED_TRAVERSAL, "a.js", "path-traversal", config);
  assert.ok(hits.length > 0);
  assert.ok(hits.every((f) => f.tier === "orange"), "user pin must win over emit-site tier");
  assert.ok(hits.every((f) => f.tierAdjusted === undefined), "nothing was adjusted, so don't claim it was");
});

// ===========================================================================
// #7 / #16 — entry-point detection dropped handlers that shared a dedup key,
// and never looked inside an array-of-middleware argument.
// ===========================================================================

test("JS entry points: two inline handlers on ONE call are both kept", () => {
  const src = `app.get('/path', (req, res, next) => next(), (req, res) => res.send());`;
  assert.equal(detectJsEntryPoints(parseJs(src, "x.js"), "x.js").length, 2);
});

test("JS entry points: handlers inside an array argument are detected", () => {
  const src = `app.get('/path', [mw1, mw2], handler);`;
  const names = detectJsEntryPoints(parseJs(src, "x.js"), "x.js").map((e) => e.qualName);
  assert.deepEqual(names, ["mw1", "mw2", "handler"]);
});

// ===========================================================================
// #12 / #13 — Java entry-point detection was entirely dead (`modifiers` is not
// a field in tree-sitter-java), and Go missed TitleCase router verbs.
// ===========================================================================

test("Java entry points: JAX-RS @GET is detected", () => {
  if (skipUnless("java")) return;
  const src = `\nclass Foo {\n  @GET\n  @Path("/x")\n  public String get() { return "y"; }\n}`;
  const eps = detectEntryPoints(parseTs(src, "java"), "Foo.java", "java");
  assert.equal(eps.length, 1);
  assert.equal(eps[0].qualName, "Foo.get");
});

test("Java entry points: Spring @GetMapping still works (the field bug killed this too)", () => {
  if (skipUnless("java")) return;
  const src = `\nclass Foo {\n  @GetMapping("/users")\n  public String users() { return "y"; }\n}`;
  const eps = detectEntryPoints(parseTs(src, "java"), "Foo.java", "java");
  assert.equal(eps.length, 1);
  assert.equal(eps[0].route, "/users");
});

test("Go entry points: Fiber/chi TitleCase verbs are detected", () => {
  if (skipUnless("go")) return;
  const src = `package m\nfunc main() {\n  app.Get("/path", handler)\n}`;
  const eps = detectEntryPoints(parseTs(src, "go"), "main.go", "go");
  assert.equal(eps.length, 1);
  assert.equal(eps[0].route, "/path");
});

test("Go entry points: an ordinary .Get(key, ok) call is NOT a route", () => {
  if (skipUnless("go")) return;
  // The TitleCase verbs collide with everyday Go method names; only a string-literal first
  // argument distinguishes a router registration from `cache.Get(key, ok)`.
  const src = `package m\nfunc main() {\n  cache.Get(key, ok)\n}`;
  assert.equal(detectEntryPoints(parseTs(src, "go"), "main.go", "go").length, 0);
});

// ===========================================================================
// SECURITY — repo-tracked .diffgate.json must not be able to redirect an
// outbound AI call, nor name which environment variable rides along with it.
// (Same shape as CVE-2026-21852 in Claude Code.)
// ===========================================================================

test("security: a repo-config baseURL pointing at a public host is refused", () => {
  const p = resolveProvider({ ai: { provider: "custom", baseURL: "https://attacker.example.com/collect" } });
  assert.notEqual(p.baseURL, "https://attacker.example.com/collect");
  assert.equal(p.baseURL, null, "custom preset has no default endpoint, so it must resolve to none");
});

test("security: a repo-config apiKeyEnv naming an unrelated secret is ignored", () => {
  const p = resolveProvider({ ai: { provider: "anthropic", apiKeyEnv: "AWS_SECRET_ACCESS_KEY" } });
  assert.equal(p.apiKeyEnv, "ANTHROPIC_API_KEY", "must fall back to the preset's own key env");
});

test("security: a known provider key env from repo config is still honored", () => {
  assert.equal(resolveProvider({ ai: { apiKeyEnv: "OPENAI_API_KEY" } }).apiKeyEnv, "OPENAI_API_KEY");
});

test("security: a loopback baseURL from repo config is still honored (local model case)", () => {
  const p = resolveProvider({ ai: { provider: "custom", baseURL: "http://localhost:9999/v1" } });
  assert.equal(p.baseURL, "http://localhost:9999/v1");
  assert.equal(p.local, true);
});

test("security: isAiAvailable reports false when no trusted endpoint resolved", () => {
  assert.equal(isAiAvailable({ ai: { enabled: true, provider: "custom", baseURL: "https://attacker.example.com" } }), false);
});

test("security: complete() refuses to send anything without a trusted endpoint", async () => {
  let called = false;
  const spyFetch = async () => { called = true; return { ok: true, status: 200, json: async () => ({}) }; };
  await assert.rejects(
    () => complete({
      prompt: "hi",
      config: { ai: { enabled: true, provider: "custom", baseURL: "https://attacker.example.com", model: "m" } },
      fetchImpl: spyFetch,
    }),
    /No AI endpoint configured/
  );
  assert.equal(called, false, "no request may leave the process");
});

// ===========================================================================
// SECURITY — MCP transport and tool-argument hardening.
// ===========================================================================

test("security: dispatchMessage survives a null message instead of crashing the server", async () => {
  const out = [];
  await dispatchMessage(null, (o) => out.push(o));      // used to throw a TypeError
  await dispatchMessage("a string", (o) => out.push(o));
  await dispatchMessage(42, (o) => out.push(o));
  assert.deepEqual(out, [], "malformed messages are dropped, not answered");
  // and the dispatcher still works afterwards
  await dispatchMessage({ jsonrpc: "2.0", id: 1, method: "ping" }, (o) => out.push(o));
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].result, {});
});

test("security: diffgate_analyze refuses a filePath outside the repo", async () => {
  const outside = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "dg-outside-")), "secrets.env");
  // Deliberately NOT secret-shaped: the assertion is that the path is refused before the file is
  // ever read, so a realistic key here would only be a committed credential in our own repo.
  fs.writeFileSync(outside, "PLACEHOLDER=not-a-real-value\n");
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "dg-repo-"));
  try {
    await assert.rejects(
      () => handleAnalyze({ filePath: outside, cwd: repo }),
      /outside the repo/
    );
  } finally {
    fs.rmSync(outside, { force: true });
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test("security: diffgate_analyze still accepts in-repo relative and absolute paths", async () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "dg-repo-"));
  fs.writeFileSync(path.join(repo, "ok.js"), "const x = 1;\n");
  try {
    assert.ok(await handleAnalyze({ filePath: "ok.js", cwd: repo }));
    assert.ok(await handleAnalyze({ filePath: path.join(repo, "ok.js"), cwd: repo }));
    // a file that does not exist yet (agent-supplied content) must still resolve inside the repo
    assert.ok(await handleAnalyze({ filePath: "new.js", content: "const y = 2;\n", cwd: repo }));
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});
