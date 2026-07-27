// Step-2 guard: the shared tree-sitter core's declarative sink discovery (`sinkQuery` →
// `compileTsQuery`) must stay LIVE, not silently degrade to the full-walk fallback. If a sink query
// stopped compiling against a grammar, every existing rule test would still pass (the fallback walk
// produces identical findings) — so this file asserts the query path itself is exercised, and that
// an invalid query degrades gracefully. Behavior-neutrality of the path is covered by the exact-count
// assertions in python-rules / php-rules / scenarios, which run with `sinkQuery` present and tree-sitter
// initialized.
import test from "node:test";
import assert from "node:assert/strict";
import { initTreeSitter, treeSitterReady } from "../dist/core/index.js";
import { compileTsQuery } from "../dist/core/parsers/treesitter.js";

// Mirrors the real rules' sink queries (python.ts / php.ts).
const PY_SINK = "(call) @sink";
const PHP_SINK = "[(function_call_expression) (member_call_expression) (nullsafe_member_call_expression) (scoped_call_expression)] @sink";

test("python sink query compiles against the loaded grammar (query path is live)", async (t) => {
  await initTreeSitter();
  if (!treeSitterReady("python")) return t.skip("tree-sitter python grammar unavailable");
  assert.ok(compileTsQuery("python", PY_SINK), "python sink query must compile — else rules silently fall back to the walk");
});

test("php sink query compiles against the loaded grammar (query path is live)", async (t) => {
  await initTreeSitter();
  if (!treeSitterReady("php")) return t.skip("tree-sitter php grammar unavailable");
  assert.ok(compileTsQuery("php", PHP_SINK), "php sink query must compile — else rules silently fall back to the walk");
});

test("an invalid query returns null so the engine degrades to the full walk", async (t) => {
  await initTreeSitter();
  if (!treeSitterReady("python")) return t.skip("tree-sitter python grammar unavailable");
  assert.equal(compileTsQuery("python", "(this_node_type_does_not_exist) @x"), null);
});

test("compiled queries are memoized (same object for the same lang+source)", async (t) => {
  await initTreeSitter();
  if (!treeSitterReady("python")) return t.skip("tree-sitter python grammar unavailable");
  assert.strictEqual(compileTsQuery("python", PY_SINK), compileTsQuery("python", PY_SINK));
});

// ===========================================================================
// Incremental grammar init.
//
// `initTreeSitter` used to return the first call's promise verbatim, so the
// first language list won permanently. A host that warmed up with one subset
// and later needed another language got a resolved promise and no parser —
// which every coverage check downstream reads as "this language has nothing in
// it", not as an error.
// ===========================================================================

test("initTreeSitter loads a language requested by a LATER call", async () => {
  const { initTreeSitter, treeSitterReady, parseTs } = await import("../dist/core/parsers/treesitter.js");

  await initTreeSitter(["python"]);
  assert.equal(treeSitterReady("python"), true, "first call loads what it asked for");

  await initTreeSitter(["ruby"]);
  assert.equal(treeSitterReady("ruby"), true, "a second call must load a language the first skipped");
  assert.equal(treeSitterReady("python"), true, "and must not evict what was already loaded");

  const tree = parseTs(`def x\n  1\nend\n`, "ruby");
  assert.ok(tree && tree.rootNode, "the late-loaded grammar actually parses");
});
