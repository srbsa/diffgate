// Language coverage for the call graph must track whether a grammar actually LOADED, not merely
// whether this build ships a profile for the language.
//
// The distinction is load-bearing. `impact()` returns null (unknown) for an uncovered language and a
// real count for a covered one, and `attachStructuralImpact` treats a count of <=1 as proof that an
// abstraction is speculative. So a language whose grammar failed to load — the VS Code extension
// path, a CJS bundle that can't resolve node_modules, any host that skipped `initTreeSitter` — would
// report "no callers" for code it never parsed a single line of, and that unknown would be published
// as a finding.
//
// This file owns the reset because `_resetTreeSitter` is global module state: run it inside a suite
// that shares an init with other tests and it silently unloads their grammars.
import test from "node:test";
import assert from "node:assert/strict";
import { isCallGraphLanguage } from "../dist/core/graph/callgraph.js";
import { initTreeSitter, treeSitterReady, _resetTreeSitter } from "../dist/core/parsers/treesitter.js";

/** Languages that have a call-graph profile AND a tree-sitter grammar (no Babel fallback). */
const TREE_SITTER_PROFILE_LANGS = ["python", "go", "java", "kotlin", "ruby", "php", "csharp"];

test("with no grammar loaded, every tree-sitter language reports NO coverage", () => {
  _resetTreeSitter();
  try {
    for (const lang of TREE_SITTER_PROFILE_LANGS) {
      assert.equal(treeSitterReady(lang), false, `${lang}: precondition — grammar is unloaded`);
      assert.equal(
        isCallGraphLanguage(lang),
        false,
        `${lang}: an unloaded grammar must read as "no data", not as "no callers"`
      );
    }
  } finally {
    _resetTreeSitter();
  }
});

test("the Babel path is covered even with tree-sitter fully unloaded", () => {
  _resetTreeSitter();
  try {
    // JS/TS never touches tree-sitter in this build — its call graph comes off the Babel AST, which
    // is bundled. Coverage here must NOT regress when grammars are missing. Note the argument is a
    // *language*, not an extension: `detectLanguage` already folds .jsx/.tsx into javascript/typescript.
    for (const lang of ["javascript", "typescript"]) {
      assert.equal(isCallGraphLanguage(lang), true, `${lang}: Babel path is always available`);
    }
  } finally {
    _resetTreeSitter();
  }
});

test("after init, the loaded grammars report coverage", async () => {
  _resetTreeSitter();
  await initTreeSitter(TREE_SITTER_PROFILE_LANGS);
  const loaded = TREE_SITTER_PROFILE_LANGS.filter((l) => treeSitterReady(l));
  assert.ok(loaded.length > 0, "this build should load at least one grammar");
  for (const lang of loaded) {
    assert.equal(isCallGraphLanguage(lang), true, `${lang}: loaded grammar means real coverage`);
  }
});

test("a language with no profile at all is never covered", () => {
  assert.equal(isCallGraphLanguage("brainfuck"), false);
  assert.equal(isCallGraphLanguage(""), false);
});
