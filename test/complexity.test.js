import { strict as assert } from "assert";
import { test } from "node:test";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { computeBabelComplexity, computeTreeComplexity, cognitiveComplexity, nestingDepth, profileFor, analyzeComplexity } from "../dist/core/complexity.js";
import { parseJs } from "../dist/core/parsers/javascript.js";
import { parseTs } from "../dist/core/parsers/treesitter.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test("cognitiveComplexity: linear function (no decisions)", () => {
  // Parse a simple linear function
  const code = `function simple() { const x = 1; return x; }`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const fn = ast.program?.body[0];
  assert(fn, "Should find function");

  const complexity = cognitiveComplexity(fn, profile, "babel");
  assert.equal(complexity, 0, "Linear function should have 0 cognitive complexity");
});

test("cognitiveComplexity: single if statement (+1)", () => {
  const code = `function test(x) { if (x) return 1; else return 0; }`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const fn = ast.program?.body[0];
  const complexity = cognitiveComplexity(fn, profile, "babel");

  assert(complexity >= 1, `If statement should add at least 1 (got ${complexity})`);
});

test("cognitiveComplexity: nested if inside loop", () => {
  const code = `function nested(arr) {
    for (let i = 0; i < arr.length; i++) {
      if (arr[i] > 0) {
        return arr[i];
      }
    }
  }`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const fn = ast.program?.body[0];
  const complexity = cognitiveComplexity(fn, profile, "babel");

  // for: +1 base, if inside loop: +1 base + 1 nesting depth = 2, total >= 3
  assert(complexity >= 2, `Nested if in loop should have higher complexity (got ${complexity})`);
});

test("nestingDepth: linear function", () => {
  const code = `function simple() { return 1; }`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const fn = ast.program?.body[0];
  const depth = nestingDepth(fn, profile, "babel");

  // A function body's own `{ }` is not a nesting level — otherwise Babel numbers would not be
  // comparable with the tree-sitter languages, and every one-liner would report depth 1.
  assert.equal(depth, 0, `Linear function should have nesting depth 0 (got ${depth})`);
});

test("nestingDepth: double-nested if", () => {
  const code = `function nested() {
    if (a) {
      if (b) {
        return 1;
      }
    }
  }`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const fn = ast.program?.body[0];
  const depth = nestingDepth(fn, profile, "babel");

  assert(depth >= 2, `Double-nested if should have depth >= 2 (got ${depth})`);
});

test("computeBabelComplexity: extracts multiple functions with metrics", () => {
  const code = `
    function simple() { return 1; }
    function complex(a, b) {
      if (a) {
        for (let i = 0; i < b; i++) {
          console.log(i);
        }
      }
      return a + b;
    }
  `;

  const ast = parseJs(code);
  const profile = profileFor("javascript");
  const functions = computeBabelComplexity(ast, profile);

  assert(functions.length >= 2, `Should find at least 2 functions (got ${functions.length})`);

  const simple = functions.find(f => f.name === "simple");
  const complex = functions.find(f => f.name === "complex");

  assert(simple, "Should find 'simple' function");
  assert(complex, "Should find 'complex' function");

  assert.equal(simple.metrics.params, 0, "simple should have 0 params");
  assert(simple.metrics.cognitive === 0, "simple should have 0 cognitive complexity");

  assert.equal(complex.metrics.params, 2, "complex should have 2 params");
  assert(complex.metrics.cognitive > 0, "complex should have positive cognitive complexity");
  assert(complex.metrics.nesting >= 1, "complex should have nesting >= 1");
});

test("computeBabelComplexity: function lines and bodyLines", () => {
  const code = `function test() {
    const x = 1;
    return x;
  }`;

  const ast = parseJs(code);
  const profile = profileFor("javascript");
  const functions = computeBabelComplexity(ast, profile);

  assert.equal(functions.length, 1, "Should find 1 function");
  const fn = functions[0];

  assert(fn.startLine !== null && fn.endLine !== null, "Should have line range");
  assert(fn.endLine >= fn.startLine, "endLine should be >= startLine");
  assert(fn.bodyLines.length > 0, "Should have body lines");
  assert.equal(fn.bodyLines.length, fn.metrics.lines, "bodyLines length should match metrics.lines");
});

test("computeBabelComplexity: parameter counting", () => {
  const code = `
    function noParams() { return 1; }
    function threeParams(a, b, c) { return a + b + c; }
  `;

  const ast = parseJs(code);
  const profile = profileFor("javascript");
  const functions = computeBabelComplexity(ast, profile);

  const noParams = functions.find(f => f.name === "noParams");
  const threeParams = functions.find(f => f.name === "threeParams");

  assert.equal(noParams?.metrics.params, 0, "noParams should have 0 params");
  assert.equal(threeParams?.metrics.params, 3, "threeParams should have 3 params");
});

test("profileFor: language lookup", () => {
  assert.ok(profileFor("javascript"), "Should find JavaScript profile");
  assert.ok(profileFor("typescript"), "Should find TypeScript profile");
  assert.ok(profileFor("python"), "Should find Python profile");
  assert.ok(profileFor("go"), "Should find Go profile");
  assert.ok(profileFor("java"), "Should find Java profile");
  assert.ok(profileFor("kotlin"), "Should find Kotlin profile");
  assert.ok(profileFor("ruby"), "Should find Ruby profile");
  assert.ok(profileFor("php"), "Should find PHP profile");
  assert.ok(profileFor("csharp") || profileFor("c#"), "Should find C# profile");
  assert.ok(profileFor("jsx"), "Should find JSX profile");
  assert.ok(profileFor("tsx"), "Should find TSX profile");

  // Case-insensitive
  assert.ok(profileFor("PYTHON"), "Should be case-insensitive");
  assert.ok(profileFor("JavaScript"), "Should be case-insensitive");
});

test("profileFor: unknown language falls back to null", () => {
  const profile = profileFor("rust"); // Not in LANGUAGE_PROFILES
  // Rust is not in our current profiles, so this should be null or a fallback
  // Current implementation returns null for unknown; if we add a fallback, adjust assertion
  assert(profile === null || profile.lang === "rust", "Unknown language behavior");
});

test("analyzeComplexity: Babel path (no ctx.tsTree, use ctx.ast)", () => {
  const code = `function test(x, y) {
    if (x > 0) {
      for (let i = 0; i < y; i++) {
        console.log(i);
      }
    }
    return x + y;
  }`;

  const ast = parseJs(code);
  const ctx = {
    language: "javascript",
    ast,
    tsTree: null,
    config: {},
  };

  const functions = analyzeComplexity(ctx);
  assert(functions.length >= 1, "Should find at least 1 function");
  assert.equal(functions[0].name, "test", "Should find 'test' function");
  assert.equal(functions[0].metrics.params, 2, "Should have 2 params");
});

// Tree-sitter tests (for Python)
test("computeTreeComplexity: Python function analysis", async () => {
  const pythonCode = `def simple_func():
    return 42

def complex_func(a, b):
    for i in range(10):
        if i > 5:
            print(i)
    return a + b
`;

  const tree = await parseTs("python", pythonCode);
  if (!tree) {
    console.log("Tree-sitter parser unavailable for Python; skipping this test");
    return;
  }

  const profile = profileFor("python");
  assert.ok(profile, "Should find Python profile");

  const functions = computeTreeComplexity(tree, profile);
  assert(functions.length >= 1, `Should find functions in Python code (got ${functions.length})`);
});

test("analyzeComplexity: Tree-sitter path (with ctx.tsTree)", async () => {
  const pythonCode = `def test_func(x):
    if x > 0:
        return x * 2
    return 0
`;

  const tree = await parseTs("python", pythonCode);
  if (!tree) {
    console.log("Tree-sitter parser unavailable for Python; skipping this test");
    return;
  }

  const ctx = {
    language: "python",
    tsTree: tree,
    ast: null,
    config: {},
  };

  const functions = analyzeComplexity(ctx);
  assert(functions.length >= 1, "Should find at least 1 function from tree-sitter");
});

test("memoization: repeated calls return same array", () => {
  const code = `function test() { if (x) return 1; }`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const result1 = computeBabelComplexity(ast, profile);
  const result2 = computeBabelComplexity(ast, profile);

  assert.equal(result1, result2, "Memoization should return same array reference");
});

test("edge case: empty function", () => {
  const code = `function empty() {}`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const functions = computeBabelComplexity(ast, profile);
  assert(functions.length >= 1, "Should find function even if empty");

  const fn = functions[0];
  assert.equal(fn.metrics.cognitive, 0, "Empty function should have 0 cognitive complexity");
  assert.equal(fn.metrics.params, 0, "Empty function should have 0 params");
});

test("edge case: arrow function", () => {
  const code = `const fn = (a, b) => a + b;`;
  const ast = parseJs(code);
  const profile = profileFor("javascript");

  const functions = computeBabelComplexity(ast, profile);
  assert(functions.length >= 1, "Should find arrow function");

  const fn = functions[0];
  assert.equal(fn.metrics.params, 2, "Arrow function should count params");
});

test("logical operator sequences: a && b && c vs a && b || c", () => {
  // This test validates the "logical operator sequence break" logic
  // Same operator → +1 total, different operators → +1 for the break

  const andAnd = `function test1(a, b, c) { return a && b && c; }`;
  const andOr = `function test2(a, b, c) { return a && b || c; }`;

  const ast1 = parseJs(andAnd);
  const ast2 = parseJs(andOr);
  const profile = profileFor("javascript");

  const fn1 = ast1.program?.body[0];
  const fn2 = ast2.program?.body[0];

  const cog1 = cognitiveComplexity(fn1, profile, "babel");
  const cog2 = cognitiveComplexity(fn2, profile, "babel");

  // cog2 should be >= cog1 because of the operator sequence break
  assert(cog2 >= cog1, `Operator break should increase complexity (${cog1} vs ${cog2})`);
});
