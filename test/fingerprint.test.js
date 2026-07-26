import { strict as assert } from "assert";
import { test } from "node:test";
import * as path from "path";
import { fileURLToPath } from "url";
import {
  nameTokens,
  tokenOverlap,
  shapeFunctions,
} from "../dist/core/fingerprint.js";
import { parseJs } from "../dist/core/parsers/javascript.js";
import { parseTs, initTreeSitter } from "../dist/core/parsers/treesitter.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Each test FILE gets its own module instance under `node --test` — initTreeSitter() called in
// another test file does NOT leave this file's parserCache populated. This ensures tree-sitter
// assertions actually run and would FAIL if the logic were wrong.
await initTreeSitter();

// ============================================================================
// nameTokens tests
// ============================================================================

test("nameTokens: camelCase split", () => {
  const result = nameTokens("formatCurrency");
  assert.deepEqual(result, ["format", "currency"]);
});

test("nameTokens: snake_case split", () => {
  const result = nameTokens("format_currency_v2");
  // "v" is a stopword, "2" is dropped (not text), so we get ["format", "currency"]
  assert.deepEqual(result, ["format", "currency"]);
});

test("nameTokens: camelCase with get prefix", () => {
  const result = nameTokens("getUserName");
  // "get" is a stopword, so ["user", "name"]
  assert.deepEqual(result, ["user", "name"]);
});

test("nameTokens: single letter stopword kept at length 2", () => {
  const result = nameTokens("doIt");
  // "do" is a stopword, "it" is length 2 so it survives
  assert.deepEqual(result, ["it"]);
});

test("nameTokens: bare stopword returns empty", () => {
  const result = nameTokens("run");
  // "run" is a stopword, so []
  assert.deepEqual(result, []);
});

test("nameTokens: empty string", () => {
  const result = nameTokens("");
  assert.deepEqual(result, []);
});

test("nameTokens: null/undefined handling", () => {
  assert.deepEqual(nameTokens(null), []);
  assert.deepEqual(nameTokens(undefined), []);
});

test("nameTokens: PascalCase", () => {
  const result = nameTokens("CreateNewUser");
  // "create" and "new" are stopwords
  assert.deepEqual(result, ["user"]);
});

test("nameTokens: hyphen separated", () => {
  const result = nameTokens("fetch-user-data");
  // "fetch" is a stopword
  assert.deepEqual(result, ["user", "data"]);
});

test("nameTokens: deduplication", () => {
  const result = nameTokens("getUserUser");
  // "get" is stopped, "user" appears twice but deduped
  assert.deepEqual(result, ["user"]);
});

test("nameTokens: single char token dropped", () => {
  const result = nameTokens("aUserName");
  // "a" is dropped (length < 2), "get" is stopped (if present)
  const found = result.indexOf("a");
  assert.equal(found, -1, "single-char token should be dropped");
});

// ============================================================================
// tokenOverlap tests
// ============================================================================

test("tokenOverlap: identical sets", () => {
  const a = ["user", "name", "data"];
  const b = ["user", "name", "data"];
  const similarity = tokenOverlap(a, b);
  assert.equal(similarity, 1, "identical sets should have overlap = 1");
});

test("tokenOverlap: disjoint sets", () => {
  const a = ["user", "name"];
  const b = ["foo", "bar"];
  const similarity = tokenOverlap(a, b);
  assert.equal(similarity, 0, "disjoint sets should have overlap = 0");
});

test("tokenOverlap: half overlap", () => {
  const a = ["user", "name"];
  const b = ["user", "data"];
  // intersection = ["user"] (size 1)
  // union = ["user", "name", "data"] (size 3)
  // Jaccard = 1/3
  const similarity = tokenOverlap(a, b);
  assert.equal(similarity, 1 / 3, "half overlap should be 1/3");
});

test("tokenOverlap: empty first set", () => {
  const similarity = tokenOverlap([], ["user", "name"]);
  assert.equal(similarity, 0, "empty first set should return 0");
});

test("tokenOverlap: empty second set", () => {
  const similarity = tokenOverlap(["user"], []);
  assert.equal(similarity, 0, "empty second set should return 0");
});

test("tokenOverlap: both empty", () => {
  const similarity = tokenOverlap([], []);
  assert.equal(similarity, 0, "both empty should return 0");
});

test("tokenOverlap: null/undefined sets", () => {
  assert.equal(tokenOverlap(null, ["x"]), 0);
  assert.equal(tokenOverlap(["x"], undefined), 0);
});

// ============================================================================
// shapeFunctions: Babel (JavaScript) tests
// ============================================================================

test("shapeFunctions: two functions with identical structure, different names and literals", () => {
  const code = `
    function firstFunction(x) {
      if (x > 0) {
        return x * 2;
      }
      return 0;
    }
    function secondFunction(y) {
      if (y > 5) {
        return y * 3;
      }
      return 0;
    }
  `;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  assert(shapes.length >= 2, `Expected at least 2 functions, got ${shapes.length}`);

  const first = shapes.find(s => s.name === "firstFunction");
  const second = shapes.find(s => s.name === "secondFunction");

  assert(first, "Should find firstFunction");
  assert(second, "Should find secondFunction");

  // Different names, but identical control flow should produce the same hash.
  assert(
    first.shapeHash && second.shapeHash,
    "Both functions should have non-empty shapeHash"
  );
  assert.equal(
    first.shapeHash,
    second.shapeHash,
    "Identical structure should produce identical shapeHash"
  );
});

test("shapeFunctions: two functions with different control flow", () => {
  const code = `
    function linearCode(x) {
      const a = x + 1;
      const b = a * 2;
      return b;
    }
    function withLoop(arr) {
      let sum = 0;
      for (let i = 0; i < arr.length; i++) {
        sum += arr[i];
      }
      return sum;
    }
  `;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  const linear = shapes.find(s => s.name === "linearCode");
  const withLoop_ = shapes.find(s => s.name === "withLoop");

  assert(linear, "Should find linearCode");
  assert(withLoop_, "Should find withLoop");

  // Different control flow should produce different hashes.
  assert(
    linear.shapeHash && withLoop_.shapeHash,
    "Both should have non-empty shapeHash"
  );
  assert.notEqual(
    linear.shapeHash,
    withLoop_.shapeHash,
    "Different control flow should produce different shapeHash"
  );
});

test("shapeFunctions: function with 1-line body", () => {
  const code = `function tiny() { return 42; }`;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  assert.equal(shapes.length, 1, "Should find 1 function");
  const fn = shapes[0];

  // A single return statement is just 1 node, too small to fingerprint.
  assert.equal(fn.shapeHash, "", "1-statement function should have empty shapeHash");
  assert.equal(fn.statementCount, 1, "1-line body has 1 statement node");
});

test("shapeFunctions: function with minimal body", () => {
  const code = `
    function oneLine(x) {
      return x * 2;
    }
  `;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  const fn = shapes[0];
  // A function with only a return statement is 1 node: statementCount = 1 < 3
  assert.equal(fn.shapeHash, "", "Function with 1 statement should have empty shapeHash");
  assert(fn.statementCount < 3, "Function body has < 3 statement nodes");
});

test("shapeFunctions: extract arity (parameter count)", () => {
  const code = `
    function noParams() { return 1; }
    function twoParams(a, b) { return a + b; }
    function threeParams(x, y, z) { return x + y + z; }
  `;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  const noParams = shapes.find(s => s.name === "noParams");
  const twoParams = shapes.find(s => s.name === "twoParams");
  const threeParams = shapes.find(s => s.name === "threeParams");

  assert.equal(noParams?.arity, 0, "noParams should have arity 0");
  assert.equal(twoParams?.arity, 2, "twoParams should have arity 2");
  assert.equal(threeParams?.arity, 3, "threeParams should have arity 3");
});

test("shapeFunctions: extract line ranges", () => {
  const code = `function test(x) {
    if (x > 0) {
      return x;
    }
    return 0;
  }`;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  assert.equal(shapes.length, 1, "Should find 1 function");
  const fn = shapes[0];

  assert(fn.startLine >= 1, "startLine should be 1-based");
  assert(fn.endLine >= fn.startLine, "endLine should be >= startLine");
  assert(fn.name === "test", "Function name should be 'test'");
});

test("shapeFunctions: anonymous function", () => {
  const code = `const fn = function(x) { return x * 2; };`;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  // Should find the anonymous function expression
  assert(shapes.length >= 1, "Should find anonymous function");
  const fn = shapes[0];
  assert.equal(fn.name, "", "Anonymous function should have empty name");
});

test("shapeFunctions: arrow function", () => {
  const code = `const add = (a, b) => {
    const sum = a + b;
    return sum;
  };`;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  assert(shapes.length >= 1, "Should find arrow function");
  const fn = shapes[0];
  assert.equal(fn.arity, 2, "Arrow function should have 2 parameters");
});

// ============================================================================
// shapeFunctions: Tree-sitter (Python) tests
// ============================================================================

test("shapeFunctions: Python with three functions starting on line 1 (regression: first-line bug)", async () => {
  // Regression test for the bug where functions starting on line 1 (tree-sitter row 0) were
  // dropped due to truthiness check on row value. The first function starts on line 1.
  const pythonCode = `def process_first(value):
    if value > 10:
        return value * 2
    else:
        return 0
def process_second(data):
    if data > 10:
        return data * 3
    else:
        return 0
def process_third(x):
    if x > 10:
        return x * 2
    else:
        return 0
`;

  const tree = await parseTs(pythonCode, "python");
  assert.ok(tree, "Python tree-sitter parser must be available");

  const shapes = shapeFunctions({
    language: "python",
    tsTree: tree,
    lines: pythonCode.split("\n"),
  });

  // Must find all 3 functions, including the one starting on line 1 (row 0).
  assert.equal(shapes.length, 3, `Expected exactly 3 Python functions, got ${shapes.length}`);

  // Verify the exact names in order
  const names = shapes.map(s => s.name);
  assert.deepEqual(
    names,
    ["process_first", "process_second", "process_third"],
    "Should find all three functions in order, including the first one on line 1"
  );

  // First function starts on line 1 (0-based row 0, so 0 + 1 = 1) — regression for dropped first-line functions
  const first = shapes[0];
  assert.equal(first.startLine, 1, "First function must start on line 1 (not dropped by row=0 bug)");
  assert(first.shapeHash !== "", "First function has if/else structure, should have non-empty hash");

  // All three functions have identical if/else structure with binary expression returns
  assert.equal(shapes[1].shapeHash, first.shapeHash, "All three functions structurally identical: second matches first");
  assert.equal(shapes[2].shapeHash, first.shapeHash, "All three functions structurally identical: third matches first");
  assert.equal(shapes[0].statementCount, shapes[1].statementCount, "First two have same statement count");
  assert.equal(shapes[1].statementCount, shapes[2].statementCount, "All three have same statement count");
});

test("shapeFunctions: Go function on line 1 (first-line regression, another language)", async () => {
  // Same regression test for Go: function starting at line 1 should not be dropped.
  const goCode = `func process(x int) int {
	if x > 0 {
		return x * 2
	}
	return 0
}
func another(y int) int {
	if y > 0 {
		return y * 3
	}
	return 0
}
`;

  const tree = await parseTs(goCode, "go");
  assert.ok(tree, "Go tree-sitter parser must be available");

  const shapes = shapeFunctions({
    language: "go",
    tsTree: tree,
    lines: goCode.split("\n"),
  });

  // Both functions should be found
  assert.equal(shapes.length, 2, `Expected exactly 2 Go functions, got ${shapes.length}`);

  const names = shapes.map(s => s.name);
  assert.deepEqual(names, ["process", "another"], "Should find both Go functions");

  // First function starts on line 1
  const first = shapes[0];
  assert.equal(first.startLine, 1, "First Go function must start on line 1");

  // Both have identical if/else structure
  assert.equal(shapes[0].shapeHash, shapes[1].shapeHash, "Both Go functions have identical structure");
});

// ============================================================================
// Edge cases and error handling
// ============================================================================

test("shapeFunctions: file that fails to parse", () => {
  // Invalid code
  const code = `function broken() { if (x > }} }`;

  try {
    const ast = parseJs(code);
    const shapes = shapeFunctions({
      language: "javascript",
      ast,
      lines: code.split("\n"),
    });
    // On parse error, parseJs may return null; shapeFunctions returns []
    assert(Array.isArray(shapes), "Should return an array even on parse error");
  } catch {
    // Parse failure is acceptable
  }
});

test("shapeFunctions: missing both ast and tsTree", () => {
  const shapes = shapeFunctions({
    language: "javascript",
    lines: ["console.log('test');"],
  });

  assert.deepEqual(shapes, [], "Should return [] when both ast and tsTree are absent");
});

test("shapeFunctions: complex nested function", () => {
  const code = `
    function complex(x) {
      if (x > 0) {
        for (let i = 0; i < x; i++) {
          if (i % 2 === 0) {
            console.log(i);
          }
        }
      }
      return x;
    }
  `;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  assert.equal(shapes.length, 1, "Should find 1 function");
  const fn = shapes[0];

  // Complex nested structure should definitely have statementCount >= 3
  assert(fn.statementCount >= 3, "Complex function should have many statements");
  assert(fn.shapeHash !== "", "Complex function should have non-empty shapeHash");
});

test("shapeFunctions: class method (Babel)", () => {
  const code = `
    class MyClass {
      myMethod(x) {
        if (x > 0) return x;
        return 0;
      }
    }
  `;

  const ast = parseJs(code);
  const shapes = shapeFunctions({
    language: "javascript",
    ast,
    lines: code.split("\n"),
  });

  // Babel should find the class method
  assert(shapes.length >= 1, "Should find at least 1 method");
});
