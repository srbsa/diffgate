// Test suite for reinvented-helper rule and attachReinvention pass.
//
// Follows the pattern from structural-impact.test.js: real temp directories with real files on disk,
// no mocking of the repo walk. Tests must be load-bearing against mutation testing.

import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { attachReinvention } from "../dist/core/reinvention.js";
import { analyze } from "../dist/core/index.js";
import { initTreeSitter, parseTs } from "../dist/core/parsers/treesitter.js";
import { parseJs } from "../dist/core/parsers/javascript.js";
import { shapeFunctions } from "../dist/core/fingerprint.js";
import { detectLanguage } from "../dist/core/parsers/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Each test FILE gets its own module instance under `node --test` — initTreeSitter() called in
// another test file does NOT leave this file's parserCache populated. This ensures tree-sitter
// assertions actually run and would FAIL if the logic were wrong.
await initTreeSitter();

/** Create a temporary directory for a test. */
function mkTempDir() {
  const tmpDir = fs.mkdtempSync(path.join(__dirname, "../.test-tmp-"));
  return tmpDir;
}

/** Cleanup a temporary directory. */
function rmTempDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Ignore errors
  }
}

/** Create a finding stub for testing. */
function finding(over = {}) {
  return {
    ruleId: "reinvented-helper",
    symbol: null,
    line: 1,
    column: 0,
    endLine: 1,
    endColumn: 10,
    tier: "yellow",
    blocking: false,
    title: "Function duplicates existing implementation",
    message: "⚡ Possible reinvented helper: test_func",
    code: "def test_func():",
    fix: null,
    ...over,
  };
}

/** Create a file result stub for testing. */
function file(filePath, findings) {
  return {
    filePath,
    findings,
    tier: findings.length > 0 ? "yellow" : "green",
    counts: { green: 0, yellow: findings.length, orange: 0 },
    blocking: false,
  };
}

/** Compute the actual shapeHash for a piece of code. */
function getShapeHashForCode(content, language) {
  const lines = content.split("\n");
  let shapes = [];

  if (language === "python" || language === "go" || language === "java" || language === "kotlin" || language === "ruby" || language === "php" || language === "csharp") {
    const tree = parseTs(content, language);
    if (tree) {
      shapes = shapeFunctions({ language, tsTree: tree, lines });
    }
  } else if (language === "javascript" || language === "typescript" || language === "jsx" || language === "tsx") {
    const ast = parseJs(content, language);
    if (ast) {
      shapes = shapeFunctions({ language, ast, lines });
    }
  }

  if (shapes.length > 0) {
    return {
      shapeHash: shapes[0].shapeHash,
      arity: shapes[0].arity,
      statementCount: shapes[0].statementCount,
    };
  }
  return null;
}

// ============================================================================
// Test 1: Two identical functions in different files with similar names
// ============================================================================

test("a: Two structurally identical functions in DIFFERENT files with similar names → finding SURVIVES and message names the other file and line", async () => {
  const tmpDir = mkTempDir();
  try {
    // File 1: contains the original function
    const file1Content = `def process_order(items, cost):
    total = 0
    for item in items:
        total += item
    if total > 100:
        return False
    return True
`;
    fs.writeFileSync(path.join(tmpDir, "orders.py"), file1Content);

    // File 2: contains the new (diff) function with same shape but similar name
    const file2Content = `def handle_order(items, cost):
    total = 0
    for item in items:
        total += item
    if total > 100:
        return False
    return True
`;
    fs.writeFileSync(path.join(tmpDir, "new_orders.py"), file2Content);

    // Get the actual shapeHash for both functions (they should be identical).
    const shapeData = getShapeHashForCode(file2Content, "python");
    assert.ok(shapeData, "Should be able to compute shape for test function");

    // Simulate that new_orders.py was changed.
    const files = [
      file(path.join(tmpDir, "new_orders.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: handle_order",
          code: "def handle_order(items, cost):",
          symbol: "handle_order",
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: shapeData.arity,
            statementCount: shapeData.statementCount,
            name: "handle_order",
          },
        }),
      ]),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    assert.equal(result[0].findings.length, 1, "Finding should survive");
    const msg = result[0].findings[0].message;
    assert.match(msg, /handle_order/, "Message should contain new function name");
    assert.match(msg, /process_order/, "Message should contain existing function name");
    assert.match(msg, /orders\.py/, "Message should contain existing file path");
    assert.match(msg, /:1/, "Message should contain existing function line");
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 2: Same shape but different arity → finding DROPPED
// ============================================================================

test("b: Same shape but arity differs → finding DROPPED", async () => {
  const tmpDir = mkTempDir();
  try {
    // File 1: function with 2 parameters
    const file1Content = `def process_order(items, cost):
    total = 0
    for item in items:
        total += item
    return total
`;
    fs.writeFileSync(path.join(tmpDir, "orders.py"), file1Content);

    // File 2: function with 3 parameters (different arity, but we'll claim it has the same shape)
    const file2Content = `def handle_order(items, cost, tax):
    total = 0
    for item in items:
        total += item
    return total
`;
    fs.writeFileSync(path.join(tmpDir, "new_orders.py"), file2Content);

    const shapeData = getShapeHashForCode(file1Content, "python");
    assert.ok(shapeData, "Should be able to compute shape for file 1");

    const files = [
      file(path.join(tmpDir, "new_orders.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: handle_order",
          symbol: "handle_order",
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: 3, // Different from existing function's arity (2)
            statementCount: shapeData.statementCount,
            name: "handle_order",
          },
        }),
      ]),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    assert.equal(result[0].findings.length, 0, "Finding should be dropped due to arity mismatch");
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 3: Same shape but unrelated names → finding DROPPED
// ============================================================================

test("c: Same shape but unrelated names (tokenOverlap below 0.34) → finding DROPPED", async () => {
  const tmpDir = mkTempDir();
  try {
    // File 1: function with name "process_order"
    const file1Content = `def process_order(items):
    total = 0
    for item in items:
        total += item
    if total > 100:
        return False
    return True
`;
    fs.writeFileSync(path.join(tmpDir, "orders.py"), file1Content);

    // File 2: function with unrelated name "xyz_abc"
    const file2Content = `def xyz_abc(items):
    total = 0
    for item in items:
        total += item
    if total > 100:
        return False
    return True
`;
    fs.writeFileSync(path.join(tmpDir, "new_orders.py"), file2Content);

    const shapeData = getShapeHashForCode(file1Content, "python");
    assert.ok(shapeData, "Should be able to compute shape");

    const files = [
      file(path.join(tmpDir, "new_orders.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: xyz_abc",
          symbol: "xyz_abc",
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: shapeData.arity,
            statementCount: shapeData.statementCount,
            name: "xyz_abc", // This name has very low overlap with "process_order"
          },
        }),
      ]),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    assert.equal(result[0].findings.length, 0, "Finding should be dropped due to low name overlap");
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 4: Only match is in a test file → finding DROPPED
// ============================================================================

test("d: Only match is in a test file → finding DROPPED", async () => {
  const tmpDir = mkTempDir();
  try {
    // File 1: function in a test file
    const file1Content = `def process_order(items):
    total = 0
    for item in items:
        total += item
    return total
`;
    fs.writeFileSync(path.join(tmpDir, "orders.test.py"), file1Content);

    // File 2: function in main code
    const file2Content = `def handle_order(items):
    total = 0
    for item in items:
        total += item
    return total
`;
    fs.writeFileSync(path.join(tmpDir, "new_orders.py"), file2Content);

    const shapeData = getShapeHashForCode(file2Content, "python");
    assert.ok(shapeData, "Should be able to compute shape");

    const files = [
      file(path.join(tmpDir, "new_orders.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: handle_order",
          symbol: "handle_order",
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: shapeData.arity,
            statementCount: shapeData.statementCount,
            name: "handle_order",
          },
        }),
      ]),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    assert.equal(
      result[0].findings.length,
      0,
      "Finding should be dropped because only match is in a test file"
    );
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 5: Only match is in another file that is also part of this diff (a move) → finding DROPPED
// ============================================================================

test("e: Only match is in another file that is also part of this diff (a move) → finding DROPPED", async () => {
  const tmpDir = mkTempDir();
  try {
    // File 1: function in old location (but also marked as changed)
    const file1Content = `def process_order(items):
    total = 0
    for item in items:
        total += item
    return total
`;
    fs.writeFileSync(path.join(tmpDir, "old_orders.py"), file1Content);

    // File 2: same function in new location (also changed)
    const file2Content = `def handle_order(items):
    total = 0
    for item in items:
        total += item
    return total
`;
    fs.writeFileSync(path.join(tmpDir, "new_orders.py"), file2Content);

    const shapeData = getShapeHashForCode(file2Content, "python");
    assert.ok(shapeData, "Should be able to compute shape");

    // Both files are in the changed set, simulating a move or refactor.
    const files = [
      file(path.join(tmpDir, "new_orders.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: handle_order",
          symbol: "handle_order",
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: shapeData.arity,
            statementCount: shapeData.statementCount,
            name: "handle_order",
          },
        }),
      ]),
      file(path.join(tmpDir, "old_orders.py"), []),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    assert.equal(
      result[0].findings.length,
      0,
      "Finding should be dropped because the match is also in a changed file"
    );
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 6: statementCount < 5 → never emitted in the first place
// ============================================================================

test("f: statementCount < 5 → finding with low statement count should be dropped (never reach index)", async () => {
  const tmpDir = mkTempDir();
  try {
    // File 1: short function with < 5 statements
    const file1Content = `def simple():
    return 42
`;
    fs.writeFileSync(path.join(tmpDir, "util.py"), file1Content);

    // File 2: same short function
    const file2Content = `def other_simple():
    return 42
`;
    fs.writeFileSync(path.join(tmpDir, "new_util.py"), file2Content);

    const shapeData = getShapeHashForCode(file2Content, "python");
    assert.ok(shapeData, "Should be able to compute shape");

    const files = [
      file(path.join(tmpDir, "new_util.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: other_simple",
          symbol: "other_simple",
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: shapeData.arity,
            statementCount: shapeData.statementCount, // Will be < 5
            name: "other_simple",
          },
        }),
      ]),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    // Finding should be dropped because the existing function has statementCount < 5.
    assert.equal(result[0].findings.length, 0, "Finding should be dropped due to low statement count");
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 7: No reinvented-helper findings → repo scan does not happen
// ============================================================================

test("g: No reinvented-helper finding present → attachReinvention returns input array unchanged AND does not scan repo", async () => {
  const tmpDir = mkTempDir();
  try {
    // Create some files to make the repo non-empty.
    fs.writeFileSync(path.join(tmpDir, "file1.py"), "def func(): pass\n");
    fs.writeFileSync(path.join(tmpDir, "file2.py"), "def func2(): pass\n");

    // Input has NO reinvented-helper findings.
    const files = [
      file(path.join(tmpDir, "file1.py"), [
        {
          ruleId: "some-other-rule",
          symbol: null,
          line: 1,
          column: 0,
          endLine: 1,
          endColumn: 10,
          tier: "green",
          blocking: false,
          title: "Other rule",
          message: "Some other message",
          code: "",
          fix: null,
        },
      ]),
    ];

    const originalLength = files.length;
    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    // Result should be identical to input (same reference for efficiency).
    assert.deepEqual(result, files, "Should return input unchanged when no reinvented-helper findings");
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 8: A surviving finding still has tier "yellow" and blocking false
// ============================================================================

test("h: A surviving finding still has tier 'yellow' and blocking false", async () => {
  const tmpDir = mkTempDir();
  try {
    // File 1: original function
    const file1Content = `def processUserData(x):
    a = x
    b = a + 1
    c = b * 2
    d = c - 1
    return d
`;
    fs.writeFileSync(path.join(tmpDir, "base.py"), file1Content);

    // File 2: new function with similar name pattern - shares "process" and "user"
    const file2Content = `def processUserList(x):
    a = x
    b = a + 1
    c = b * 2
    d = c - 1
    return d
`;
    fs.writeFileSync(path.join(tmpDir, "new_base.py"), file2Content);

    const shapeData = getShapeHashForCode(file2Content, "python");
    assert.ok(shapeData, "Should be able to compute shape");

    const files = [
      file(path.join(tmpDir, "new_base.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: processUserList",
          symbol: "processUserList",
          tier: "yellow",
          blocking: false,
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: shapeData.arity,
            statementCount: shapeData.statementCount,
            name: "processUserList",
          },
        }),
      ]),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    assert.equal(result[0].findings.length, 1, "Finding should survive");
    assert.equal(result[0].findings[0].tier, "yellow", "Tier should still be yellow");
    assert.equal(result[0].findings[0].blocking, false, "Blocking should still be false");
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 9: Multiple candidates, pick the best one (lowest file path, then lowest line)
// ============================================================================

test("picks the best match when multiple candidates exist (lowest file path, then lowest line)", async () => {
  const tmpDir = mkTempDir();
  try {
    // Create three files with similar functions
    const funcContent = `def similar(x):
    a = x
    b = a + 1
    c = b * 2
    d = c - 1
    return d
`;

    // File A: first candidate
    fs.writeFileSync(path.join(tmpDir, "aaa_file.py"), funcContent);

    // File B: second candidate (lower path than zzz, but higher than aaa)
    fs.writeFileSync(path.join(tmpDir, "zzz_file.py"), funcContent);

    // File NEW: the new function
    fs.writeFileSync(path.join(tmpDir, "new_file.py"), funcContent);

    const shapeData = getShapeHashForCode(funcContent, "python");
    assert.ok(shapeData, "Should be able to compute shape");

    const files = [
      file(path.join(tmpDir, "new_file.py"), [
        finding({
          line: 1,
          message: "⚡ Possible reinvented helper: similar",
          symbol: "similar",
          meta: {
            shapeHash: shapeData.shapeHash,
            arity: shapeData.arity,
            statementCount: shapeData.statementCount,
            name: "similar",
          },
        }),
      ]),
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    assert.equal(result[0].findings.length, 1, "Finding should survive");
    const msg = result[0].findings[0].message;
    assert.match(msg, /aaa_file\.py/, "Should pick the lowest file path");
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// Test 10: File tier/counts are recomputed when findings are dropped
// ============================================================================

test("file tier and counts are recomputed when findings are filtered", async () => {
  const tmpDir = mkTempDir();
  try {
    // Create a file with a function
    fs.writeFileSync(path.join(tmpDir, "base.py"), `def func(): pass\n`);

    // Create a file with two findings: one reinvention, one other
    const files = [
      {
        filePath: path.join(tmpDir, "test.py"),
        findings: [
          finding({
            line: 1,
            message: "⚡ Possible reinvented helper: test_func",
            symbol: "test_func",
            meta: {
              shapeHash: "nonexistent",
              arity: 0,
              statementCount: 10,
              name: "test_func",
            },
          }),
          {
            ruleId: "other-rule",
            symbol: null,
            line: 2,
            column: 0,
            endLine: 2,
            endColumn: 10,
            tier: "green",
            blocking: false,
            title: "Other",
            message: "Other message",
            code: "",
            fix: null,
          },
        ],
        tier: "yellow",
        counts: { green: 1, yellow: 1, orange: 0 },
        blocking: false,
      },
    ];

    const result = attachReinvention(files, { cwd: tmpDir, config: {} });

    // The reinvention finding should be dropped (no match), leaving only the other finding.
    assert.equal(result[0].findings.length, 1, "One finding should be dropped");
    assert.equal(result[0].findings[0].ruleId, "other-rule", "Remaining finding should be the other rule");
    // Counts should be recomputed: 1 green, 0 yellow
    assert.equal(result[0].counts.green, 1);
    assert.equal(result[0].counts.yellow, 0);
  } finally {
    rmTempDir(tmpDir);
  }
});

// ============================================================================
// End-to-end: detector rule -> makeFinding -> attachReinvention
//
// The tests above hand-construct findings that already carry `meta`, which skips the entire
// detector half of the rule. That gap hid a real bug: `runAst`/`runTsAst` enumerated emit fields
// and silently dropped `meta`, so every finding reached `attachReinvention` with `meta: undefined`
// and was unconditionally discarded — the feature was inert end-to-end while its unit tests passed.
// These tests drive the real path: analyze() emits, then the attach pass confirms.
// ============================================================================

test("e2e: analyze() emits reinvented-helper carrying meta through makeFinding", () => {
  const content = [
    "export function calculateInvoiceTotal(entries) {",
    "  let sum = 0;",
    "  for (const entry of entries) {",
    "    if (entry.taxable) {",
    "      sum += entry.price * 1.2;",
    "    } else {",
    "      sum += entry.price;",
    "    }",
    "  }",
    "  return sum;",
    "}",
    "",
  ].join("\n");
  const changedLines = new Set(Array.from({ length: 11 }, (_, i) => i + 1));

  const res = analyze({
    filePath: "src/billing.js",
    content,
    changedLines,
    config: { rules: { structural: true } },
  });

  const hit = res.findings.find((f) => f.ruleId === "reinvented-helper");
  assert.ok(hit, "detector must emit reinvented-helper for a changed multi-statement function");
  assert.ok(hit.meta, "meta must survive makeFinding — without it the attach pass drops the finding");
  assert.equal(hit.meta.name, "calculateInvoiceTotal");
  assert.equal(hit.meta.arity, 1);
  assert.equal(typeof hit.meta.shapeHash, "string");
  assert.notEqual(hit.meta.shapeHash, "", "a fingerprintable body must carry a non-empty shapeHash");
  assert.ok(hit.meta.statementCount >= 5);
});

test("e2e: detector + attach pass confirm a real duplicate and report a repo-relative path", () => {
  const tmpDir = mkTempDir();
  try {
    fs.mkdirSync(path.join(tmpDir, "src"), { recursive: true });
    const original = [
      "export function computeInvoiceTotal(items) {",
      "  let total = 0;",
      "  for (const item of items) {",
      "    if (item.taxable) {",
      "      total += item.price * 1.2;",
      "    } else {",
      "      total += item.price;",
      "    }",
      "  }",
      "  return total;",
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(tmpDir, "src", "invoice.js"), original);

    const duplicate = original
      .replace(/computeInvoiceTotal/g, "calculateInvoiceTotal")
      .replace(/items/g, "entries")
      .replace(/item\b/g, "entry")
      .replace(/total/g, "sum");
    const dupPath = path.join(tmpDir, "src", "billing.js");
    fs.writeFileSync(dupPath, duplicate);

    const analyzed = analyze({
      filePath: dupPath,
      content: duplicate,
      changedLines: new Set(Array.from({ length: 12 }, (_, i) => i + 1)),
      config: { rules: { structural: true } },
    });
    assert.ok(
      analyzed.findings.some((f) => f.ruleId === "reinvented-helper"),
      "detector must fire on the duplicate"
    );

    const result = attachReinvention([analyzed], { cwd: tmpDir, config: {} });
    const hit = result[0].findings.find((f) => f.ruleId === "reinvented-helper");
    assert.ok(hit, "the duplicate exists on disk, so the finding must survive confirmation");

    // The index stores absolute paths; the message must not.
    assert.ok(
      hit.message.includes("src/invoice.js:1"),
      `message must name the original at a repo-relative path, got: ${hit.message}`
    );
    assert.ok(
      !hit.message.includes(tmpDir),
      `message must not leak an absolute path, got: ${hit.message}`
    );
    assert.equal(hit.tier, "yellow");
    assert.equal(hit.blocking, false);
  } finally {
    rmTempDir(tmpDir);
  }
});
