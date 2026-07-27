import { test } from "node:test";
import { strict as assert } from "assert";
import { analyze, DEFAULT_CONFIG } from "../dist/core/index.js";

test("structural: cognitive-complexity-spike fires on complex JS function", () => {
  const filePath = "test.js";
  const content = `function complex(a, b) {
  if (a > 0) {
    if (b > 0) {
      if (a + b > 100) {
        return a * b;
      } else {
        return a + b;
      }
    } else {
      for (let i = 0; i < b; i++) {
        if (i % 2 === 0) {
          console.log(i);
        }
      }
      return 0;
    }
  }
  return -1;
}`;

  const result = analyze({ filePath, content, config: DEFAULT_CONFIG, changedLines: new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]) });

  const finding = result.findings.find(f => f.ruleId === "cognitive-complexity-spike");
  assert(finding, "Should find cognitive-complexity-spike finding");
  assert.match(finding.message, /cognitive complexity/i, "Message should mention cognitive complexity");
});

test("structural: long-function fires on long JS function", () => {
  const filePath = "test.js";
  const content = `function longFunc() {
  const x = 1;
  const y = 2;
  const z = 3;
  const a = 4;
  const b = 5;
  const c = 6;
  const d = 7;
  const e = 8;
  const f = 9;
  const g = 10;
  const h = 11;
  const i = 12;
  const j = 13;
  const k = 14;
  const l = 15;
  const m = 16;
  const n = 17;
  const o = 18;
  const p = 19;
  const q = 20;
  const r = 21;
  const s = 22;
  const t = 23;
  const u = 24;
  const v = 25;
  const w = 26;
  const x2 = 27;
  const y2 = 28;
  const z2 = 29;
  const a2 = 30;
  const b2 = 31;
  const c2 = 32;
  const d2 = 33;
  const e2 = 34;
  const f2 = 35;
  const g2 = 36;
  return x + y + z;
}`;

  const result = analyze({ filePath, content, config: DEFAULT_CONFIG, changedLines: new Set(Array.from({ length: 40 }, (_, i) => i + 1)) });

  const finding = result.findings.find(f => f.ruleId === "long-function");
  assert(finding, "Should find long-function finding");
  assert.match(finding.message, /spans \d+ lines/i, "Message should mention line count");
});

test("structural: too-many-parameters fires on JS function with many params", () => {
  const filePath = "test.js";
  const content = `function manyParams(a, b, c, d, e, f) {
  return a + b + c + d + e + f;
}`;

  const result = analyze({ filePath, content, config: DEFAULT_CONFIG, changedLines: new Set([1, 2, 3]) });

  const finding = result.findings.find(f => f.ruleId === "too-many-parameters");
  assert(finding, "Should find too-many-parameters finding");
  assert.match(finding.message, /\d+ parameters/i, "Message should mention parameter count");
});

test("structural: deep-nesting fires on deeply nested JS function", () => {
  const filePath = "test.js";
  // The JS/TS nesting threshold is 4, so this needs 5 real levels. A function's own braces are not
  // a level — only control-flow constructs count.
  const content = `function nested(a, b, c, d, e) {
  if (a) {
    if (b) {
      if (c) {
        if (d) {
          if (e) {
            return true;
          }
        }
      }
    }
  }
}`;

  const result = analyze({ filePath, content, config: DEFAULT_CONFIG, changedLines: new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]) });

  const finding = result.findings.find(f => f.ruleId === "deep-nesting");
  assert(finding, "Should find deep-nesting finding");
  assert.match(finding.message, /nesting depth/i, "Message should mention nesting depth");
});

test("structural: no false-block (yellow tier)", () => {
  const filePath = "test.js";
  const content = `function complex(a) {
  if (a > 0) {
    if (a > 10) {
      if (a > 100) {
        return a;
      }
    }
  }
  return 0;
}`;

  const result = analyze({ filePath, content, config: DEFAULT_CONFIG, changedLines: new Set([1, 2, 3, 4, 5, 6, 7, 8, 9]) });

  const findings = result.findings.filter(f => f.ruleId.startsWith("cognitive") || f.ruleId.startsWith("deep"));
  for (const f of findings) {
    assert.equal(f.tier, "yellow", `Structural rule should be yellow, not ${f.tier}`);
    assert.equal(f.blocking, false, "Structural rule should not be blocking");
  }
});

// ===========================================================================
// single-caller-abstraction scope.
//
// The rule asks the call graph "how many call sites name this symbol?". That
// question is only answerable where the language's construction syntax produces
// such a call site. Where it does not, the graph returns a structural zero for
// EVERY declaration, used or not, and the confirmation pass reads that zero as
// proof — so the rule fired on every new class in the diff regardless of usage.
// ===========================================================================

test("single-caller-abstraction: scoped to languages whose construction resolves to a call", async () => {
  const { STRUCTURAL_TSAST_RULES, STRUCTURAL_AST_RULES } = await import("../dist/core/rules/structural.js");

  const tsRule = STRUCTURAL_TSAST_RULES.find((r) => r.id === "single-caller-abstraction");
  assert.ok(tsRule, "tree-sitter half is registered");
  assert.deepEqual(
    [...tsRule.languages].sort(),
    ["python"],
    "Java/C#/PHP/Ruby/Kotlin build objects with `new Foo()` / `Foo.new`, which never produces a " +
      "call site named Foo — a caller count there is a structural zero, not evidence"
  );

  const astRule = STRUCTURAL_AST_RULES.find((r) => r.id === "single-caller-abstraction");
  assert.ok(astRule, "Babel half is registered");
  assert.deepEqual([...astRule.languages].sort(), ["javascript", "jsx", "tsx", "typescript"]);
});

test("single-caller-abstraction: interfaces are excluded — they are never called", async () => {
  const { STRUCTURAL_AST_RULES } = await import("../dist/core/rules/structural.js");
  const rule = STRUCTURAL_AST_RULES.find((r) => r.id === "single-caller-abstraction");

  const emitted = [];
  const emit = (e) => emitted.push(e);
  const ctx = { language: "typescript", filePath: "src/x.ts", changedLines: null };

  rule.visit({ type: "TSInterfaceDeclaration", id: { name: "Shape" }, loc: { start: { line: 1, column: 0 }, end: { line: 3, column: 1 } } }, null, ctx, emit);
  assert.deepEqual(emitted, [], "an interface's caller count is unconditionally zero");

  rule.visit({ type: "ClassDeclaration", id: { name: "Shape" }, loc: { start: { line: 1, column: 0 }, end: { line: 3, column: 1 } } }, null, ctx, emit);
  assert.equal(emitted.length, 1, "a class still emits — `new Shape()` is indexed as a call site");
  assert.equal(emitted[0].symbol, "Shape");
});

// ===========================================================================
// ts-over-generic: nesting can live in ANY type argument, not just the first.
// ===========================================================================

const tsGenericConfig = {
  ...DEFAULT_CONFIG,
  rules: { ...DEFAULT_CONFIG.rules, "ts-over-generic": { enabled: true } },
};

const overGenericHits = (content) =>
  analyze({ filePath: "t.ts", content, previousContent: null, changedLines: null, config: tsGenericConfig })
    .findings.filter((f) => f.ruleId === "ts-over-generic");

test("ts-over-generic: deep nesting in the FIRST type argument fires", () => {
  assert.equal(overGenericHits("type A = Promise<Array<Map<Set<string>>>>;").length, 1);
});

test("ts-over-generic: deep nesting in a LATER type argument also fires", () => {
  // The regression: descent followed only `params[0]`, so this scored 1 and stayed silent —
  // `Map<K, V>` puts the interesting half in the second argument, which is the common real shape.
  const hits = overGenericHits("type B = Map<string, Promise<Array<Set<number>>>>;");
  assert.equal(hits.length, 1, "nesting under the second type argument must be measured");
  assert.match(hits[0].message, /4 levels/);
});

test("ts-over-generic: nesting inside a union member is measured", () => {
  assert.equal(overGenericHits("type D = string | Promise<Array<Map<Set<number>>>>;").length, 1);
});

test("ts-over-generic: a shallow type alias stays quiet", () => {
  assert.deepEqual(overGenericHits("type C = Map<string, number>;"), []);
});

// ===========================================================================
// pass-through-wrapper: only a NAMED binding can be "inlined at the call site".
// ===========================================================================

const passThroughConfig = {
  ...DEFAULT_CONFIG,
  rules: { ...DEFAULT_CONFIG.rules, "pass-through-wrapper": { enabled: true } },
};

const passThroughHits = (content, filePath = "t.ts") =>
  analyze({ filePath, content, previousContent: null, changedLines: null, config: passThroughConfig })
    .findings.filter((f) => f.ruleId === "pass-through-wrapper");

test("pass-through-wrapper: an inline callback argument is not a wrapper", () => {
  // None of these have a call site to inline — the function IS the argument. And for the array
  // callbacks the suggested rewrite is not behaviour-preserving: map/filter/forEach pass
  // (element, index, array), which is why ["1","2","3"].map(parseInt) is [1, NaN, NaN].
  assert.deepEqual(passThroughHits("const loaded = langs.filter((l) => ready(l));"), []);
  assert.deepEqual(passThroughHits("const out = xs.map(x => parse(x));"), []);
  assert.deepEqual(passThroughHits("xs.forEach(x => log(x));"), []);
  assert.deepEqual(passThroughHits("setTimeout(() => flush(), 100);"), []);
  assert.deepEqual(passThroughHits("const C = () => <button onClick={e => handle(e)} />;", "t.tsx"), []);
});

test("pass-through-wrapper: a named delegation still fires, whatever binds the name", () => {
  for (const src of [
    "const getUser = (id) => fetchUser(id);",
    "function getUser(id) { return fetchUser(id); }",
    "getUser = (id) => fetchUser(id);",
    "const o = { getUser: (id) => fetchUser(id) };",
  ]) {
    const hits = passThroughHits(src);
    assert.equal(hits.length, 1, `should fire: ${src}`);
    assert.equal(hits[0].symbol, "getUser", `should name the symbol: ${src}`);
    assert.match(hits[0].message, /getUser/);
  }
});

test("pass-through-wrapper: a wrapper that reshapes arguments is doing real work", () => {
  assert.deepEqual(passThroughHits("const f = (x) => ready(x, true);"), []);
  assert.deepEqual(passThroughHits("const f = (a, b) => ready(b, a);"), []);
});
