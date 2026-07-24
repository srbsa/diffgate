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
  const content = `function nested(a, b, c, d) {
  if (a) {
    if (b) {
      if (c) {
        if (d) {
          return true;
        }
      }
    }
  }
}`;

  const result = analyze({ filePath, content, config: DEFAULT_CONFIG, changedLines: new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) });

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
