import test from "node:test";
import assert from "node:assert";
import { runBench, CORPUS } from "../dist/bench.js";
import { analyze } from "../dist/core/analyzer.js";

test("noise benchmark", async (t) => {
  const result = runBench(analyze, CORPUS);

  await t.test("covers the whole corpus", () => {
    assert.equal(result.cases, CORPUS.length);
    assert.ok(result.positives > 0);
    assert.ok(result.cleanCases > 0);
  });

  await t.test("zero false BLOCKS on clean changes (the headline claim)", () => {
    assert.equal(result.falseBlocksPerCleanCase, 0, `the gate must never falsely block a safe change; got ${result.falseBlocksPerCleanCase}/case`);
  });

  await t.test("high recall on the positive cases", () => {
    assert.ok(result.overall.recall >= 0.8, `recall too low: ${result.overall.recall}`);
  });

  await t.test("metrics are well-formed", () => {
    for (const r of result.rules) {
      assert.ok(r.precision >= 0 && r.precision <= 1);
      assert.ok(r.recall >= 0 && r.recall <= 1);
      assert.ok(r.f1 >= 0 && r.f1 <= 1);
    }
  });

  await t.test("custom corpus: a known noisy analyzer scores a false block", () => {
    const noisy = () => ({ filePath: "x", language: "js", findings: [{ ruleId: "sql-injection", tier: "orange", blocking: true }], tier: "orange", counts: {}, blocking: true });
    const r = runBench(noisy, [{ name: "clean", language: "javascript", content: "const x = 1;", expected: [] }]);
    assert.equal(r.falseBlocksPerCleanCase, 1);
  });
});
