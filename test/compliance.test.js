import test from "node:test";
import assert from "node:assert";
import { complianceReport, RULE_CONTROLS, CONTROLS } from "../dist/compliance.js";

function file(findings) {
  return { filePath: "/repo/a.js", language: "javascript", findings, tier: "green", counts: {}, blocking: false };
}
function finding(ruleId, over = {}) {
  return { ruleId, tier: "orange", blocking: true, title: ruleId, message: "m", line: 1, column: 0, endLine: 1, endColumn: 1, code: "", fix: null, ...over };
}

test("compliance report", async (t) => {
  await t.test("maps rules to SOC 2 controls", () => {
    const rep = complianceReport([file([finding("hardcoded-secret"), finding("sql-injection")])]);
    const ids = rep.evidence.map((e) => e.control.id);
    assert.ok(ids.includes("CC6.1")); // secret → logical access
    assert.ok(ids.includes("CC6.6")); // sql-injection → boundary
    assert.equal(rep.totalFindings, 2);
    assert.equal(rep.blocked, true);
  });

  await t.test("aggregates finding counts per control", () => {
    const rep = complianceReport([file([finding("sql-injection"), finding("xss-sink"), finding("path-traversal")])]);
    const cc66 = rep.evidence.find((e) => e.control.id === "CC6.6");
    assert.ok(cc66);
    assert.equal(cc66.findings, 3);
    assert.deepEqual(cc66.rules, ["path-traversal", "sql-injection", "xss-sink"]);
  });

  await t.test("tracks unmapped rules", () => {
    const rep = complianceReport([file([finding("todo-marker", { tier: "green", blocking: false })])]);
    assert.deepEqual(rep.unmapped, ["todo-marker"]);
    assert.equal(rep.evidence.length, 0);
  });

  await t.test("every mapped control id is defined", () => {
    for (const controls of Object.values(RULE_CONTROLS)) {
      for (const c of controls) assert.ok(CONTROLS[c], `missing control def: ${c}`);
    }
  });
});
