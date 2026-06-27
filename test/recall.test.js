// Recall-spike integration (docs/DESIGN-recall-and-parity.md option B): borrowing Semgrep findings
// and running them through the gate. Uses canned semgrep --json output (real schema) via an injected
// runner — no semgrep binary needed for the unit tests.
import test from "node:test";
import assert from "node:assert/strict";
import {
  makeSemgrepProvider, parseSemgrep, mapSeverityToTier, diffScope, dedupeAgainst, toFindings,
  recallActive, getRecallProvider, attachRecall,
} from "../dist/core/index.js";

const result = (filePath, findings) => ({
  filePath, language: "python", findings,
  tier: "green", counts: { green: 0, yellow: 0, orange: 0 }, blocking: false, parseError: null,
});
const fakeProvider = (byPath) => ({
  id: "fake", scan: () => null,
  scanFiles: () => new Map(Object.entries(byPath)),
});

const SEMGREP_JSON = JSON.stringify({
  results: [
    { check_id: "python.lang.security.audit.dangerous-system-call", path: "app.py",
      start: { line: 12 }, end: { line: 12 }, extra: { severity: "ERROR", message: "os.system with input" } },
    { check_id: "python.flask.security.open-redirect", path: "app.py",
      start: { line: 30 }, end: { line: 31 }, extra: { severity: "WARNING", message: "open redirect" } },
    { check_id: "generic.secrets.gitleaks.generic-api-key", path: "app.py",
      start: { line: 5 }, extra: { severity: "INFO", message: "maybe a key" } },
  ],
  errors: [],
});

test("parseSemgrep: reads check_id, line, severity, message from --json", () => {
  const f = parseSemgrep(SEMGREP_JSON);
  assert.equal(f.length, 3);
  assert.equal(f[0].ruleId, "python.lang.security.audit.dangerous-system-call");
  assert.equal(f[0].line, 12);
  assert.equal(f[0].severity, "ERROR");
  assert.equal(f[1].endLine, 31);
});

test("parseSemgrep: garbage / empty / non-JSON → null (no-op, never throws)", () => {
  assert.equal(parseSemgrep(""), null);
  assert.equal(parseSemgrep(null), null);
  assert.equal(parseSemgrep("semgrep: command not found"), null);
  assert.equal(parseSemgrep('{"no_results": true}'), null);
});

test("mapSeverityToTier: capped at yellow (advisory), and NEVER blocking", () => {
  // Capped at yellow so a borrowed finding never trips the default failOn:orange gate.
  assert.deepEqual(mapSeverityToTier("ERROR"), { tier: "yellow", blocking: false });
  assert.deepEqual(mapSeverityToTier("WARNING"), { tier: "yellow", blocking: false });
  assert.deepEqual(mapSeverityToTier("INFO"), { tier: "green", blocking: false });
  assert.equal(mapSeverityToTier("WHATEVER").blocking, false);
  assert.notEqual(mapSeverityToTier("ERROR").tier, "orange", "borrowed findings never reach the gate tier");
});

test("diffScope: keeps only findings on changed lines; null = whole-file (keep all)", () => {
  const raw = parseSemgrep(SEMGREP_JSON);
  assert.equal(diffScope(raw, new Set([12])).length, 1);
  assert.equal(diffScope(raw, new Set([12, 30])).length, 2);
  assert.equal(diffScope(raw, null).length, 3);
});

test("dedupeAgainst: a native DiffGate finding on a line suppresses the borrowed one (ours wins)", () => {
  const raw = parseSemgrep(SEMGREP_JSON);
  const native = [{ ruleId: "dangerous-exec", line: 12 }];
  const kept = dedupeAgainst(raw, native);
  assert.ok(!kept.some((f) => f.line === 12), "line 12 already covered natively → dropped");
  assert.equal(kept.length, 2);
});

test("toFindings: namespaced ruleId, advisory tier, never blocking, trust unconfirmed", () => {
  const findings = toFindings(parseSemgrep(SEMGREP_JSON));
  assert.equal(findings[0].ruleId, "semgrep:dangerous-system-call");
  assert.equal(findings[0].tier, "yellow");
  assert.equal(findings[0].blocking, false);
  assert.equal(findings[0].trust, "unconfirmed");
  assert.ok(findings.every((f) => f.blocking === false), "no borrowed finding can block the gate");
  assert.ok(findings.every((f) => f.tier !== "orange"), "no borrowed finding reaches the gate tier");
});

test("makeSemgrepProvider: drives the injected runner and returns parsed findings", () => {
  const provider = makeSemgrepProvider({ runner: () => SEMGREP_JSON });
  const f = provider.scan("app.py", "");
  assert.equal(f.length, 3);
  // an unavailable engine (runner returns null) → null, not an error
  const off = makeSemgrepProvider({ runner: () => null });
  assert.equal(off.scan("app.py", ""), null);
});

// --- gating: off by default, "ci" only under CI, true always ---------------
test("recallActive: false/undefined is off; true is on; 'ci' depends on CI env", () => {
  assert.equal(recallActive({ enabled: false }), false);
  assert.equal(recallActive({}), false);
  assert.equal(recallActive({ enabled: true }), true);
  assert.equal(recallActive({ enabled: "ci" }, { CI: "true" }), true);
  assert.equal(recallActive({ enabled: "ci" }, {}), false);
  assert.equal(recallActive({ enabled: "ci" }, { CI: "false" }), false);
});

test("getRecallProvider: disabled config → null; injected provider is returned verbatim", () => {
  assert.equal(getRecallProvider("/repo", {}), null, "off by default");
  assert.equal(getRecallProvider("/repo", { recall: { enabled: false } }), null);
  const inj = fakeProvider({});
  assert.equal(getRecallProvider("/repo", { recall: { enabled: true } }, { provider: inj }), inj);
  assert.equal(getRecallProvider("/repo", { recall: { enabled: true, command: "definitely-not-semgrep-xyz" } }), null);
});

test("attachRecall: null provider is a pure no-op", () => {
  const files = [result("a.py", [])];
  assert.equal(attachRecall(files, { cwd: "/repo", config: {}, provider: null }), files);
});

test("attachRecall: borrowed findings are added to a file DiffGate flagged nothing on (recall value)", () => {
  const provider = fakeProvider({
    "a.py": [{ ruleId: "python.lang.ssrf", line: 3, severity: "ERROR", message: "ssrf", file: "a.py" }],
  });
  const [out] = attachRecall([result("a.py", [])], { cwd: "/repo", config: {}, provider });
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].ruleId, "semgrep:ssrf");
  assert.equal(out.findings[0].blocking, false, "borrowed finding never blocks");
  assert.equal(out.tier, "yellow", "result tier recomputed; borrowed advisory caps at yellow");
});

test("attachRecall: diff-scopes to changed lines and dedupes against native findings", () => {
  const provider = fakeProvider({
    "a.py": [
      { ruleId: "r.sqli", line: 2, severity: "ERROR", message: "sqli", file: "a.py" },
      { ruleId: "r.ssrf", line: 5, severity: "ERROR", message: "ssrf", file: "a.py" },
      { ruleId: "r.weak", line: 9, severity: "WARNING", message: "weak", file: "a.py" },
    ],
  });
  const native = result("a.py", [{ ruleId: "sql-injection", tier: "orange", blocking: true, line: 2, message: "" }]);
  const changed = new Map([["a.py", new Set([2, 5])]]);
  const [out] = attachRecall([native], { cwd: "/repo", config: {}, changed, provider });
  const borrowed = out.findings.filter((f) => f.ruleId.startsWith("semgrep:"));
  assert.deepEqual(borrowed.map((f) => f.ruleId), ["semgrep:ssrf"], "line 2 deduped, line 9 out of diff");
  assert.ok(out.findings.some((f) => f.ruleId === "sql-injection"), "native finding preserved");
});

// End-to-end of the gate pipeline on borrowed findings: diff-scope → dedupe → map → never blocks.
test("pipeline: borrowed findings are diff-scoped, deduped, and cannot block the gate", () => {
  const raw = parseSemgrep(SEMGREP_JSON);
  const native = [{ ruleId: "dangerous-exec", line: 12 }];
  const scoped = diffScope(dedupeAgainst(raw, native), new Set([12, 30, 31]));
  const findings = toFindings(scoped);
  assert.equal(findings.length, 1); // line 12 deduped, line 5 out of diff → only line 30 survives
  assert.equal(findings[0].ruleId, "semgrep:open-redirect");
  assert.ok(findings.every((f) => !f.blocking));
});
