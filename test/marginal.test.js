import test from "node:test";
import assert from "node:assert/strict";
import { analyze } from "../dist/core/index.js";
import {
  runMarginal, runMarginalSampled, modelRunner, extractCode, SCENARIOS,
  wilsonInterval, scenariosForMode, buildPrompt,
} from "../dist/marginal.js";

const analyzeFn = (a) => analyze(a);

test("SCENARIOS are well-formed (id, task, filename, targetRules)", () => {
  assert.ok(SCENARIOS.length >= 10);
  const ids = new Set();
  for (const s of SCENARIOS) {
    assert.ok(s.id && !ids.has(s.id), `unique id: ${s.id}`);
    ids.add(s.id);
    assert.ok(s.task.length > 20, `${s.id} has a real task`);
    assert.ok(/\.[a-z]+$/.test(s.filename), `${s.id} filename has an extension`);
    assert.ok(Array.isArray(s.targetRules) && s.targetRules.length > 0);
  }
});

test("extractCode prefers fenced blocks and strips <think>", () => {
  assert.equal(extractCode("```js\nconst a = 1;\n```"), "const a = 1;");
  assert.equal(extractCode("<think>plan</think>\n```\nx()\n```"), "x()");
  assert.equal(extractCode("no fences here"), "no fences here");
});

test("runMarginal counts a catch when the agent ships an injectable query", async () => {
  // Fake agent that writes the naive (vulnerable) implementation for the SQL lookup task.
  const runner = async (s) => {
    if (s.id === "sql-user-lookup") {
      return { raw: "x", code: "const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;\npool.query(sql);\n" };
    }
    return { raw: "x", code: "function add(a, b) { return a + b; }\n" }; // clean for the rest
  };
  const result = await runMarginal(SCENARIOS, runner, analyzeFn);
  assert.equal(result.total, SCENARIOS.length);
  assert.ok(result.defectCatches >= 1, "the injectable query is a defect catch");
  const sql = result.byScenario.find((r) => r.id === "sql-user-lookup");
  assert.equal(sql.caught, true);
  assert.equal(sql.kind, "defect", "sql-injection is a defect, not an advisory");
  assert.equal(sql.onTarget, true, "fired rule matches the designed-for risk");
  assert.ok(sql.firedRules.includes("sql-injection"));
  assert.ok(result.marginalCatchRate > 0 && result.marginalCatchRate <= 1);
});

test("a sensitive-area advisory (secure PBKDF2 auth) scores as advisory, not a defect", async () => {
  // The secure password-hashing code from the live run trips auth-crypto, which is a "get review"
  // nudge that fires on correct code — it must NOT inflate the defect-catch rate.
  const secureAuth =
    "const crypto = require('crypto');\n" +
    "function hashPassword(p){const s=crypto.randomBytes(16).toString('hex');" +
    "const k=crypto.pbkdf2Sync(p,s,100000,64,'sha512');return {salt:s,hash:k.toString('hex')};}\n";
  const runner = async (s) => ({ raw: "x", code: s.id === "password-hash" ? secureAuth : "function add(a, b) { return a + b; }\n" });
  const result = await runMarginal(SCENARIOS, runner, analyzeFn);
  const auth = result.byScenario.find((r) => r.id === "password-hash");
  assert.equal(auth.caught, true, "auth-crypto fired");
  assert.equal(auth.kind, "advisory", "but it is an advisory, not a defect");
  assert.equal(auth.onTarget, false, "advisory firing on correct code is not an on-target defect catch");
  assert.equal(result.defectCatches, 0, "no defect among these");
  assert.ok(result.advisoryOnly >= 1);
  assert.equal(result.marginalCatchRate, 0, "advisories never inflate the defect-catch headline");
});

test("runMarginal: a clean agent yields a 0% marginal catch rate", async () => {
  const runner = async () => ({ raw: "x", code: "export function add(a, b) { return a + b; }\n" });
  const result = await runMarginal(SCENARIOS, runner, analyzeFn);
  assert.equal(result.catches, 0);
  assert.equal(result.marginalCatchRate, 0);
});

test("runMarginal records errors without counting them as catches or clean", async () => {
  const runner = async (s) => { if (s.id === "eval-calculator") throw new Error("model down"); return { raw: "", code: "function add(a, b) { return a + b; }\n" }; };
  const result = await runMarginal(SCENARIOS, runner, analyzeFn);
  assert.equal(result.errors, 1);
  const errored = result.byScenario.find((r) => r.id === "eval-calculator");
  assert.equal(errored.error, "model down");
  assert.equal(errored.caught, false);
  // rate denominator excludes the errored scenario
  assert.equal(result.marginalCatchRate, result.catches / (result.total - result.errors));
});

test("dangerous-exec scores as advisory whether the shell-out is safe or injectable", async () => {
  // The rule matches child_process/exec*/spawn *presence*, so it cannot tell the safe array-arg
  // execFile from an injectable template-string exec. Both must score advisory, not defect — a hit
  // is "audit this shell-out", not proof the agent shipped a command injection.
  const safe = "const { execFile } = require('child_process');\n" +
    "function ping(host){ return new Promise((res,rej)=>execFile('ping',['-c','1',host],(e,o)=>e?rej(e):res(o))); }\n";
  const injectable = "const { exec } = require('child_process');\n" +
    "function ping(host){ return new Promise((res,rej)=>exec(`ping -c 1 ${host}`,(e,o)=>e?rej(e):res(o))); }\n";
  for (const code of [safe, injectable]) {
    const runner = async (s) => ({ raw: "x", code: s.id === "exec-ping" ? code : "function add(a, b) { return a + b; }\n" });
    const result = await runMarginal(SCENARIOS, runner, analyzeFn);
    const ping = result.byScenario.find((r) => r.id === "exec-ping");
    assert.equal(ping.caught, true, "dangerous-exec fires");
    assert.equal(ping.kind, "advisory", "but it is an advisory, not a defect");
    assert.equal(result.defectCatches, 0, "shell-out presence never counts as a defect catch");
  }
});

test("modelRunner extracts code from the completion's fenced output", async () => {
  const completeFn = async ({ prompt }) => ({ text: "```js\n// " + prompt.slice(0, 8) + "\nrun();\n```" });
  const runner = modelRunner(completeFn, { ai: { enabled: true, provider: "lmstudio" } });
  const out = await runner(SCENARIOS[0]);
  assert.ok(out.code.includes("run();"));
  assert.ok(!out.code.includes("```"), "fences stripped");
});

// --- EDIT mode: only the lines the agent changed are analyzed -----------------

test("edit mode analyzes ONLY the changed lines (diff-aware before-the-diff)", async () => {
  const scenario = {
    id: "edit-x", language: "javascript", filename: "x.js", targetRules: ["sql-injection"],
    task: "n/a",
    seed: {
      content: "const sql = `SELECT * FROM t WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
      request: "add a helper",
    },
  };
  // Returns the seed UNCHANGED plus a clean appended line: the pre-existing vuln is on unchanged lines.
  const unchanged = async (s) => ({ raw: "x", code: s.seed.content + "function ok() { return 1; }\n" });
  const r1 = await runMarginal([scenario], unchanged, analyzeFn, { mode: "edit" });
  assert.equal(r1.mode, "edit");
  assert.equal(r1.byScenario[0].kind, "clean", "a vuln on an UNCHANGED line is not flagged in edit mode");

  // Newly introduced injectable query (all lines changed) IS flagged.
  const introduced = async () => ({ raw: "x", code: "const id = req.query.id;\nconst sql = `SELECT * FROM t WHERE id = ${id}`;\ndb.query(sql);\n" });
  const r2 = await runMarginal([scenario], introduced, analyzeFn, { mode: "edit" });
  assert.equal(r2.byScenario[0].kind, "defect", "a newly introduced injectable query is flagged");
  assert.ok(r2.byScenario[0].firedRules.includes("sql-injection"));
});

test("scenariosForMode: edit needs a seed; buildPrompt embeds the seed file + request", () => {
  const edit = scenariosForMode(SCENARIOS, "edit");
  assert.ok(edit.length > 0 && edit.every((s) => s.seed), "every edit scenario carries a seed");
  assert.equal(scenariosForMode(SCENARIOS, "greenfield").length, SCENARIOS.length);
  const s = SCENARIOS.find((x) => x.id === "sql-user-lookup");
  assert.equal(buildPrompt(s, "greenfield").prompt, s.task);
  const e = buildPrompt(s, "edit");
  assert.ok(e.prompt.includes(s.seed.content.split("\n")[0]), "edit prompt embeds the seed contents");
  assert.ok(e.prompt.includes(s.seed.request), "edit prompt carries the change request");
});

// --- known-gap scenarios are tracked, never inflate/deflate the headline ------

test("knownGap scenarios are excluded from the headline and tracked via gapClean", async () => {
  // python-sql-lookup is a known gap: f-string SQLi has no orange rule, so it scores clean — and must
  // NOT be counted as the model writing safe code.
  const runner = async (s) => {
    if (s.id === "python-sql-lookup") {
      return { raw: "x", code: "def get_user(conn, user_id):\n    cur = conn.cursor()\n    cur.execute(f'SELECT * FROM users WHERE id = {user_id}')\n    return cur.fetchone()\n" };
    }
    return { raw: "x", code: "function add(a, b) { return a + b; }\n" };
  };
  const result = await runMarginal(SCENARIOS, runner, analyzeFn);
  const gap = result.byScenario.find((r) => r.id === "python-sql-lookup");
  assert.equal(gap.knownGap, true);
  assert.equal(gap.kind, "clean", "Python f-string SQLi is a DiffGate coverage gap → scores clean");
  assert.ok(result.gapClean >= 1, "the gap clean is tracked separately");
  assert.equal(result.scored, result.total - 2, "the 2 knownGap scenarios are out of the headline denominator");
  assert.equal(result.marginalCatchRate, 0);
});

// --- confidence: multi-sample + Wilson CI ------------------------------------

test("wilsonInterval bounds a binomial proportion", () => {
  assert.deepEqual(wilsonInterval(0, 0), { low: 0, high: 0 });
  const none = wilsonInterval(0, 10);
  assert.equal(none.low, 0);
  assert.ok(none.high > 0 && none.high < 0.4, "0/10 upper bound is well under 0.4");
  const half = wilsonInterval(5, 10);
  assert.ok(half.low < 0.5 && half.high > 0.5, "5/10 CI straddles 0.5");
  const all = wilsonInterval(10, 10);
  assert.equal(all.high, 1);
  assert.ok(all.low > 0.6);
});

test("runMarginalSampled reports a defect rate with a Wilson CI over pooled trials", async () => {
  let sqlCalls = 0;
  const injectable = "pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);\n";
  const runner = async (s) => {
    if (s.id === "sql-user-lookup") {
      const vuln = sqlCalls++ % 2 === 0; // defect on samples 1 & 3, clean on 2 & 4
      return { raw: "x", code: vuln ? injectable : "pool.query('SELECT 1');\n" };
    }
    return { raw: "x", code: "function add(a, b) { return a + b; }\n" };
  };
  const result = await runMarginalSampled(SCENARIOS, runner, analyzeFn, { samples: 4 });
  assert.equal(result.samples, 4);
  assert.equal(result.scoredScenarios, SCENARIOS.length - 2, "knownGap scenarios excluded");
  assert.equal(result.trials, result.scoredScenarios * 4, "4 samples per scored scenario, no errors");
  const sql = result.byScenario.find((a) => a.id === "sql-user-lookup");
  assert.equal(sql.samples, 4);
  assert.equal(sql.defect, 2, "defect on 2 of 4 samples");
  assert.equal(sql.defectFreq, 0.5);
  assert.equal(result.defectCatches, 2);
  assert.equal(result.defectRate, 2 / result.trials);
  assert.ok(result.ci.low >= 0 && result.ci.high <= 1 && result.ci.high > result.ci.low, "non-degenerate CI within [0,1]");
  assert.ok(result.ci.high > result.defectRate, "CI upper bound sits above the point estimate");
  assert.equal(result.runs.length, 4, "individual sample runs are retained for audit");
});
