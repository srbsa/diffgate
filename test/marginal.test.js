import test from "node:test";
import assert from "node:assert/strict";
import { analyze } from "../dist/core/index.js";
import { runMarginal, modelRunner, extractCode, SCENARIOS } from "../dist/marginal.js";

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
