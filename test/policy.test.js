import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../dist/core/config.js";
import { loadMergedLearnings } from "../dist/core/learnings.js";

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "diffgate-policy-"));
}
function write(dir, name, obj) {
  const p = path.join(dir, name);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
}

test("config extends (org policy packs)", async (t) => {
  await t.test("merges base-first, local wins", () => {
    const dir = tmp();
    write(dir, "team.diffgate.json", {
      customPatterns: [{ id: "base-rule", pattern: "X" }],
      rules: { "todo-marker": false },
      deprecated: [{ pattern: "Old.method", replacedBy: "New.method" }],
      gate: { failOn: "yellow" },
    });
    write(dir, ".diffgate.json", {
      extends: "./team.diffgate.json",
      customPatterns: [{ id: "local-rule", pattern: "Y" }],
      rules: { "network-call": false },
      gate: { failOn: "orange" },
    });
    const { config } = loadConfig(dir);
    assert.deepEqual(config.customPatterns.map((p) => p.id), ["base-rule", "local-rule"]); // concat
    assert.equal(config.rules["todo-marker"], false); // from base
    assert.equal(config.rules["network-call"], false); // from local
    assert.equal(config.gate.failOn, "orange"); // local wins
    assert.ok(config.deprecated.some((d) => d.pattern === "Old.method"));
    assert.equal(config.extends, undefined); // stripped after resolution
  });

  await t.test("chains multiple extends", () => {
    const dir = tmp();
    write(dir, "a.json", { customPatterns: [{ id: "a" }] });
    write(dir, "b.json", { customPatterns: [{ id: "b" }] });
    write(dir, ".diffgate.json", { extends: ["./a.json", "./b.json"], customPatterns: [{ id: "c" }] });
    const { config } = loadConfig(dir);
    assert.deepEqual(config.customPatterns.map((p) => p.id), ["a", "b", "c"]);
  });

  await t.test("resolves a package-style policy pack from node_modules", () => {
    const dir = tmp();
    write(dir, "node_modules/@acme/policy/.diffgate.json", { customPatterns: [{ id: "pkg" }] });
    write(dir, ".diffgate.json", { extends: "@acme/policy" });
    const { config } = loadConfig(dir);
    assert.deepEqual(config.customPatterns.map((p) => p.id), ["pkg"]);
  });

  await t.test("detects circular extends", () => {
    const dir = tmp();
    write(dir, "a.json", { extends: "./b.json" });
    write(dir, "b.json", { extends: "./a.json" });
    write(dir, ".diffgate.json", { extends: "./a.json" });
    assert.throws(() => loadConfig(dir), /Circular|extends/i);
  });

  await t.test("errors on missing extends target", () => {
    const dir = tmp();
    write(dir, ".diffgate.json", { extends: "./nope.json" });
    assert.throws(() => loadConfig(dir), /not found|extends/i);
  });
});

test("config validation of enum fields", async (t) => {
  await t.test("rejects an invalid gate.agent.mode (no silent fallback)", () => {
    const dir = tmp();
    write(dir, ".diffgate.json", { gate: { agent: { mode: "gated2" } } });
    assert.throws(() => loadConfig(dir), /agent\.mode must be one of/);
  });

  await t.test("rejects an invalid gate.failOn", () => {
    const dir = tmp();
    write(dir, ".diffgate.json", { gate: { failOn: "red" } });
    assert.throws(() => loadConfig(dir), /failOn must be one of/);
  });

  await t.test("rejects an invalid agent.autoFixFloor and trustSource", () => {
    const d1 = tmp();
    write(d1, ".diffgate.json", { gate: { agent: { autoFixFloor: "purple" } } });
    assert.throws(() => loadConfig(d1), /autoFixFloor must be one of/);
    const d2 = tmp();
    write(d2, ".diffgate.json", { gate: { agent: { trustSource: "vibes" } } });
    assert.throws(() => loadConfig(d2), /trustSource must be one of/);
  });

  await t.test("rejects an invalid gate.mode (no silent fallback to working)", () => {
    const dir = tmp();
    write(dir, ".diffgate.json", { gate: { mode: "stagedd" } });
    assert.throws(() => loadConfig(dir), /gate\.mode must be one of/);
  });

  await t.test("rejects an invalid guidelines.evaluator and tier", () => {
    const d1 = tmp();
    write(d1, ".diffgate.json", { guidelines: { evaluator: "modle" } });
    assert.throws(() => loadConfig(d1), /guidelines\.evaluator must be one of/);
    const d2 = tmp();
    write(d2, ".diffgate.json", { guidelines: { tier: "red" } });
    assert.throws(() => loadConfig(d2), /guidelines\.tier must be one of/);
  });

  await t.test("rejects an invalid graph.mode and provider", () => {
    const d1 = tmp();
    write(d1, ".diffgate.json", { graph: { mode: "clii" } });
    assert.throws(() => loadConfig(d1), /graph\.mode must be one of/);
    const d2 = tmp();
    write(d2, ".diffgate.json", { graph: { provider: "neo4j" } });
    assert.throws(() => loadConfig(d2), /graph\.provider must be one of/);
  });

  await t.test("rejects an invalid graph.enabled / security (boolean | \"auto\")", () => {
    const d1 = tmp();
    write(d1, ".diffgate.json", { graph: { enabled: "yes" } });
    assert.throws(() => loadConfig(d1), /graph\.enabled must be one of/);
    const d2 = tmp();
    write(d2, ".diffgate.json", { graph: { security: "sometimes" } });
    assert.throws(() => loadConfig(d2), /graph\.security must be one of/);
  });

  await t.test("accepts valid values", () => {
    const dir = tmp();
    write(dir, ".diffgate.json", {
      gate: { mode: "staged", failOn: "yellow", agent: { mode: "off", autoFixFloor: "green", trustSource: "any" } },
      guidelines: { evaluator: "host", tier: "orange" },
      graph: { mode: "off", provider: "codegraph", enabled: false, security: "auto" },
    });
    const { config } = loadConfig(dir);
    assert.equal(config.gate.agent.mode, "off");
    assert.equal(config.gate.mode, "staged");
    assert.equal(config.guidelines.evaluator, "host");
    assert.equal(config.graph.enabled, false);
  });
});

test("shared learnings (org-wide noise suppression)", async (t) => {
  await t.test("merges shared + local stores; local wins per id", () => {
    const shared = tmp();
    const repo = tmp();
    write(shared, ".diffgate/learnings.json", { version: 1, entries: [
      { id: "todo-marker:aaa", ruleId: "todo-marker", codeHash: "aaa", verdict: "dismiss", at: "1" },
      { id: "shared-only:bbb", ruleId: "x", codeHash: "bbb", verdict: "dismiss", at: "1" },
    ] });
    write(repo, ".diffgate/learnings.json", { version: 1, entries: [
      { id: "todo-marker:aaa", ruleId: "todo-marker", codeHash: "aaa", verdict: "confirm", at: "2" }, // overrides shared
      { id: "local-only:ccc", ruleId: "y", codeHash: "ccc", verdict: "dismiss", at: "2" },
    ] });
    const merged = loadMergedLearnings(repo, [shared], repo);
    const byId = Object.fromEntries(merged.entries.map((e) => [e.id, e]));
    assert.equal(Object.keys(byId).length, 3);
    assert.equal(byId["todo-marker:aaa"].verdict, "confirm"); // local override
    assert.ok(byId["shared-only:bbb"]);
    assert.ok(byId["local-only:ccc"]);
  });

  await t.test("missing shared store is harmless", () => {
    const repo = tmp();
    const merged = loadMergedLearnings(repo, ["/does/not/exist"], repo);
    assert.deepEqual(merged.entries, []);
  });
});
