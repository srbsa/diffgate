import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { detectProjectDefaults, tailorConfig } from "../dist/scaffold.js";

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "diffgate-scaffold-"));
}

test("detectProjectDefaults", async (t) => {
  await t.test("npm test from package.json", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ scripts: { test: "jest" } }));
    fs.writeFileSync(path.join(dir, "index.js"), "1");
    const d = detectProjectDefaults(dir);
    assert.equal(d.testCommand, "npm test");
    assert.deepEqual(d.languages, ["javascript"]);
  });

  await t.test("ignores the npm placeholder test script", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ scripts: { test: 'echo "Error: no test specified" && exit 1' } }));
    const d = detectProjectDefaults(dir);
    assert.equal(d.testCommand, null);
  });

  await t.test("pytest for python projects", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "pyproject.toml"), "[tool.poetry]");
    fs.writeFileSync(path.join(dir, "main.py"), "x = 1");
    const d = detectProjectDefaults(dir);
    assert.equal(d.testCommand, "pytest");
    assert.deepEqual(d.languages, ["python"]);
  });

  await t.test("go test for go modules", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "go.mod"), "module x");
    const d = detectProjectDefaults(dir);
    assert.equal(d.testCommand, "go test ./...");
  });

  await t.test("make test when Makefile has a test target", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "Makefile"), "test:\n\techo hi\n");
    const d = detectProjectDefaults(dir);
    assert.equal(d.testCommand, "make test");
  });

  await t.test("detects guideline files and scans src/", () => {
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "AGENTS.md"), "# rules");
    fs.mkdirSync(path.join(dir, "src"));
    fs.writeFileSync(path.join(dir, "src", "a.ts"), "1");
    const d = detectProjectDefaults(dir);
    assert.deepEqual(d.guidelineFiles, ["AGENTS.md"]);
    assert.deepEqual(d.languages, ["typescript"]);
  });

  await t.test("empty project → no test command, reasons populated", () => {
    const dir = tmp();
    const d = detectProjectDefaults(dir);
    assert.equal(d.testCommand, null);
    assert.ok(d.reasons.length > 0);
  });
});

test("tailorConfig merges detected defaults", () => {
  const base = { testCommand: null, guidelines: { enabled: true, tier: "yellow" } };
  const out = tailorConfig(base, { testCommand: "npm test", languages: ["javascript"], guidelineFiles: ["AGENTS.md"], reasons: [] });
  assert.equal(out.testCommand, "npm test");
  assert.equal(out.guidelines.enabled, true);
  assert.equal(out.guidelines.tier, "yellow"); // preserved
});
