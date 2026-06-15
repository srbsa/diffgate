import test from "node:test";
import assert from "node:assert";
import { analyze } from "../dist/core/analyzer.js";

const JS_CONFIG = { rules: {} };

test("AST Rules Benchmarking & Accuracy Verification", async (t) => {
  // --- Test Snippets ---
  const unsafeSqlLiteral = `
    const sql = \`SELECT * FROM users WHERE id = \${req.query.id}\`;
    db.query(sql);
  `;
  const unsafeSqlConcat = `
    const sql = "SELECT * FROM users WHERE id = " + req.query.id;
    db.query(sql);
  `;
  const safeSqlParameterized = `
    const sql = "SELECT * FROM users WHERE id = ?";
    db.query(sql, [req.query.id]);
  `;

  const unsafePathTraversal = `
    const filepath = path.join(__dirname, req.query.filename);
    fs.readFile(filepath, 'utf8');
  `;
  const safePathResolved = `
    const filepath = path.resolve(__dirname, 'static_file.txt');
    fs.readFile(filepath, 'utf8');
  `;

  const unsafeXss = `
    element.innerHTML = "<b>Hello " + req.query.name + "</b>";
  `;
  const safeXssStatic = `
    element.innerHTML = "<b>Hello User</b>";
  `;

  // --- 1. Accuracy Check (Recall & Precision) ---
  await t.test("Recall: Detect SQL Injection correctly", () => {
    const res1 = analyze({ filePath: "test.js", content: unsafeSqlLiteral, config: JS_CONFIG });
    assert.ok(res1.findings.some(f => f.ruleId === "sql-injection"), "Should catch template literal SQL injection");

    const res2 = analyze({ filePath: "test.js", content: unsafeSqlConcat, config: JS_CONFIG });
    assert.ok(res2.findings.some(f => f.ruleId === "sql-injection"), "Should catch concatenated SQL injection");
  });

  await t.test("Precision: Ignore Parameterized SQL queries", () => {
    const res = analyze({ filePath: "test.js", content: safeSqlParameterized, config: JS_CONFIG });
    const hasSqlInjection = res.findings.some(f => f.ruleId === "sql-injection");
    assert.strictEqual(hasSqlInjection, false, "Should NOT flag parameterized SQL queries");
  });

  await t.test("Recall: Detect Path Traversal correctly", () => {
    const res = analyze({ filePath: "test.js", content: unsafePathTraversal, config: JS_CONFIG });
    assert.ok(res.findings.some(f => f.ruleId === "path-traversal"), "Should catch path traversal containing request parameters");
  });

  await t.test("Precision: Ignore Static Path Resolution", () => {
    const res = analyze({ filePath: "test.js", content: safePathResolved, config: JS_CONFIG });
    const hasPathTraversal = res.findings.some(f => f.ruleId === "path-traversal");
    assert.strictEqual(hasPathTraversal, false, "Should NOT flag safe static path resolution");
  });

  await t.test("Recall: Detect XSS Sinks correctly", () => {
    const res = analyze({ filePath: "test.js", content: unsafeXss, config: JS_CONFIG });
    assert.ok(res.findings.some(f => f.ruleId === "xss-sink"), "Should catch dynamic assignment to innerHTML");
  });

  await t.test("Precision: Ignore Static innerHTML Assignment", () => {
    const res = analyze({ filePath: "test.js", content: safeXssStatic, config: JS_CONFIG });
    const hasXss = res.findings.some(f => f.ruleId === "xss-sink");
    assert.strictEqual(hasXss, false, "Should NOT flag static assignments to innerHTML");
  });

  // --- 2. Performance Speed Benchmark ---
  await t.test("Speed Benchmark: Run full file analysis in under 5ms", () => {
    const content = `
      const express = require('express');
      const app = express();
      app.get('/user', (req, res) => {
        const query = "SELECT * FROM users WHERE id = " + req.query.id;
        db.query(query, (err, user) => {
          element.innerHTML = "<div>" + user.name + "</div>";
          res.json(user);
        });
      });
    `;

    const start = performance.now();
    const iterations = 100;
    for (let i = 0; i < iterations; i++) {
      analyze({ filePath: "app.js", content, config: JS_CONFIG });
    }
    const end = performance.now();
    const avgMs = (end - start) / iterations;
    
    console.log(`\n  ⚡ Average AST rules execution time: ${avgMs.toFixed(3)}ms`);
    assert.ok(avgMs < 5.0, `AST rules execution must take less than 5ms (was ${avgMs.toFixed(3)}ms)`);
  });

  await t.test("Rule Packs: Disabling 'web-security' disables sql-injection finding", () => {
    const disabledConfig = {
      rules: {
        "web-security": false
      }
    };
    const res = analyze({ filePath: "test.js", content: unsafeSqlLiteral, config: disabledConfig });
    const hasSqlInjection = res.findings.some(f => f.ruleId === "sql-injection");
    assert.strictEqual(hasSqlInjection, false, "SQL injection should be skipped when web-security pack is disabled");
  });
});
