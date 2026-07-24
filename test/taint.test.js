import test from "node:test";
import assert from "node:assert/strict";

import { analyze, DEFAULT_CONFIG } from "../dist/core/index.js";
import { classifySecret, shannonEntropy } from "../dist/core/taint.js";

const cfg = DEFAULT_CONFIG;
const find = (res, ruleId) => res.findings.find((f) => f.ruleId === ruleId);

// --- A. XSS sanitizer-aware down-tiering (native, no code graph) -------------

test("xss-sink: an unsanitized dynamic innerHTML stays a blocking-class orange", () => {
  const res = analyze({ filePath: "v.js", content: `el.innerHTML = req.query.name;\n`, config: cfg });
  const f = find(res, "xss-sink");
  assert.ok(f, "xss-sink should fire");
  assert.equal(f.tier, "orange");
  assert.ok(!f.tierAdjusted, "an unsanitized finding carries no tier adjustment");
});

test("xss-sink: DOMPurify.sanitize at the sink down-tiers orange → yellow review", () => {
  const res = analyze({ filePath: "v.js", content: `el.innerHTML = DOMPurify.sanitize(req.query.name);\n`, config: cfg });
  const f = find(res, "xss-sink");
  assert.ok(f, "xss-sink should still fire (we enrich, not suppress)");
  assert.equal(f.tier, "yellow");
  assert.equal(f.blocking, false);
  assert.equal(f.tierAdjusted, "deescalated");
  assert.match(f.message, /sanitizer/i);
});

test("xss-sink: escapeHtml is recognized as a sanitizer", () => {
  const res = analyze({ filePath: "v.js", content: `el.innerHTML = escapeHtml(userInput);\n`, config: cfg });
  assert.equal(find(res, "xss-sink").tier, "yellow");
});

test("xss-sink: down-tier follows a local variable to its sanitizer", () => {
  const content = `const clean = DOMPurify.sanitize(dirty);\nel.innerHTML = clean;\n`;
  const res = analyze({ filePath: "v.js", content, config: cfg });
  const f = find(res, "xss-sink");
  assert.ok(f, "xss-sink should fire on the aliased assignment");
  assert.equal(f.tier, "yellow");
  assert.equal(f.tierAdjusted, "deescalated");
});

test("xss-sink: an unrelated function call is NOT treated as a sanitizer", () => {
  const res = analyze({ filePath: "v.js", content: `el.innerHTML = renderTemplate(req.query.name);\n`, config: cfg });
  assert.equal(find(res, "xss-sink").tier, "orange", "renderTemplate must not be mistaken for a sanitizer");
});

// --- B. Extended request-derived taint sources -------------------------------

test("path-traversal: now recognizes req.cookies as a taint source", () => {
  const res = analyze({ filePath: "f.js", content: `fs.readFile(path.join(__dirname, req.cookies.file));\n`, config: cfg });
  assert.ok(find(res, "path-traversal"), "request cookies should be treated as user input");
});

// --- C. Secret-finding precision (entropy + placeholders) --------------------

test("hardcoded-secret: keeps a real-looking generic value (regression guard)", () => {
  const res = analyze({ filePath: "c.js", content: `const apiKey = "supersecretvalue123";\n`, config: cfg });
  const f = find(res, "hardcoded-secret");
  assert.ok(f, "a high-entropy generic secret must still be flagged");
  assert.equal(f.tier, "orange");
  assert.equal(f.blocking, true);
});

test("hardcoded-secret: keeps known provider key formats and labels confidence", () => {
  const res = analyze({ filePath: "c.js", content: `const k = "sk_live_abcdef0123456789abcd";\n`, config: cfg });
  const f = find(res, "hardcoded-secret");
  assert.ok(f, "known key format must always be flagged");
  assert.match(f.message, /high confidence/i);
});

test("hardcoded-secret: drops obvious placeholders", () => {
  const res = analyze({ filePath: "c.js", content: `const secret = "changeme";\n`, config: cfg });
  assert.equal(find(res, "hardcoded-secret"), undefined, "placeholder value should not be flagged");
});

test("hardcoded-secret: drops env-var references, not committed secrets", () => {
  const res = analyze({ filePath: "c.js", content: 'const apiKey = "${process.env.API_KEY}";\n', config: cfg });
  assert.equal(find(res, "hardcoded-secret"), undefined, "env interpolation is config, not a secret");
});

test("hardcoded-secret: env-var-name → display-label maps are not secrets", () => {
  // Real-world false block (2026-07-08): sidebar labels keyed by env-var name.
  const content =
    'KEY_LABELS = {"FULLENRICH_API_KEY": "FullEnrich", "OPENAI_API_KEY": "OpenAI", "TAVILY_API_KEY": "Tavily"}\n';
  const res = analyze({ filePath: "app.py", content, config: cfg });
  assert.equal(find(res, "hardcoded-secret"), undefined, "label values mirroring their key name are not credentials");
});

test("classifySecret: unit behavior", () => {
  assert.equal(classifySecret('apiKey = "changeme"').skip, true);
  assert.equal(classifySecret('apiKey = "your-key-here"').skip, true);
  assert.equal(classifySecret('token = "${process.env.X}"').skip, true);
  assert.ok(!classifySecret('apiKey = "supersecretvalue123"').skip);
  assert.match(classifySecret("AKIAIOSFODNN7EXAMPLE").note || "", /provider key format/i);
  // env-var-name → label maps are configuration, not credentials
  assert.equal(classifySecret('FULLENRICH_API_KEY": "FullEnrich"').skip, true);
  assert.equal(classifySecret('token = "GITHUB_ACCESS_TOKEN"').skip, true);
  assert.ok(!classifySecret('client_secret = "9f8a7b6c5d4e3f2a1b0c"').skip, "real-looking value still fires");
});

test("shannonEntropy: random strings score higher than repetitive ones", () => {
  assert.ok(shannonEntropy("aaaaaaaa") < 1);
  assert.ok(shannonEntropy("a8Fk2Lq9Zx") > 3);
});

// --- D. AI-era provider key formats (0.7.4) -----------------------------------
// The tool's identity is "triage AI-written diffs" — AI-generated code disproportionately embeds
// AI-provider keys, often INLINE (a bare key in a fetch header has no `key = "…"` assignment shape
// for the generic pattern). Each format must be flagged blocking + high-confidence, and must also be
// recognized by classifySecret's KNOWN_TOKEN_RE (the two lists must stay in sync).
const FAKE_KEYS = {
  anthropic: "sk-ant-api03-" + "A".repeat(40),
  openaiProject: "sk-proj-" + "B".repeat(40),
  openaiLegacy: "sk-" + "C".repeat(20) + "T3BlbkFJ" + "D".repeat(20),
  huggingface: "hf_" + "E".repeat(34),
  gitlab: "glpat-" + "F".repeat(20),
  npm: "npm_" + "G".repeat(36),
};

for (const [provider, key] of Object.entries(FAKE_KEYS)) {
  test(`hardcoded-secret: ${provider} key format is flagged blocking + high-confidence`, () => {
    const res = analyze({ filePath: "c.js", content: `const k = "${key}";\n`, config: cfg });
    const f = find(res, "hardcoded-secret");
    assert.ok(f, `${provider} key must be flagged`);
    assert.equal(f.tier, "orange");
    assert.equal(f.blocking, true);
    assert.match(f.message, /high confidence/i, "must carry the known-provider confidence note");
  });
  test(`classifySecret: ${provider} format matches KNOWN_TOKEN_RE`, () => {
    assert.match(classifySecret(key).note || "", /provider key format/i);
  });
}

test("hardcoded-secret: a BARE inline AI key (no assignment shape) is still caught", () => {
  const res = analyze({
    filePath: "c.js",
    content: `fetch(url, { headers: { "x-api-key": "${FAKE_KEYS.anthropic}" } });\n`,
    config: cfg,
  });
  assert.ok(find(res, "hardcoded-secret"), "inline header keys have no key= shape — the format must carry it");
});

test("hardcoded-secret: prose/short lookalikes of the new prefixes are NOT flagged", () => {
  for (const content of [
    `// keys start with the sk-proj- prefix\n`,
    `const mode = "sk-ant";\n`,
    `const pkg = "npm_package_name";\n`, // npm_ requires exactly 36 alnum after the prefix
  ]) {
    const res = analyze({ filePath: "c.js", content, config: cfg });
    assert.equal(find(res, "hardcoded-secret"), undefined, `must not flag: ${content.trim()}`);
  }
});

test("hardcoded-secret: an env reference for an AI key stays unflagged", () => {
  const res = analyze({ filePath: "c.js", content: `const k = process.env.ANTHROPIC_API_KEY;\n`, config: cfg });
  assert.equal(find(res, "hardcoded-secret"), undefined);
});
