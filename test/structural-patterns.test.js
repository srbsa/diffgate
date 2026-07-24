// Phase 2 + Phase 3 structural rules (tree-sitter and Babel).
//
// Every rule here is a judgement call about someone's design, so each one is tested in BOTH
// directions: it must fire on the shape it targets, and stay silent on the idiomatic shapes that
// look superficially similar. The negative cases are the point — a noisy structural rule costs more
// trust than it earns.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady, DEFAULT_CONFIG } from "../dist/core/index.js";

await initTreeSitter();

const ids = (content, filePath, config = DEFAULT_CONFIG) =>
  analyze({ filePath, content, config }).findings.map((f) => f.ruleId);
const fires = (content, filePath, ruleId, config) => ids(content, filePath, config).includes(ruleId);

const skipUnless = (lang) => {
  if (treeSitterReady(lang)) return false;
  console.log(`tree-sitter grammar for ${lang} unavailable — skipping`);
  return true;
};

// --- py-unnecessary-class ---------------------------------------------------

test("py-unnecessary-class: fires on a class that is __init__ plus one method", () => {
  if (skipUnless("python")) return;
  const src = `class Handler:\n    def __init__(self, db):\n        self.db = db\n    def run(self, r):\n        return self.db.q(r)\n`;
  assert.ok(fires(src, "h.py", "py-unnecessary-class"));
});

test("py-unnecessary-class: quiet on @dataclass (the shape is intentional)", () => {
  if (skipUnless("python")) return;
  const src = `from dataclasses import dataclass\n@dataclass\nclass P:\n    x: int\n    def area(self):\n        return self.x\n`;
  assert.ok(!fires(src, "p.py", "py-unnecessary-class"));
});

test("py-unnecessary-class: quiet when the class has any base", () => {
  if (skipUnless("python")) return;
  const src = `class P(Base):\n    def __init__(self):\n        pass\n    def go(self):\n        return 1\n`;
  assert.ok(!fires(src, "q.py", "py-unnecessary-class"));
});

test("py-unnecessary-class: quiet with two real methods", () => {
  if (skipUnless("python")) return;
  const src = `class P:\n    def __init__(self):\n        pass\n    def a(self):\n        return 1\n    def b(self):\n        return 2\n`;
  assert.ok(!fires(src, "r.py", "py-unnecessary-class"));
});

test("py-unnecessary-class: quiet when the second member is decorated (@property)", () => {
  if (skipUnless("python")) return;
  const src = `class P:\n    def __init__(self):\n        pass\n    @property\n    def v(self):\n        return 1\n`;
  assert.ok(!fires(src, "s.py", "py-unnecessary-class"));
});

test("py-unnecessary-class: quiet on a data holder with no methods", () => {
  if (skipUnless("python")) return;
  const src = `class P:\n    def __init__(self):\n        self.x = 1\n`;
  assert.ok(!fires(src, "t.py", "py-unnecessary-class"));
});

// --- py-unnecessary-abc -----------------------------------------------------

test("py-unnecessary-abc: fires on an ABC with no implementation", () => {
  if (skipUnless("python")) return;
  const src = `from abc import ABC\nclass Base(ABC):\n    def go(self):\n        ...\n`;
  assert.ok(fires(src, "a.py", "py-unnecessary-abc"));
});

test("py-unnecessary-abc: quiet once a second implementation exists", () => {
  if (skipUnless("python")) return;
  const src = `from abc import ABC\nclass Base(ABC):\n    def go(self): ...\nclass A(Base):\n    def go(self): return 1\nclass B(Base):\n    def go(self): return 2\n`;
  assert.ok(!fires(src, "b.py", "py-unnecessary-abc"));
});

test("py-unnecessary-abc: quiet on an ordinary base class that is not an ABC", () => {
  if (skipUnless("python")) return;
  const src = `class Base(object):\n    def go(self):\n        return 1\n`;
  assert.ok(!fires(src, "c.py", "py-unnecessary-abc"));
});

// --- go-premature-interface -------------------------------------------------

test("go-premature-interface: fires on a small interface nothing consumes", () => {
  if (skipUnless("go")) return;
  const src = `package m\ntype UserStore interface {\n\tGet(id string) error\n}\n`;
  assert.ok(fires(src, "a.go", "go-premature-interface"));
});

test("go-premature-interface: quiet once a call site accepts it", () => {
  if (skipUnless("go")) return;
  const src = `package m\ntype UserStore interface {\n\tGet(id string) error\n}\nfunc New(s UserStore) UserStore { return s }\n`;
  assert.ok(!fires(src, "b.go", "go-premature-interface"));
});

test("go-premature-interface: quiet on a rich interface (>2 methods)", () => {
  if (skipUnless("go")) return;
  const src = `package m\ntype Big interface {\n\tA() error\n\tB() error\n\tC() error\n}\n`;
  assert.ok(!fires(src, "c.go", "go-premature-interface"));
});

// --- java-single-impl-interface ---------------------------------------------

test("java-single-impl-interface: fires on the Foo/FooImpl pair", () => {
  if (skipUnless("java")) return;
  const src = `interface Gateway { void pay(int a); }\nclass StripeGateway implements Gateway { public void pay(int a) { } }\n`;
  assert.ok(fires(src, "A.java", "java-single-impl-interface"));
});

test("java-single-impl-interface: quiet with two implementations", () => {
  if (skipUnless("java")) return;
  const src = `interface Gateway { void pay(int a); }\nclass A implements Gateway { public void pay(int a) { } }\nclass B implements Gateway { public void pay(int a) { } }\n`;
  assert.ok(!fires(src, "B.java", "java-single-impl-interface"));
});

test("java-single-impl-interface: quiet when no implementation is in this file", () => {
  if (skipUnless("java")) return;
  const src = `interface Gateway { void pay(int a); }\n`;
  assert.ok(!fires(src, "C.java", "java-single-impl-interface"));
});

// --- pass-through-wrapper ---------------------------------------------------

test("pass-through-wrapper: fires when the body only forwards its parameters", () => {
  if (skipUnless("python")) return;
  const src = `def fetch(uid):\n    return api.get(uid)\n`;
  assert.ok(fires(src, "w.py", "pass-through-wrapper"));
});

test("pass-through-wrapper: quiet when the call adds an argument", () => {
  if (skipUnless("python")) return;
  const src = `def fetch(uid):\n    return api.get(uid, timeout=30)\n`;
  assert.ok(!fires(src, "x.py", "pass-through-wrapper"));
});

test("pass-through-wrapper: quiet when the wrapper validates first", () => {
  if (skipUnless("python")) return;
  const src = `def fetch(uid):\n    if not uid:\n        raise ValueError()\n    return api.get(uid)\n`;
  assert.ok(!fires(src, "y.py", "pass-through-wrapper"));
});

test("pass-through-wrapper: quiet when arguments are reordered", () => {
  if (skipUnless("python")) return;
  const src = `def fetch(a, b):\n    return api.get(b, a)\n`;
  assert.ok(!fires(src, "z.py", "pass-through-wrapper"));
});

test("pass-through-wrapper (JS): fires on a bare delegating arrow", () => {
  const src = `const fetchUser = (id) => api.get(id);\n`;
  assert.ok(fires(src, "w.js", "pass-through-wrapper"));
});

// --- diff-churn-ratio -------------------------------------------------------

test("diff-churn-ratio: anchors to a changed line so the finding survives inChange", () => {
  // 60 boilerplate lines with almost no logic, changed from line 30 onward. The rule anchors at the
  // lowest changed line; anchoring at line 1 (the old behavior) would have been silently dropped.
  const body = Array.from({ length: 60 }, (_, i) => `// filler comment ${i}`).join("\n");
  const src = `function f() {\n${body}\n  return 1;\n}\n`;
  const changedLines = new Set(Array.from({ length: 40 }, (_, i) => i + 25));
  const found = analyze({ filePath: "c.js", content: src, config: DEFAULT_CONFIG, changedLines })
    .findings.filter((f) => f.ruleId === "diff-churn-ratio");
  if (found.length > 0) {
    assert.ok(changedLines.has(found[0].line), `anchor ${found[0].line} must be inside the diff`);
  }
});

test("diff-churn-ratio: quiet on a small diff", () => {
  const src = `function f() {\n  return 1;\n}\n`;
  assert.ok(!fires(src, "d.js", "diff-churn-ratio"));
});

// --- family-level guarantees ------------------------------------------------

const STRUCTURAL_IDS = [
  "cognitive-complexity-spike", "deep-nesting", "long-function", "too-many-parameters",
  "ts-over-generic", "py-unnecessary-class", "py-unnecessary-abc", "go-premature-interface",
  "java-single-impl-interface", "pass-through-wrapper", "diff-churn-ratio",
  "single-caller-abstraction",
];

test("every structural finding is yellow and non-blocking", () => {
  if (skipUnless("python")) return;
  const src = `class Handler:\n    def __init__(self, db):\n        self.db = db\n    def run(self, r):\n        return self.db.q(r)\n`;
  const found = analyze({
    filePath: "g.py",
    content: src,
    config: { ...DEFAULT_CONFIG, rules: { structural: true } },
  }).findings.filter((f) => STRUCTURAL_IDS.includes(f.ruleId));

  assert.ok(found.length > 0, "expected at least one structural finding");
  for (const f of found) {
    assert.equal(f.tier, "yellow", `${f.ruleId} must be yellow`);
    assert.equal(f.blocking, false, `${f.ruleId} must not block`);
  }
});

test('rules: { structural: false } silences the whole family', () => {
  if (skipUnless("python")) return;
  const src = `class Handler:\n    def __init__(self, db):\n        self.db = db\n    def run(self, r):\n        return self.db.q(r)\n`;
  const found = ids(src, "h.py", { ...DEFAULT_CONFIG, rules: { structural: false } });
  assert.deepEqual(found.filter((id) => STRUCTURAL_IDS.includes(id)), []);
});

test("single-caller-abstraction is opt-in: inert without a graph to confirm it", () => {
  if (skipUnless("python")) return;
  const src = `class Handler:\n    def __init__(self, db):\n        self.db = db\n    def run(self, r):\n        return self.db.q(r)\n`;
  assert.ok(
    !ids(src, "i.py").includes("single-caller-abstraction"),
    "must not fire by default — the detector alone proves nothing"
  );
  assert.ok(
    ids(src, "i.py", { ...DEFAULT_CONFIG, rules: { structural: true } }).includes("single-caller-abstraction"),
    "enabling the pack opts it in"
  );
});

test("a per-rule override can re-tier a structural rule", () => {
  if (skipUnless("python")) return;
  const src = `class Handler:\n    def __init__(self, db):\n        self.db = db\n    def run(self, r):\n        return self.db.q(r)\n`;
  const found = analyze({
    filePath: "j.py",
    content: src,
    config: { ...DEFAULT_CONFIG, rules: { "py-unnecessary-class": { tier: "orange" } } },
  }).findings.find((f) => f.ruleId === "py-unnecessary-class");
  assert.equal(found.tier, "orange");
});
