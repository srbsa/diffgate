// Test-context de-escalation.
//
// Security findings in test, fixture, and mock files are almost always intentional scaffolding —
// mock SQL, `eval` in a harness, fake request payloads, sample tokens. Blocking the gate on them is
// the fastest way to teach a team to ignore the tool (research: test-file findings are "almost
// always a false positive"). So in a test file an orange finding routes attention instead of
// blocking: we DOWN-tier orange → yellow and clear `blocking`, with a visible reason. We never
// SUPPRESS — the finding still shows, just as a review note.
//
// Exemptions — kept at full tier even in tests, because a real one is catastrophic regardless of
// where it lives:
//   - `hardcoded-secret`: a committed real key is leaked whether or not the file is a test (and
//     `classifySecret` has already dropped fake/placeholder/low-entropy values before this point).
//   - `db-schema-destructive`: a `DROP`/`TRUNCATE` can hit a real database if a test is misconfigured.
//
// Opt out per-rule by pinning its tier (`rules: { "sql-injection": { "tier": "orange" } }`) or
// globally with `testScope: false`.

import type { Config, Finding } from "./types.js";
import { IMPACT_RULES } from "./impact.js";

// Never down-tier these in tests: catastrophic-if-real classes (secret/destructive schema), plus the
// public-surface rules whose tier is owned by the cross-file graph (a test helper with real callers
// should still escalate — that's the graph's call, not ours).
const EXEMPT = new Set(["hardcoded-secret", "db-schema-destructive", ...IMPACT_RULES]);

// A path segment that marks a test/fixture tree (any language convention).
const TEST_DIR = /(?:^|\/)(?:tests?|__tests__|__mocks__|specs?|fixtures?|testdata|e2e|mocks?)(?:\/)/i;
// A filename that marks a test/spec file: foo.test.ts, foo.spec.js, foo_test.go, test_foo.py, FooTest.java
const TEST_FILE = /(?:[._-](?:test|spec)\.[a-z0-9]+|_(?:test|spec)\.[a-z0-9]+|^test_[^/]*\.[a-z0-9]+|Tests?\.(?:java|kt|cs|scala|swift))$/i;

/** Whether a file is a test / fixture / mock file by path or filename convention. */
export function isTestPath(filePath: string): boolean {
  const norm = filePath.replace(/\\/g, "/");
  if (TEST_DIR.test("/" + norm)) return true;
  const base = norm.split("/").pop() || norm;
  return base === "conftest.py" || TEST_FILE.test(base);
}

function tierPinned(config: Partial<Config>, ruleId: string): boolean {
  const ov = config.rules?.[ruleId];
  return !!(ov && typeof ov === "object" && (ov.tier !== undefined || ov.blocking !== undefined));
}

/**
 * Down-tier non-exempt orange findings in test files (orange → yellow, blocking cleared). No-op when
 * `testScope` is false, the file is not a test file, or a rule's tier is pinned. Returns a new array.
 */
export function applyTestScope(findings: Finding[], filePath: string, config: Partial<Config>): Finding[] {
  if (config.testScope === false) return findings;
  if (!isTestPath(filePath)) return findings;
  return findings.map((f) => {
    if (f.tier !== "orange") return f;
    if (EXEMPT.has(f.ruleId)) return f;
    if (tierPinned(config, f.ruleId)) return f;
    return {
      ...f,
      tier: "yellow",
      blocking: false,
      tierAdjusted: "deescalated",
      message:
        `${f.message}\n\n🧪 In a test/fixture file — down-tiered to review (test code is lower-stakes). ` +
        `Pin the rule's tier or set \`testScope: false\` to keep it blocking.`,
    };
  });
}
