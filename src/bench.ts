// Noise benchmark: run the deterministic engine over a labeled corpus and report
// precision / recall / F1 per rule, plus the headline metric — false positives per
// clean change. This is the artifact behind the "lowest-noise reviewer" claim; the
// methodology lives in BENCHMARK.md and the corpus is versioned here so results are
// reproducible offline (no network, no model).
import type { AnalyzeResult, Config } from "./core/types.js";

export interface BenchCase {
  name: string;
  language: string;
  content: string;
  /** Rule ids that SHOULD fire. Empty = a clean change that must produce no findings. */
  expected: string[];
}

export type AnalyzeFn = (args: { filePath: string; content: string; config: Config }) => AnalyzeResult;

export interface RuleScore {
  rule: string;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface BenchResult {
  cases: number;
  positives: number;
  cleanCases: number;
  rules: RuleScore[];
  overall: { tp: number; fp: number; fn: number; precision: number; recall: number; f1: number };
  /** Headline trust metric: orange (gating) findings on clean changes / clean case. Should be 0 —
   *  the gate must never falsely block a safe change. */
  falseBlocksPerCleanCase: number;
  /** Yellow/green advisories on clean changes / clean case. These are by-design (informational),
   *  surfaced separately so the noise number isn't conflated with the blocking number. */
  advisoriesPerCleanCase: number;
}

const ext: Record<string, string> = { javascript: "js", typescript: "ts", python: "py", go: "go", java: "java", ruby: "rb", sql: "sql" };

export const CORPUS: BenchCase[] = [
  // --- positives: the rule SHOULD fire ---
  { name: "sql-injection/template", language: "javascript", expected: ["sql-injection", "raw-query"],
    content: "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n" },
  { name: "sql-injection/concat", language: "javascript", expected: ["sql-injection", "raw-query"],
    content: 'const sql = "SELECT * FROM users WHERE id = " + req.query.id;\ndb.query(sql);\n' },
  { name: "xss/innerHTML-untrusted", language: "javascript", expected: ["xss-sink"],
    content: 'el.innerHTML = "<b>Hi " + req.query.name + "</b>";\n' },
  { name: "path-traversal/req-join", language: "javascript", expected: ["path-traversal"],
    content: "const p = path.join(__dirname, req.query.filename);\nfs.readFile(p, 'utf8', cb);\n" },
  { name: "secret/aws", language: "javascript", expected: ["hardcoded-secret"],
    content: 'const key = "AKIAIOSFODNN7EXAMPLE";\nconst secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";\n' },
  { name: "dangerous-exec/eval", language: "javascript", expected: ["dangerous-exec"],
    content: "function run(s) { return eval(s); }\n" },
  { name: "prototype-pollution/assign-body", language: "javascript", expected: ["prototype-pollution"],
    content: "Object.assign(target, req.body);\n" },
  { name: "nosql-injection/find-body", language: "javascript", expected: ["nosql-injection"],
    content: "User.find(req.body);\n" },
  { name: "cors/wildcard", language: "javascript", expected: ["permissive-cors"],
    content: "app.use(cors({ origin: '*' }));\n" },
  { name: "schema-destructive/drop", language: "sql", expected: ["db-schema-destructive"],
    content: "DROP TABLE users;\n" },
  { name: "schema-destructive/delete-no-where", language: "sql", expected: ["db-schema-destructive"],
    content: "DELETE FROM sessions;\n" },
  { name: "auth-crypto/jwt", language: "javascript", expected: ["auth-crypto"],
    content: "const token = jwt.sign({ uid }, process.env.JWT_SECRET);\n" },

  // --- negatives: clean changes that must produce NO findings (the noise test) ---
  { name: "clean/parameterized-sql", language: "javascript", expected: [],
    content: 'const sql = "SELECT * FROM users WHERE id = ?";\ndb.query(sql, [req.query.id]);\n' },
  { name: "clean/static-innerHTML", language: "javascript", expected: [],
    content: 'el.innerHTML = "<b>Hello</b>";\n' },
  { name: "clean/path-resolve-static", language: "javascript", expected: [],
    content: "const p = path.resolve(__dirname, 'static.txt');\nfs.readFile(p, 'utf8', cb);\n" },
  { name: "clean/env-reference", language: "javascript", expected: [],
    content: "const region = process.env.AWS_REGION || 'us-east-1';\n" },
  { name: "clean/pure-helper", language: "javascript", expected: [],
    content: "function add(a, b) {\n  return a + b;\n}\n" },
  { name: "clean/typed-fetch", language: "javascript", expected: [],
    content: "async function load(id) {\n  const r = await fetch(`/api/items/${id}`);\n  return r.json();\n}\n" },
  { name: "clean/select-where", language: "sql", expected: [],
    content: "SELECT id, name FROM users WHERE active = true;\n" },
  { name: "clean/comment-only", language: "javascript", expected: [],
    content: "// refactor: extract the validation step into its own function\nreturn validate(input);\n" },
];

function emptyConfig(): Config {
  return { rules: {}, customPatterns: [], deprecated: [] } as unknown as Config;
}

export function runBench(analyzeFn: AnalyzeFn, corpus: BenchCase[] = CORPUS): BenchResult {
  const perRule = new Map<string, { tp: number; fp: number; fn: number }>();
  const bump = (rule: string, k: "tp" | "fp" | "fn") => {
    const r = perRule.get(rule) || { tp: 0, fp: 0, fn: 0 };
    r[k] += 1;
    perRule.set(rule, r);
  };

  let cleanCases = 0;
  let blocksOnClean = 0;
  let advisoriesOnClean = 0;

  for (const cse of corpus) {
    const res = analyzeFn({ filePath: `bench.${ext[cse.language] || "txt"}`, content: cse.content, config: emptyConfig() });
    const found = new Set(res.findings.map((f) => f.ruleId));
    const expected = new Set(cse.expected);

    // Clean cases measure noise (tier-split), not detection accuracy — advisories on safe
    // code are by-design, so they don't count against rule precision.
    if (expected.size === 0) {
      cleanCases += 1;
      for (const f of res.findings) {
        if (f.blocking || f.tier === "orange") blocksOnClean += 1;
        else advisoriesOnClean += 1;
      }
      continue;
    }

    // Positive cases measure detection: recall (did we catch it?) + cross-rule confusion.
    for (const rule of expected) (found.has(rule) ? bump(rule, "tp") : bump(rule, "fn"));
    for (const rule of found) if (!expected.has(rule)) bump(rule, "fp");
  }

  const rules: RuleScore[] = [...perRule.entries()]
    .map(([rule, { tp, fp, fn }]) => ({ rule, tp, fp, fn, ...prf(tp, fp, fn) }))
    .sort((a, b) => a.rule.localeCompare(b.rule));

  const agg = rules.reduce((acc, r) => ({ tp: acc.tp + r.tp, fp: acc.fp + r.fp, fn: acc.fn + r.fn }), { tp: 0, fp: 0, fn: 0 });

  return {
    cases: corpus.length,
    positives: corpus.filter((c) => c.expected.length > 0).length,
    cleanCases,
    rules,
    overall: { ...agg, ...prf(agg.tp, agg.fp, agg.fn) },
    falseBlocksPerCleanCase: cleanCases === 0 ? 0 : round(blocksOnClean / cleanCases),
    advisoriesPerCleanCase: cleanCases === 0 ? 0 : round(advisoriesOnClean / cleanCases),
  };
}

function prf(tp: number, fp: number, fn: number): { precision: number; recall: number; f1: number } {
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision: round(precision), recall: round(recall), f1: round(f1) };
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}
