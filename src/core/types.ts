// Shared type definitions for the DiffGate engine.

export type Tier = "green" | "yellow" | "orange";

export interface TierCounts {
  green: number;
  yellow: number;
  orange: number;
}

export interface Fix {
  title: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  newText: string;
}

export interface Finding {
  ruleId: string;
  tier: Tier;
  blocking: boolean;
  title: string;
  message: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  code: string;
  fix: Fix | null;
  /** The code symbol this finding concerns (used for cross-file blast-radius lookup). */
  symbol?: string | null;
  /** Cross-file blast-radius data, attached post-analysis when a code graph is available. */
  impact?: ImpactInfo | null;
  /** Set when a tier was raised/lowered from the rule default by the impact pass. */
  tierAdjusted?: "escalated" | "deescalated" | null;
  /** Graph-aware security verdict for injection-class findings (Pro security graph only). */
  security?: SecurityVerdict | null;
  /** Community-graph reachability verdict: is this sink reachable from an untrusted entry point? */
  reachability?: ReachabilityVerdict | null;
  /** Pre-edit context (callers/tests/history) for a high-blast finding — MCP analyze only. */
  editContext?: EditContext | null;
  /**
   * Deterministic confidence label for the agent autonomy ladder, set by a graph-independent pass:
   *  - "confirmed"   a high-trust deterministic signal backs the risk (a graph taint path, or a
   *                  non-security deterministic pattern/AST rule).
   *  - "cleared"     a high-trust signal disproved it (the graph found no taint path to the sink).
   *  - "unconfirmed" no deterministic signal could confirm/deny it (an injection-class pattern with
   *                  no code graph, or an LLM-derived guideline finding). Treat as advisory.
   *  - "reachable"   the community code graph proved a path from an untrusted entry point (an HTTP/
   *                  event handler) to this sink. Strongest non-AST confirmation; block-worthy.
   *  - "unreachable" the community code graph found no path from an untrusted entry point to this
   *                  sink. Advisory only — coverage depends on the index, so verify before dismissing.
   */
  trust?: "confirmed" | "unconfirmed" | "cleared" | "reachable" | "unreachable" | null;
  /** Metadata attached by a rule for consumption by an attach-pass; never rendered to users. */
  meta?: Record<string, unknown>;
}

/** A single location in the codebase (a call site, a missing-test target, etc.). */
export interface ImpactRef {
  file?: string;
  line?: number;
  symbol?: string;
}

/** Cross-file blast radius for a changed symbol, sourced from a code graph (or a grep fallback). */
export interface ImpactInfo {
  symbol: string;
  /** Number of distinct call sites that depend on the changed symbol. */
  callerCount: number;
  /** A capped sample of those call sites. */
  callers: ImpactRef[];
  /** Whether the symbol is reachable from an entry point / user input. null = the graph did not say. */
  reachable: boolean | null;
  /** Changed/affected symbols with no covering test. */
  testGaps: ImpactRef[];
  /** Suggested reviewers (owners of the top callers), most-relevant first. */
  reviewers: string[];
  /** Where this impact came from: "codegraph", "grep", etc. */
  source: string;
  /** True if callers/testGaps were truncated to the cap. */
  truncated?: boolean;
  /** Cyclomatic complexity of the changed symbol, when the graph reports it. */
  complexity?: number | null;
  /** True when the symbol's documentation looks stale relative to its current signature. */
  staleDoc?: boolean | null;
  /** Call sites in OTHER indexed repos that depend on this symbol — a change here can break a
   *  consumer the diff doesn't touch. High-signal: present only when the graph indexes >1 project. */
  crossProject?: ImpactRef[];
  /** Count of impacted sites the graph marks as breaking (analyze_impact `breaking_changes`),
   *  distinct from total callers — populated on a rename/delete-style change. */
  breakingCount?: number | null;
  /** True when the graph matched callers by bare name only and more than one definition in the
   *  codebase shares that name — the caller count may be conflated across unrelated symbols, so
   *  it must not drive tier escalation/de-escalation (enrich-only). */
  ambiguous?: boolean;
}

/** A symbol whose documentation/spec drifted from the code, surfaced by pr_context. */
export interface StaleDoc {
  symbol?: string;
  file?: string;
  note?: string;
}

/** Whole-diff context from a single pr_context call: per-symbol impact + repo-level signals. */
export interface PrContextInfo {
  /** Impact keyed by symbol name (exact), used to enrich findings without a per-finding call. */
  bySymbol: Record<string, ImpactInfo>;
  /** Symbols whose docs drifted from the code. */
  staleDocs: StaleDoc[];
  /** A suggested commit-message subject line, when the graph offers one. */
  commitHint?: string | null;
  source: string;
}

/** Pre-edit context for a symbol: who calls it, what tests cover it, recent history. */
export interface EditContext {
  callers: ImpactRef[];
  tests: ImpactRef[];
  /** Recent change history (authors / commits touching the symbol), newest first. */
  history: string[];
  source: string;
}

/** Graph-aware taint verdict for an injection-class finding. */
export interface SecurityVerdict {
  /** true = user input reaches the sink; false = no taint path; null = the graph was unsure. */
  tainted: boolean | null;
  /** The taint path (source → … → sink), when the graph traced one. */
  dataFlow: ImpactRef[];
  /** Which detector produced this (e.g. "detect_injection", "trace_data_flow"). */
  detector?: string;
  source: string;
}

/** An untrusted entry point (an HTTP/event handler) the reachability pass treats as a taint source. */
export interface ReachabilityEntryPoint {
  /** Handler/function name (e.g. "user_route"). */
  name: string;
  /** Entry-point kind as classified by the graph (e.g. "http_handler", "event_handler"). */
  kind: string;
  /** Route path, when the framework exposes one (e.g. "/user/:id"). */
  route?: string;
  /** HTTP method, when known (e.g. "GET"). */
  method?: string;
  /** File declaring the handler. */
  file?: string;
}

/**
 * Community-edition reachability verdict for an injection-class finding. Answers the precision
 * question without the Pro taint engine: is this sink reachable, through the call graph, from an
 * untrusted entry point? The verdict object is only present when the graph could answer — a null
 * return from the provider means "unknown" and leaves the finding untouched (fail-safe).
 */
export interface ReachabilityVerdict {
  /** true = a call path from an untrusted entry point reaches the sink; false = none found in the graph. */
  reachable: boolean;
  /** Always "codegraph" today. */
  source: string;
  /** The untrusted entry point(s) from which the sink is reachable (empty when reachable=false). */
  entryPoints: ReachabilityEntryPoint[];
  /** Best-effort sink → … → entry-point hops, when the graph exposes an ordered path. */
  path?: ImpactRef[];
  /** Hops from the sink to the nearest entry point (0 = the sink's function is itself the handler). */
  depth?: number;
}

export interface AnalyzeResult {
  filePath: string;
  language: string;
  findings: Finding[];
  tier: Tier;
  counts: TierCounts;
  blocking: boolean;
  parseError?: string | null;
}

/** One commit's metadata, used by the history-scan (`check --since/--author/<commit>`). */
export interface Commit {
  sha: string;
  shortSha: string;
  author: string;
  email: string;
  /** ISO 8601 author date. */
  date: string;
  subject: string;
  /** Names/emails from `Co-authored-by:` trailers — where most agent attribution lives. */
  coAuthors: string[];
}

/** Result of reviewing a single historical commit's diff. */
export interface CommitReview {
  commit: Commit;
  files: AnalyzeResult[];
  tier: Tier;
  counts: TierCounts;
  blocking: boolean;
}

/** Selection criteria for which commits a history scan should review. */
export interface HistorySelection {
  /** Single commit-ish (e.g. a sha). Takes precedence over range/since. */
  commit?: string;
  /** Explicit `A..B` range. */
  range?: string;
  /** A rev (→ `<since>..HEAD`) or a git date expression (e.g. "2 weeks ago"). */
  since?: string;
  /** Case-insensitive pattern matched against author name/email and co-author trailers. */
  author?: string;
  /** Preset filter for common AI-agent authorship signatures. */
  ai?: boolean;
  /** Cap on commits reviewed (default 50). */
  limit?: number;
}

export interface GateConfig {
  failOn: Tier;
  mode: "staged" | "working";
  /** How an agent consumer (MCP / `check --agent`) is gated. See AgentConfig. */
  agent?: AgentConfig;
}

/**
 * Autonomy policy for an agent consumer. The aim is graded advice with a budget — not a hard block
 * on every finding — so agents self-correct without infinite fix-loops or needless human interrupts.
 */
export interface AgentConfig {
  /**
   * - "advisory" (default): only `blocking` findings (the hard rules) and graph-confirmed taint
   *   actually block; everything else is surfaced as "review" and never fails the agent gate.
   * - "gated": legacy — anything at/above the gate tier blocks (orange blocks).
   * - "off": never blocks; pure advisory data, the agent owns every decision.
   */
  mode?: "advisory" | "gated" | "off";
  /** Findings at/above this tier are the agent's auto-fix rung; below it they are informational. Default "orange". */
  autoFixFloor?: Tier;
  /** Loop budget: max DiffGate fixes an agent should apply in one turn before pausing. Default 3. */
  maxFixesPerTurn?: number;
  /** Escalate to a human when the same finding survives this many agent turns. Default 2. */
  escalateAfterTurns?: number;
  /** Source of truth for the gate decision. "deterministic" (default) keeps LLM output (explain)
   *  out of the gate — only graph/AST/pattern signals can move a rung. "any" lets all signals count. */
  trustSource?: "deterministic" | "any";
}

export interface AiDeepReviewConfig {
  model?: string;
  maxSteps?: number;
}

export interface AiConfig {
  enabled: boolean;
  provider?: string;
  model?: string | Record<string, string>;
  apiKeyEnv?: string | null;
  baseURL?: string | null;
  maxTokens?: number;
  temperature?: number;
  tokenParam?: string;
  deepReview?: AiDeepReviewConfig;
  wire?: "anthropic" | "openai";
  local?: boolean;
  /** Disable model "thinking" for quick tasks (explain). Defaults to true for local providers, off for hosted APIs that reject non-standard params. */
  noThink?: boolean;
  extraHeaders?: Record<string, string>;
}

export interface DeprecatedEntry {
  pattern: string;
  replacedBy: string;
  author?: string;
  pr?: string;
  tier?: Tier;
}

export interface CustomPattern {
  id?: string;
  pattern?: string | RegExp;
  patterns?: (string | RegExp)[];
  flags?: string;
  tier?: Tier;
  blocking?: boolean;
  title?: string;
  languages?: string[];
  message?: string;
  /** Only run on files whose repo-relative path matches one of these globs (same syntax as
   *  `ignore`). Empty or missing = all files. */
  include?: string[];
  /** Never run on files matching these globs. Wins over `include`. */
  exclude?: string[];
}

export interface GuidelinesConfig {
  /** Ingest natural-language coding guidelines from AGENTS.md/CLAUDE.md/etc. and enforce them at review time. */
  enabled?: boolean;
  /** Auto-detect the standard guideline filenames (AGENTS.md, CLAUDE.md, .cursorrules, ...). Default true. */
  autoDetect?: boolean;
  /** Extra guideline file globs/names beyond the auto-detected set (e.g. "docs/STANDARDS.md"). */
  files?: string[];
  /** Max guideline files merged per changed file (nearest-wins + repo-root kept; middle dropped). Default 3. */
  maxDepth?: number;
  /** Per-file byte budget; oversized files are section-extracted then truncated. Default 8000. */
  maxBytesPerFile?: number;
  /** Tier assigned to guideline findings (severity is capped to this). Default "yellow". */
  tier?: Tier;
  /** Whether guideline findings gate the build. Default false (advisory — they are non-deterministic). */
  blocking?: boolean;
  /** "auto" = host-delegate when no model is configured, else model. "model" forces the configured provider. "host" forces caller delegation. */
  evaluator?: "auto" | "model" | "host";
}

export interface GuidelineRuleSet {
  /** Guideline files that apply, nearest-first. */
  sources: string[];
  /** Extracted, budget-trimmed guideline text. */
  text: string;
  /** Guideline files found but dropped by the depth cap, for transparency. */
  dropped: string[];
}

export interface GraphConfig {
  /** Use a code graph for cross-file blast radius. "auto" (default) = use it when available, silent when not. */
  enabled?: boolean | "auto";
  /** Graph backend. Currently only "codegraph" (github.com/codegraph-ai/CodeGraph). */
  provider?: string;
  /** Binary to invoke for one-shot CLI queries. Default "codegraph-server". */
  command?: string;
  /** How to reach the graph: "cli" one-shot per query (default), or "off" to disable. */
  mode?: "cli" | "off";
  /** Max call sites / test gaps to keep per finding. Default 20. */
  maxCallers?: number;
  /** callerCount at/above this keeps a public-surface finding orange; below it de-escalates. Default 1. */
  escalateThreshold?: number;
  /** Per-query budget in ms before the graph call is abandoned (degrades to no impact). Default 4000. */
  timeoutMs?: number;
  /** Use one pr_context call per review for whole-diff impact (falls back to per-finding analyze_impact). Default true. */
  prContext?: boolean;
  /** Fill test gaps via find_related_tests in the analyze_impact fallback path. Default true. */
  relatedTests?: boolean;
  /** Attach pre-edit context (get_edit_context) to escalated findings in MCP analyze. Default true. */
  editContext?: boolean;
  /** Use the Pro security graph (taint tracing) to enrich injection findings. "auto" (default) = use when present. */
  security?: boolean | "auto";
  /** Allow the security graph to DOWN-tier an injection finding it proves has no taint path. Default false (enrich-only). */
  securityDeescalate?: boolean;
  /** Use community-edition reachability (entry-point → sink call-path) to escalate cross-language
   *  injection findings. "auto" (default) = use when a graph is available. No Pro binary required. */
  reachability?: boolean | "auto";
  /** Allow reachability to DOWN-tier a finding it proves is unreachable. Default false (fail-safe:
   *  never auto-clear, because an incomplete index could hide a real, reachable vulnerability). */
  reachabilityDeescalate?: boolean;
  /** Entry-point kinds treated as untrusted taint sources. Default ["http_handler", "event_handler"]. */
  untrustedEntryKinds?: string[];
  /** Max caller-chain hops to walk from a sink before giving up on reaching an entry point. Default 6. */
  reachabilityMaxDepth?: number;
  /** Per-call budget (ms) for reachability graph queries (entry points + caller walk). Default 4000. */
  reachabilityTimeoutMs?: number;
}

export interface LearningsConfig {
  /** Extra learning stores to merge in (org-wide noise suppression). Each is a repo root,
   *  a `.diffgate` dir, or a direct learnings.json path. Resolved relative to the config file. */
  shared?: string[];
}

/** Optional borrowed-recall layer (docs/DESIGN-recall-and-parity.md): pipe an external scanner's
 *  findings through the gate (diff-scoped, deduped, ADVISORY-only — never blocking). Off by default;
 *  meant for the CI/PR layer, where its latency is invisible, not the millisecond inner loop. */
export interface RecallConfig {
  /** false (default) = off. "ci" = on only when running in CI (`process.env.CI` set). true = always on. */
  enabled?: boolean | "ci";
  /** External engine. Only "semgrep" today. */
  provider?: "semgrep";
  /** Binary name / path. Default "semgrep". Absent on PATH → no-op. */
  command?: string;
  /** Engine ruleset (semgrep `--config`). Default "auto". */
  config?: string;
  /** Per-invocation budget (ms) for the batched scan. Default 60000. */
  timeoutMs?: number;
}

export interface Config {
  /** Org-wide policy packs to inherit from, base-first. Local config wins on conflicts.
   *  Each entry is a path (./team.diffgate.json), or a package name resolved under node_modules. */
  extends?: string | string[];
  gate: GateConfig;
  ai: AiConfig;
  testCommand?: string | null;
  ignore?: string[];
  /** Per-rule (or per-pack) override. `false` turns a rule off; `true` opts a default-off rule in,
   *  the shorthand for `{ enabled: true }`. An object form additionally re-tiers or path-scopes. */
  rules?: Record<string, boolean | { enabled?: boolean; tier?: Tier; blocking?: boolean; include?: string[]; exclude?: string[] }>;
  customPatterns?: CustomPattern[];
  deprecated?: DeprecatedEntry[];
  orangePatterns?: string[];
  guidelines?: GuidelinesConfig;
  graph?: GraphConfig;
  recall?: RecallConfig;
  learnings?: LearningsConfig;
  /** Down-tier non-exempt orange findings in test/fixture files (orange → yellow, non-blocking).
   *  Secrets, destructive schema, and graph-owned public-surface rules stay at full tier. Default true. */
  testScope?: boolean;
  /** Per-language complexity thresholds. Merges with built-in defaults.
   *  Keys: language names (python, go, java, etc.), or "_default" for fallback.
   *  Values: partial ComplexityThresholds (any subset of maxCognitiveComplexity, maxNestingDepth, etc.). */
  languageOverrides?: Record<string, Record<string, number | undefined> | undefined>;
}

// Minimal Babel-compatible AST node type
export interface AstNode {
  type: string;
  loc?: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
  [key: string]: unknown;
}

/**
 * Minimal tree-sitter node surface (a subset of web-tree-sitter's `Node`). Tree-sitter powers
 * AST-precision rules for languages @babel can't parse (Python first). Positions are 0-indexed
 * `row`/`column`; rules add 1 to `row` for our 1-indexed `line`.
 */
export interface TsNode {
  /** Stable unique id within a tree — used to de-duplicate query-captured sink nodes. */
  id: number;
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  childForFieldName(field: string): TsNode | null;
  namedChild(index: number): TsNode | null;
  namedChildCount: number;
  namedChildren: TsNode[];
  descendantsOfType(types: string | string[]): TsNode[];
  parent: TsNode | null;
}

export interface TsTree {
  rootNode: TsNode;
}

/** Minimal surface of a compiled tree-sitter query (web-tree-sitter `Query`). Drives `tsast` rules'
 *  declarative sink discovery — see `sinkQuery` and `compileTsQuery`. */
export interface TsQueryCapture {
  name: string;
  node: TsNode;
}
export interface TsQueryMatch {
  captures: TsQueryCapture[];
}
export interface TsQuery {
  matches(root: TsNode): TsQueryMatch[];
}

export interface RuleContext {
  filePath: string;
  language: string;
  lines: string[];
  /** `lines` with comment regions blanked to spaces (columns preserved). Pattern rules match
   *  against this so commented-out code is not flagged; rules with `scanRaw` use `lines`. */
  scanLines?: string[];
  changedLines: Set<number> | null;
  config: Config;
  ast?: AstNode | null;
  /** Tree-sitter parse of the file, when a matching grammar is loaded (e.g. Python). Drives `tsast`
   *  rules. Absent when the grammar isn't ready — those languages fall back to pattern rules. */
  tsTree?: TsTree | null;
}

export interface FindingEmitArg {
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  code?: string;
  message?: string;
  tier?: Tier;
  fix?: Fix | null;
  /** Override the rule's default blocking flag (e.g. a sanitizer-aware native down-tier). */
  blocking?: boolean;
  /** Set when a tier was raised/lowered from the rule default by a native refinement. */
  tierAdjusted?: "escalated" | "deescalated" | null;
  /** Symbol name this finding concerns, for cross-file blast-radius lookup. */
  symbol?: string | null;
  loc?: {
    start: { line: number; column: number };
    end?: { line: number; column: number };
  };
  /** Metadata a rule attaches for a later attach-pass to consume; never rendered to users. */
  meta?: Record<string, unknown>;
}

export type EmitFn = (partial: FindingEmitArg) => void;

interface RuleBase {
  id: string;
  tier: Tier;
  blocking?: boolean;
  title: string;
  languages?: string[];
  message?: string | ((match: string) => string);
  enabledByDefault?: boolean;
  skipIfAst?: boolean;
  /**
   * Match against the RAW line (comments not masked). For rules where a hit inside a comment is
   * still a real finding — `hardcoded-secret` (a committed secret is leaked even in a comment) and
   * `todo-marker` (markers live in comments by definition). Default false: pattern rules see
   * comment-masked text so commented-out code (`// eval(x)`, `# os.system(...)`) stops being noise.
   *
   * Doubles as the docs opt-in: prose files (.md, .txt, .rst, …) are all-comment, so the engine
   * runs ONLY `scanRaw` rules there — "real even in a comment" and "real even in prose" are the
   * same property (see DOCS_FILE in rules/index.ts).
   */
  scanRaw?: boolean;
  /**
   * Like {@link skipIfAst}, but per-language: skip this broad pattern rule ONLY when the loaded
   * tree-sitter tree is for one of these languages — i.e. a language that has a precise `tsast`
   * replacement for it. Used by `dangerous-exec` (PHP now owns command/code-injection via AST, but
   * Python still relies on the regex for `os.system`/`subprocess`). Extend the list as precise rules
   * land for more languages.
   */
  skipIfAstLangs?: string[];
  /**
   * Opposite of {@link languages}: this rule never applies to these languages, even when
   * `languages` is `["*"]`. Used to carve out a language with its own precise sibling rule under
   * the same id (e.g. `dangerous-exec`'s JS/TS AST rule owns `.exec()` receiver-awareness, so the
   * broad regex here must not double-fire on JS/TS).
   */
  excludeLanguages?: string[];
  /**
   * Per-rule path scoping (set from a CustomPattern or a `rules` override, never on built-in rule
   * definitions). Globs use the `ignore` syntax and match the repo-relative path; `exclude` wins
   * over `include`, and an empty/missing `include` means all files. Enforced in `runRules` via
   * `matchesPathScope` so every surface (CLI diff, MCP, editor live path) behaves identically.
   */
  include?: string[];
  exclude?: string[];
  /**
   * Set only on the effective rule built from a `rules` override (never on a built-in rule
   * definition) when the user explicitly pinned `tier` and/or `blocking` in config. `makeFinding`
   * checks this so a rule's own dynamic per-finding tier adjustment (e.g. `emitMaybeSanitized`
   * down-tiering a taint finding it found a recognized sanitizer for) can't silently override an
   * explicit user policy — the override is what the user asked for; a rule's own heuristic for one
   * specific finding should not be able to un-ask it.
   */
  tierPinned?: boolean;
}

export interface PatternRule extends RuleBase {
  type: "pattern";
  patterns: RegExp[];
  /**
   * Optional post-match refinement: inspect the matched text to drop false positives (`skip`),
   * re-tier, or attach a confidence note. Runs per match in the engine. Used by `hardcoded-secret`
   * for entropy/placeholder precision.
   */
  validate?: (matchText: string) => { skip?: boolean; tier?: Tier; note?: string } | null | void;
}

export interface AstRule extends RuleBase {
  type: "ast";
  visit: (node: AstNode, parent: AstNode | null, ctx: RuleContext, emit: EmitFn) => void;
}

/** Like {@link AstRule}, but visits a tree-sitter tree (`ctx.tsTree`) instead of the @babel AST.
 *  Used for languages @babel can't parse — Python first. The engine walks every named node. */
export interface TsAstRule extends RuleBase {
  type: "tsast";
  /**
   * Optional declarative sink discovery: an S-expression tree-sitter query capturing candidate
   * sink-site nodes (e.g. `(call) @sink`). When present, the engine runs the query ONCE and invokes
   * `visit` only on captured nodes instead of walking every named node — `visit` keeps its own
   * precise check, so the query is a structural pre-filter, never the precision boundary. Falls back
   * to the full walk if the query is absent or fails to compile (graceful, like the regex fallback).
   */
  sinkQuery?: string;
  visit: (node: TsNode, ctx: RuleContext, emit: EmitFn) => void;
}

export interface FileRule extends RuleBase {
  type: "file";
  detect: (ctx: RuleContext, emit: EmitFn) => void;
}

export type Rule = PatternRule | AstRule | TsAstRule | FileRule;

export interface ProviderPreset {
  wire: "anthropic" | "openai";
  baseURL: string | null;
  apiKeyEnv: string | null;
  defaultModel: string | null;
  local: boolean;
  extraHeaders?: Record<string, string>;
}

export interface ResolvedProvider {
  id: string;
  wire: "anthropic" | "openai";
  baseURL: string | null;
  apiKeyEnv: string | null;
  local: boolean;
  extraHeaders: Record<string, string>;
  presetModel: string | null;
}

export type FetchFn = (url: string | URL, init?: RequestInit) => Promise<Response>;

export interface CompleteOptions {
  baseURL: string | null;
  apiKey: string | null;
  model: string;
  system?: string;
  prompt: string;
  maxTokens?: number;
  temperature?: number | null;
  tokenParam?: string;
  extraHeaders?: Record<string, string>;
  noThink?: boolean;
  signal?: AbortSignal;
  fetchImpl?: FetchFn;
}

export interface CompleteResult {
  text: string;
  model: string;
  usage?: unknown;
}

export interface ToolCallStep {
  type: "tool";
  name: string;
  input: Record<string, unknown>;
}

export interface TranscriptEntry {
  name: string;
  input: Record<string, unknown>;
  output: string;
}

export interface DeepReviewResult {
  verdict: string;
  verdictClass: "confirmed-risk" | "likely-safe" | "needs-human";
  steps: number;
  transcript: TranscriptEntry[];
  model: string;
  hitMax: boolean;
}
