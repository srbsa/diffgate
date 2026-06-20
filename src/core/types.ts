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
  /** Pre-edit context (callers/tests/history) for a high-blast finding — MCP analyze only. */
  editContext?: EditContext | null;
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

export interface AnalyzeResult {
  filePath: string;
  language: string;
  findings: Finding[];
  tier: Tier;
  counts: TierCounts;
  blocking: boolean;
  parseError?: string | null;
}

export interface GateConfig {
  failOn: Tier;
  mode: "staged" | "working";
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
}

export interface Config {
  gate: GateConfig;
  ai: AiConfig;
  testCommand?: string | null;
  ignore?: string[];
  rules?: Record<string, false | { enabled?: boolean; tier?: Tier; blocking?: boolean }>;
  customPatterns?: CustomPattern[];
  deprecated?: DeprecatedEntry[];
  orangePatterns?: string[];
  guidelines?: GuidelinesConfig;
  graph?: GraphConfig;
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

export interface RuleContext {
  filePath: string;
  language: string;
  lines: string[];
  changedLines: Set<number> | null;
  config: Config;
  ast?: AstNode | null;
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
  /** Symbol name this finding concerns, for cross-file blast-radius lookup. */
  symbol?: string | null;
  loc?: {
    start: { line: number; column: number };
    end?: { line: number; column: number };
  };
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
}

export interface PatternRule extends RuleBase {
  type: "pattern";
  patterns: RegExp[];
}

export interface AstRule extends RuleBase {
  type: "ast";
  visit: (node: AstNode, parent: AstNode | null, ctx: RuleContext, emit: EmitFn) => void;
}

export interface FileRule extends RuleBase {
  type: "file";
  detect: (ctx: RuleContext, emit: EmitFn) => void;
}

export type Rule = PatternRule | AstRule | FileRule;

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
  temperature?: number;
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
