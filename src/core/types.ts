// Shared type definitions for the guardrail engine.

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
  extraHeaders?: Record<string, string>;
}

export interface DeprecatedEntry {
  pattern: string;
  replacedBy: string;
  author?: string;
  pr?: string;
  tier?: Tier;
}

export interface Config {
  gate: GateConfig;
  ai: AiConfig;
  testCommand?: string | null;
  ignore?: string[];
  rules?: Record<string, false | { enabled?: boolean; tier?: Tier; blocking?: boolean }>;
  customPatterns?: unknown[];
  deprecated?: DeprecatedEntry[];
  orangePatterns?: string[];
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
  steps: number;
  transcript: TranscriptEntry[];
  model: string;
  hitMax: boolean;
}
