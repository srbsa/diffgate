/** Per-language complexity thresholds. Follows SonarSource, Clippy, golangci-lint community standards. */

import type { Config } from "./types.js";

export interface ComplexityThresholds {
  maxCognitiveComplexity: number;
  maxNestingDepth: number;
  maxFunctionLines: number;
  maxParameters: number;
  maxClassLines?: number;
  maxDiffChurnRatio?: number;   // raw added lines : net AST statements
}

/** Universal default thresholds (target most languages reasonably). */
export const DEFAULT_THRESHOLDS: ComplexityThresholds = {
  maxCognitiveComplexity: 12,
  maxNestingDepth: 4,
  maxFunctionLines: 40,
  maxParameters: 5,
  maxClassLines: 250,
  maxDiffChurnRatio: 15,
};

/** Per-language thresholds (research §3 table).
 *
 * Rationale: Python/Go idioms enforce flat flow; brace languages tolerate deeper nesting.
 * Python comprehensions compress logic; Java/Rust error handling adds lines without cognitive load.
 * Options-struct pattern is idiomatic in Go/Rust at 4+ params; Java constructors accept more.
 */
export const LANGUAGE_THRESHOLDS: Record<string, Partial<ComplexityThresholds>> = {
  python: {
    maxCognitiveComplexity: 10,
    maxNestingDepth: 3,
    maxFunctionLines: 25,
    maxParameters: 4,
    maxClassLines: 200,
  },
  go: {
    maxCognitiveComplexity: 10,
    maxNestingDepth: 3,
    maxFunctionLines: 35,
    maxParameters: 4,
    maxClassLines: 400,
  },
  typescript: {
    maxCognitiveComplexity: 12,
    maxNestingDepth: 4,
    maxFunctionLines: 35,
    maxParameters: 4,
    maxClassLines: 250,
  },
  tsx: {
    maxCognitiveComplexity: 12,
    maxNestingDepth: 4,
    maxFunctionLines: 35,
    maxParameters: 4,
    maxClassLines: 250,
  },
  javascript: {
    maxCognitiveComplexity: 12,
    maxNestingDepth: 4,
    maxFunctionLines: 35,
    maxParameters: 4,
    maxClassLines: 250,
  },
  jsx: {
    maxCognitiveComplexity: 12,
    maxNestingDepth: 4,
    maxFunctionLines: 35,
    maxParameters: 4,
    maxClassLines: 250,
  },
  java: {
    maxCognitiveComplexity: 15,
    maxNestingDepth: 4,
    maxFunctionLines: 50,
    maxParameters: 5,
    maxClassLines: 400,
  },
  kotlin: {
    maxCognitiveComplexity: 15,
    maxNestingDepth: 4,
    maxFunctionLines: 50,
    maxParameters: 5,
    maxClassLines: 400,
  },
  csharp: {
    maxCognitiveComplexity: 15,
    maxNestingDepth: 4,
    maxFunctionLines: 50,
    maxParameters: 5,
    maxClassLines: 400,
  },
  "c#": {
    maxCognitiveComplexity: 15,
    maxNestingDepth: 4,
    maxFunctionLines: 50,
    maxParameters: 5,
    maxClassLines: 400,
  },
  rust: {
    maxCognitiveComplexity: 15,
    maxNestingDepth: 4,
    maxFunctionLines: 50,
    maxParameters: 5,
    maxClassLines: 400,
  },
  ruby: {
    maxCognitiveComplexity: 12,
    maxNestingDepth: 4,
    maxFunctionLines: 35,
    maxParameters: 4,
    maxClassLines: 250,
  },
  php: {
    maxCognitiveComplexity: 12,
    maxNestingDepth: 4,
    maxFunctionLines: 40,
    maxParameters: 5,
    maxClassLines: 300,
  },
  cpp: {
    maxCognitiveComplexity: 20,
    maxNestingDepth: 5,
    maxFunctionLines: 60,
    maxParameters: 6,
    maxClassLines: 600,
  },
  "c++": {
    maxCognitiveComplexity: 20,
    maxNestingDepth: 5,
    maxFunctionLines: 60,
    maxParameters: 6,
    maxClassLines: 600,
  },
};

/** Resolve thresholds for a language from config.
 *
 * Merge order: DEFAULT_THRESHOLDS ← LANGUAGE_THRESHOLDS[lang] ← cfg.languageOverrides._default ← cfg.languageOverrides[lang].
 * Most specific wins.
 */
export function resolveThresholds(language: string, config: Partial<Config>): ComplexityThresholds {
  const lang = language.toLowerCase();
  const resolved = { ...DEFAULT_THRESHOLDS };

  // Apply language-specific built-in defaults
  if (LANGUAGE_THRESHOLDS[lang]) {
    Object.assign(resolved, LANGUAGE_THRESHOLDS[lang]);
  }

  // Apply user config: _default overrides
  if (config.languageOverrides?._default) {
    Object.assign(resolved, config.languageOverrides._default);
  }

  // Apply user config: language-specific overrides (most specific wins)
  if (config.languageOverrides?.[lang]) {
    Object.assign(resolved, config.languageOverrides[lang]);
  }

  return resolved;
}
