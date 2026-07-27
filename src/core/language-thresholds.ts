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

/** Per-language thresholds (research §3 table), for the languages this build actually parses —
 *  see `GRAMMAR_PACKAGES` in parsers/treesitter.ts plus JS/TS/JSX/TSX via Babel.
 *
 * Rationale: Python/Go idioms enforce flat flow; brace languages tolerate deeper nesting.
 * Python comprehensions compress logic; Java error handling adds lines without cognitive load.
 * Options-struct pattern is idiomatic in Go at 4+ params; Java constructors accept more.
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
    // No maxClassLines: Go has no classes (GO_PROFILE.classTypes is empty in complexity.ts), so a
    // class-line threshold here can never be evaluated against anything.
    maxCognitiveComplexity: 10,
    maxNestingDepth: 3,
    maxFunctionLines: 35,
    maxParameters: 4,
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
};

/** Resolve thresholds for a language from config.
 *
 * Merge order: DEFAULT_THRESHOLDS ← LANGUAGE_THRESHOLDS[lang] ← cfg.languageOverrides._default ← cfg.languageOverrides[lang].
 * Most specific wins.
 */
/** csharp/c# is the one built-in pair with two spellings; LANGUAGE_THRESHOLDS ships both, so a
 *  user's own `languageOverrides` key should resolve the same way regardless of which they typed. */
const LANGUAGE_ALIASES: Record<string, string> = { "c#": "csharp" };

export function resolveThresholds(language: string, config: Partial<Config> | undefined | null): ComplexityThresholds {
  const lang = LANGUAGE_ALIASES[language.toLowerCase()] ?? language.toLowerCase();
  const resolved = { ...DEFAULT_THRESHOLDS };

  // Apply language-specific built-in defaults
  if (LANGUAGE_THRESHOLDS[lang]) {
    Object.assign(resolved, LANGUAGE_THRESHOLDS[lang]);
  }

  // Apply user config: _default overrides
  if (config?.languageOverrides?._default) {
    Object.assign(resolved, config.languageOverrides._default);
  }

  // Apply user config: language-specific overrides (most specific wins). Config keys are matched
  // case-insensitively and through the same alias table as the built-in defaults, so `"Python"` or
  // `"C#"` in a user's .diffgate.json behaves the same as the lowercase/canonical spelling.
  const overrides = config?.languageOverrides;
  if (overrides) {
    for (const key of Object.keys(overrides)) {
      if (key === "_default") continue;
      const normalizedKey = LANGUAGE_ALIASES[key.toLowerCase()] ?? key.toLowerCase();
      if (normalizedKey === lang) Object.assign(resolved, overrides[key]);
    }
  }

  return resolved;
}
