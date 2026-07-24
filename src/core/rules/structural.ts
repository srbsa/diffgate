/** Structural complexity rules for LLM-written code (Phase 1: Universal rules).
 *
 * These rules detect patterns that indicate unnecessary complexity or abstraction bloat:
 * cognitive complexity spikes, deep nesting, long functions, and too many parameters.
 *
 * All rules ship as 🟡 review-only (non-blocking) to protect the 0-false-block brand.
 * They are language-differentiated via languageOverrides config.
 */

import type { TsAstRule, AstRule, TsNode, AstNode } from "../types.js";
import { resolveThresholds } from "../language-thresholds.js";
import { analyzeComplexity, profileFor } from "../complexity.js";


// ===== Universal Complexity Rules (both TsAst and Ast variants) =====

/**  cognitive-complexity-spike: Flag functions exceeding language-specific cognitive complexity threshold. */
export const CognitiveComplexityTsAst: TsAstRule = {
  id: "cognitive-complexity-spike",
  type: "tsast",
  title: "Function cognitive complexity exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["python", "go", "java", "kotlin", "ruby", "php", "csharp"],
  message: (fnName: string) => `⚡ Function has high cognitive complexity. Simplify control flow.`,
  visit: (node: TsNode, ctx: any, emit: any) => {
    // Only visit function/method definition nodes
    const profile = profileFor(ctx.language);
    if (!profile || !profile.functionTypes.has(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if (node.startPosition?.row === fn.startLine - 1 && fn.metrics.cognitive > thresholds.maxCognitiveComplexity) {
        emit({
          loc: { start: { line: fn.startLine, column: 0 }, end: { line: fn.startLine, column: 10 } },
          message: `⚡ Function ${fn.name || "anonymous"} has cognitive complexity ${fn.metrics.cognitive} (threshold: ${thresholds.maxCognitiveComplexity}). Simplify control flow.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

export const CognitiveComplexityAst: AstRule = {
  id: "cognitive-complexity-spike",
  type: "ast",
  title: "Function cognitive complexity exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["javascript", "typescript", "jsx", "tsx"],
  message: (fnName: string) => `⚡ Function has high cognitive complexity. Simplify control flow.`,
  visit: (node: AstNode, _parent: AstNode | null, ctx: any, emit: any) => {
    // Only visit function declaration nodes
    if (!["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if ((node.loc?.start?.line) === fn.startLine && fn.metrics.cognitive > thresholds.maxCognitiveComplexity) {
        emit({
          loc: node.loc,
          message: `⚡ Function ${fn.name || "anonymous"} has cognitive complexity ${fn.metrics.cognitive} (threshold: ${thresholds.maxCognitiveComplexity}). Simplify control flow.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

/** deep-nesting: Flag functions/blocks exceeding language-specific nesting depth threshold. */
export const DeepNestingTsAst: TsAstRule = {
  id: "deep-nesting",
  type: "tsast",
  title: "Nesting depth exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["python", "go", "java", "kotlin", "ruby", "php", "csharp"],
  visit: (node: TsNode, ctx: any, emit: any) => {
    const profile = profileFor(ctx.language);
    if (!profile || !profile.functionTypes.has(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if (node.startPosition?.row === fn.startLine - 1 && fn.metrics.nesting > thresholds.maxNestingDepth) {
        emit({
          loc: { start: { line: fn.startLine, column: 0 }, end: { line: fn.startLine, column: 10 } },
          message: `⚡ Function ${fn.name || "anonymous"} has nesting depth ${fn.metrics.nesting} (threshold: ${thresholds.maxNestingDepth}). Flatten nested blocks.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

export const DeepNestingAst: AstRule = {
  id: "deep-nesting",
  type: "ast",
  title: "Nesting depth exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["javascript", "typescript", "jsx", "tsx"],
  visit: (node: AstNode, _parent: AstNode | null, ctx: any, emit: any) => {
    if (!["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if ((node.loc?.start?.line) === fn.startLine && fn.metrics.nesting > thresholds.maxNestingDepth) {
        emit({
          loc: node.loc,
          message: `⚡ Function ${fn.name || "anonymous"} has nesting depth ${fn.metrics.nesting} (threshold: ${thresholds.maxNestingDepth}). Flatten nested blocks.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

/** long-function: Flag functions exceeding language-specific line-count threshold. */
export const LongFunctionTsAst: TsAstRule = {
  id: "long-function",
  type: "tsast",
  title: "Function length exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["python", "go", "java", "kotlin", "ruby", "php", "csharp"],
  visit: (node: TsNode, ctx: any, emit: any) => {
    const profile = profileFor(ctx.language);
    if (!profile || !profile.functionTypes.has(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if (node.startPosition?.row === fn.startLine - 1 && fn.metrics.lines > thresholds.maxFunctionLines) {
        emit({
          loc: { start: { line: fn.startLine, column: 0 }, end: { line: fn.startLine, column: 10 } },
          message: `⚡ Function ${fn.name || "anonymous"} spans ${fn.metrics.lines} lines (threshold: ${thresholds.maxFunctionLines}). Extract sub-functions.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

export const LongFunctionAst: AstRule = {
  id: "long-function",
  type: "ast",
  title: "Function length exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["javascript", "typescript", "jsx", "tsx"],
  visit: (node: AstNode, _parent: AstNode | null, ctx: any, emit: any) => {
    if (!["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if ((node.loc?.start?.line) === fn.startLine && fn.metrics.lines > thresholds.maxFunctionLines) {
        emit({
          loc: node.loc,
          message: `⚡ Function ${fn.name || "anonymous"} spans ${fn.metrics.lines} lines (threshold: ${thresholds.maxFunctionLines}). Extract sub-functions.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

/** too-many-parameters: Flag functions exceeding language-specific parameter threshold. */
export const TooManyParametersTsAst: TsAstRule = {
  id: "too-many-parameters",
  type: "tsast",
  title: "Function parameter count exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["python", "go", "java", "kotlin", "ruby", "php", "csharp"],
  visit: (node: TsNode, ctx: any, emit: any) => {
    const profile = profileFor(ctx.language);
    if (!profile || !profile.functionTypes.has(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if (node.startPosition?.row === fn.startLine - 1 && fn.metrics.params > thresholds.maxParameters) {
        emit({
          loc: { start: { line: fn.startLine, column: 0 }, end: { line: fn.startLine, column: 10 } },
          message: `⚡ Function ${fn.name || "anonymous"} has ${fn.metrics.params} parameters (threshold: ${thresholds.maxParameters}). Use an options object or struct.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

export const TooManyParametersAst: AstRule = {
  id: "too-many-parameters",
  type: "ast",
  title: "Function parameter count exceeds language threshold",
  tier: "yellow",
  blocking: false,
  languages: ["javascript", "typescript", "jsx", "tsx"],
  visit: (node: AstNode, _parent: AstNode | null, ctx: any, emit: any) => {
    if (!["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type)) return;

    const complexities = analyzeComplexity(ctx);
    const thresholds = resolveThresholds(ctx.language, ctx.config);

    for (const fn of complexities) {
      if ((node.loc?.start?.line) === fn.startLine && fn.metrics.params > thresholds.maxParameters) {
        emit({
          loc: node.loc,
          message: `⚡ Function ${fn.name || "anonymous"} has ${fn.metrics.params} parameters (threshold: ${thresholds.maxParameters}). Use an options object or struct.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

// ===== Phase 2: Language-Specific Anti-Patterns =====

/** ts-over-generic: TypeScript/Babel rule for deeply nested generic types. */
export const TsOverGenericAst: AstRule = {
  id: "ts-over-generic",
  type: "ast",
  title: "Generic type nesting exceeds 3 levels",
  tier: "yellow",
  blocking: false,
  languages: ["typescript", "tsx"],
  visit: (node: AstNode, _parent: AstNode | null, ctx: any, emit: any) => {
    if (node.type !== "TSTypeAliasDeclaration") return;

    // Simplified: count generic nesting depth
    const typeAnnotation = (node as any).typeAnnotation;
    if (!typeAnnotation) return;

    const countNesting = (n: any): number => {
      if (!n) return 0;
      const typeStr = n.type || "";
      if (typeStr.includes("Type") && typeStr !== "Identifier" && typeStr !== "StringLiteral") {
        return 1 + Math.max(
          countNesting((n as any).typeParameters?.params?.[0]),
          countNesting((n as any).types?.[0])
        );
      }
      return 0;
    };

    const depth = countNesting(typeAnnotation);
    if (depth > 3) {
      emit({
        loc: node.loc,
        message: `⚡ Type alias has ${depth} levels of generic nesting. Simplify or flatten.`,
        tier: "yellow",
        blocking: false,
      });
    }
  },
};

// ===== Phase 3: Graph-Backed + Pure-AST Rules =====

/** pass-through-wrapper: Function that only delegates to another call. */
export const PassThroughWrapperAst: AstRule = {
  id: "pass-through-wrapper",
  type: "ast",
  title: "Function is a pass-through wrapper with no added value",
  tier: "yellow",
  blocking: false,
  languages: ["javascript", "typescript", "jsx", "tsx"],
  visit: (node: AstNode, _parent: AstNode | null, ctx: any, emit: any) => {
    if (!["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type)) return;

    // Check if body is only a return statement calling a single function
    const body = (node as any).body;
    if (!body) return;

    let returnExpr: any = null;
    if (body.type === "BlockStatement") {
      // Block body: check if it's a single return statement
      if ((body as any).body?.length !== 1 || (body as any).body[0].type !== "ReturnStatement") return;
      returnExpr = (body as any).body[0].argument;
    } else if (body.type === "CallExpression") {
      // Arrow function with implicit return of a call
      returnExpr = body;
    } else {
      return; // Not a simple delegation pattern
    }

    // Only flag if the return is actually a function call (CallExpression)
    if (returnExpr?.type === "CallExpression") {
      emit({
        loc: node.loc,
        message: `⚡ Function is a pass-through wrapper. Inline the call site.`,
        tier: "yellow",
        blocking: false,
      });
    }
  },
};

export const PassThroughWrapperTsAst: TsAstRule = {
  id: "pass-through-wrapper",
  type: "tsast",
  title: "Function is a pass-through wrapper with no added value",
  tier: "yellow",
  blocking: false,
  languages: ["python", "go", "java", "kotlin", "ruby", "php", "csharp"],
  visit: (node: TsNode, ctx: any, emit: any) => {
    const profile = profileFor(ctx.language);
    if (!profile || !profile.functionTypes.has(node.type)) return;

    // Simplified: for tree-sitter, check if function body is only a return/call
    const childCount = node.namedChildCount;
    if (childCount <= 2) { // Just the name + params or minimal body
      emit({
        loc: { start: { line: node.startPosition?.row ?? 0, column: 0 }, end: { line: node.startPosition?.row ?? 0, column: 10 } },
        message: `⚡ Function appears to be a pass-through wrapper. Inline the call site.`,
        tier: "yellow",
        blocking: false,
      });
    }
  },
};

/** diff-churn-ratio: High ratio of lines added to AST statements. */
export const DiffChurnRatioAst: AstRule = {
  id: "diff-churn-ratio",
  type: "ast",
  title: "Diff has high churn-to-logic ratio (verbose boilerplate)",
  tier: "yellow",
  blocking: false,
  languages: ["javascript", "typescript", "jsx", "tsx"],
  visit: (node: AstNode, _parent: AstNode | null, ctx: any, emit: any) => {
    // File-level rule: check the ratio once
    if ((node as any).type !== "Program") return;

    const complexities = analyzeComplexity(ctx);
    const totalStatements = complexities.reduce((sum, fn) => sum + fn.metrics.astStatements, 0);
    const changedLines = ctx.changedLines?.size || 0;
    const thresholds = resolveThresholds(ctx.language, ctx.config);
    const maxChurnRatio = thresholds.maxDiffChurnRatio || 15;

    if (changedLines > 20 && totalStatements > 0) {
      const ratio = changedLines / totalStatements;
      if (ratio > maxChurnRatio) {
        emit({
          loc: { start: { line: 1, column: 0 }, end: { line: 1, column: 10 } },
          message: `⚡ Diff adds ${changedLines} lines for ${totalStatements} logic statements (ratio ${ratio.toFixed(1)}, threshold ${maxChurnRatio}). Check for boilerplate.`,
          tier: "yellow",
          blocking: false,
        });
      }
    }
  },
};

// Export arrays for bulk registration in builtin.ts
export const STRUCTURAL_TSAST_RULES: TsAstRule[] = [
  // Phase 1
  CognitiveComplexityTsAst,
  DeepNestingTsAst,
  LongFunctionTsAst,
  TooManyParametersTsAst,
  // Phase 3
  PassThroughWrapperTsAst,
];

export const STRUCTURAL_AST_RULES: AstRule[] = [
  // Phase 1
  CognitiveComplexityAst,
  DeepNestingAst,
  LongFunctionAst,
  TooManyParametersAst,
  // Phase 2
  TsOverGenericAst,
  // Phase 3
  PassThroughWrapperAst,
  DiffChurnRatioAst,
];
