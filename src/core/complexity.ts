/** Complexity metrics engine for LLM-written code detection.
 *
 * Computes cognitive complexity (SonarSource), nesting depth, function length, and parameter count
 * via AST analysis. Supports both tree-sitter (7 languages) and Babel (JS/TS).
 * Memoized per file to share results across rules.
 */

import type { TsNode, AstNode, RuleContext } from "./types.js";

export interface ComplexityMetrics {
  cognitive: number;       // SonarSource cognitive complexity
  nesting: number;         // max control-flow nesting depth
  lines: number;           // endLine - startLine + 1
  params: number;          // parameter count of the function signature
  astStatements: number;   // net statement nodes (for diff-churn-ratio)
}

export interface FunctionComplexity {
  name: string | null;
  startLine: number;       // 1-based
  endLine: number;
  bodyLines: number[];     // every line the function body spans (for in-diff anchoring)
  metrics: ComplexityMetrics;
}

/** Per-language node vocabulary. Mirrors the LanguageProfile / CallGraphProfile pattern. */
export interface ComplexityProfile {
  lang: string;
  functionTypes: Set<string>;      // e.g. "function_definition" (ts), "FunctionDeclaration" (Babel)
  classTypes: Set<string>;         // "class_definition" (ts), "ClassDeclaration" (Babel)
  fnNameField: string | null;      // tree-sitter field name for function name, or null → use Babel id
  paramsField: string;             // "parameters" (ts) / "params" (Babel)
  paramField?: string;             // for Babel FormalParameter traversal
  decisionTypes: Set<string>;       // +1 cognitive & structural: if/for/while/switch-case/catch/ternary
  nestingTypes: Set<string>;       // types that increment nesting level (usually same as decisionTypes)
  logicalOperatorTypes: Set<string>; // boolean_operator / LogicalExpression
  logicalOpField?: string;          // Babel: operator field; tree-sitter: no field, use type
  statementTypes: Set<string>;     // counted for astStatements
  returnType?: string;
}

const MEMOIZE_CACHE = new WeakMap<any, FunctionComplexity[]>();

/** Dispatch on ctx: uses ctx.tsTree when present, else ctx.ast (Babel). */
export function analyzeComplexity(ctx: RuleContext): FunctionComplexity[] {
  if (ctx.tsTree) {
    return computeTreeComplexity(ctx.tsTree, profileFor(ctx.language) || DEFAULT_TS_PROFILE);
  }
  if (ctx.ast) {
    return computeBabelComplexity(ctx.ast, BABEL_PROFILE);
  }
  return [];
}

export function computeTreeComplexity(root: any, profile: ComplexityProfile): FunctionComplexity[] {
  const actualRoot = root.rootNode || root;
  const cached = MEMOIZE_CACHE.get(actualRoot);
  if (cached) return cached;

  const results: FunctionComplexity[] = [];
  const walk = (node: TsNode) => {
    if (profile.functionTypes.has(node.type)) {
      const fn = analyzeFunctionNode(node, "tree", profile);
      if (fn) results.push(fn);
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) walk(child);
    }
  };
  walk(actualRoot);

  MEMOIZE_CACHE.set(actualRoot, results);
  return results;
}

export function computeBabelComplexity(root: AstNode, profile: ComplexityProfile): FunctionComplexity[] {
  const cached = MEMOIZE_CACHE.get(root);
  if (cached) return cached;

  const results: FunctionComplexity[] = [];
  const walk = (node: AstNode | null) => {
    if (!node) return;
    if (profile.functionTypes.has(node.type)) {
      const fn = analyzeFunctionNode(node, "babel", profile);
      if (fn) results.push(fn);
    }
    for (const key in node) {
      const child = (node as any)[key];
      if (child && typeof child === 'object') {
        if (Array.isArray(child)) {
          for (const item of child) walk(item);
        } else {
          walk(child);
        }
      }
    }
  };
  walk(root);

  MEMOIZE_CACHE.set(root, results);
  return results;
}

function analyzeFunctionNode(node: TsNode | AstNode, kind: "tree" | "babel", profile: ComplexityProfile): FunctionComplexity | null {
  const name = extractName(node, kind, profile);
  const { startLine, endLine } = extractLineRange(node, kind);
  if (startLine === null || endLine === null) return null;

  const bodyLines: number[] = [];
  for (let i = startLine; i <= endLine; i++) bodyLines.push(i);

  const cognitive = cognitiveComplexity(node, profile, kind);
  const nesting = nestingDepth(node, profile, kind);
  const params = parameterCount(node, kind, profile);
  const astStatements = countStatements(node, kind, profile);

  return {
    name: name || null,
    startLine,
    endLine,
    bodyLines,
    metrics: {
      cognitive,
      nesting,
      lines: endLine - startLine + 1,
      params,
      astStatements,
    }
  };
}

function extractName(node: TsNode | AstNode, kind: "tree" | "babel", profile: ComplexityProfile): string | null {
  if (kind === "tree") {
    const tsNode = node as TsNode;
    if (profile.fnNameField && tsNode.childForFieldName) {
      const nameNode = tsNode.childForFieldName(profile.fnNameField);
      return nameNode?.text ?? null;
    }
    // Fallback: look for child with type "identifier"
    for (let i = 0; i < tsNode.namedChildCount; i++) {
      const child = tsNode.namedChild(i);
      if (child && child.type === "identifier") return child.text ?? null;
    }
    return null;
  } else {
    const astNode = node as AstNode;
    return (astNode as any).id?.name ?? (astNode as any).name ?? null;
  }
}

function extractLineRange(node: TsNode | AstNode, kind: "tree" | "babel"): { startLine: number | null; endLine: number | null } {
  if (kind === "tree") {
    // tree-sitter rows are 0-based; every consumer (findings, inChange, ctx.lines) is 1-based.
    const tsNode = node as TsNode;
    const start = tsNode.startPosition ? tsNode.startPosition.row + 1 : null;
    const end = tsNode.endPosition ? tsNode.endPosition.row + 1 : null;
    return { startLine: start, endLine: end };
  } else {
    const astNode = node as AstNode;
    const start = (astNode as any).loc?.start?.line ?? null;
    const end = (astNode as any).loc?.end?.line ?? null;
    return { startLine: start, endLine: end };
  }
}

/** SonarSource cognitive complexity: +1 per decision, +nesting per nested decision,
 *  +1 per logical operator sequence break. */
export function cognitiveComplexity(node: TsNode | AstNode, profile: ComplexityProfile, kind: "tree" | "babel" = "tree"): number {
  let total = 0;
  let prevOp: string | null = null;

  const walk = (n: TsNode | AstNode | null, depth: number): void => {
    if (!n) return;

    const isDecision = kind === "tree"
      ? profile.decisionTypes.has((n as TsNode).type)
      : profile.decisionTypes.has((n as AstNode).type);

    if (isDecision) {
      total += 1 + depth; // base +1, +depth for nesting
    }

    // Logical operator sequence break: +1 when operator changes (a && b && c = +1, a && b || c = +2)
    const isLogical = kind === "tree"
      ? profile.logicalOperatorTypes.has((n as TsNode).type)
      : profile.logicalOperatorTypes.has((n as AstNode).type);

    if (isLogical) {
      const op = getOperator(n, kind);
      if (prevOp !== null && prevOp !== op) {
        total += 1;
      }
      prevOp = op;
    }

    if (kind === "tree") {
      const tsNode = n as TsNode;
      let nextDepth = depth;
      if (profile.nestingTypes.has(tsNode.type)) nextDepth = depth + 1;
      for (let i = 0; i < tsNode.namedChildCount; i++) {
        const child = tsNode.namedChild(i);
        if (child) walk(child, nextDepth);
      }
    } else {
      const astNode = n as AstNode;
      let nextDepth = depth;
      if (profile.nestingTypes.has(astNode.type)) nextDepth = depth + 1;
      for (const key in astNode) {
        const child = (astNode as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            for (const item of child) walk(item as TsNode | AstNode, nextDepth);
          } else {
            walk(child as TsNode | AstNode, nextDepth);
          }
        }
      }
    }
  };

  walk(node, 0);
  return total;
}

/** Max control-flow nesting depth (if/for/while/switch/try nesting). */
export function nestingDepth(node: TsNode | AstNode, profile: ComplexityProfile, kind: "tree" | "babel" = "tree"): number {
  let maxDepth = 0;

  const walk = (n: TsNode | AstNode | null, depth: number): void => {
    if (!n) return;
    maxDepth = Math.max(maxDepth, depth);

    const isNesting = kind === "tree"
      ? profile.nestingTypes.has((n as TsNode).type)
      : profile.nestingTypes.has((n as AstNode).type);

    const nextDepth = isNesting ? depth + 1 : depth;

    if (kind === "tree") {
      const tsNode = n as TsNode;
      for (let i = 0; i < tsNode.namedChildCount; i++) {
        const child = tsNode.namedChild(i);
        if (child) walk(child, nextDepth);
      }
    } else {
      const astNode = n as AstNode;
      for (const key in astNode) {
        const child = (astNode as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            for (const item of child) walk(item as TsNode | AstNode, nextDepth);
          } else {
            walk(child as TsNode | AstNode, nextDepth);
          }
        }
      }
    }
  };

  walk(node, 0);
  return maxDepth;
}

function parameterCount(node: TsNode | AstNode, kind: "tree" | "babel", profile: ComplexityProfile): number {
  if (kind === "tree") {
    const tsNode = node as TsNode;
    if (tsNode.childForFieldName) {
      const paramsNode = tsNode.childForFieldName(profile.paramsField);
      if (!paramsNode) return 0;
      return paramsNode.namedChildCount;
    }
    return 0;
  } else {
    const astNode = node as AstNode;
    const params = (astNode as any)[profile.paramsField ?? "params"] ?? [];
    return Array.isArray(params) ? params.length : 0;
  }
}

function countStatements(node: TsNode | AstNode, kind: "tree" | "babel", profile: ComplexityProfile): number {
  let count = 0;

  const walk = (n: TsNode | AstNode | null): void => {
    if (!n) return;

    const isStatement = kind === "tree"
      ? profile.statementTypes.has((n as TsNode).type)
      : profile.statementTypes.has((n as AstNode).type);

    if (isStatement) count++;

    if (kind === "tree") {
      const tsNode = n as TsNode;
      for (let i = 0; i < tsNode.namedChildCount; i++) {
        const child = tsNode.namedChild(i);
        if (child) walk(child);
      }
    } else {
      const astNode = n as AstNode;
      for (const key in astNode) {
        const child = (astNode as any)[key];
        if (child && typeof child === 'object') {
          if (Array.isArray(child)) {
            for (const item of child) walk(item as TsNode | AstNode);
          } else {
            walk(child as TsNode | AstNode);
          }
        }
      }
    }
  };

  walk(node);
  return count;
}

function getOperator(node: TsNode | AstNode, kind: "tree" | "babel"): string {
  if (kind === "tree") {
    return (node as TsNode).text ?? "?";
  } else {
    const astNode = node as AstNode;
    return (astNode as any).operator ?? "?";
  }
}

/** ctx.language → profile (falls back to generic tree-sitter profile). */
export function profileFor(language: string): ComplexityProfile | null {
  return LANGUAGE_PROFILES[language.toLowerCase()] || null;
}

// --- Per-language profiles ---

const DEFAULT_TS_PROFILE: ComplexityProfile = {
  lang: "generic-tree-sitter",
  functionTypes: new Set(["function_definition", "method_definition"]),
  classTypes: new Set(["class_definition"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "while_statement", "switch_statement", "catch_clause", "ternary_expression"]),
  nestingTypes: new Set(["if_statement", "for_statement", "while_statement", "do_statement", "switch_statement", "try_statement"]),
  logicalOperatorTypes: new Set(["boolean_operator"]),
  statementTypes: new Set(["expression_statement", "return_statement", "assignment", "variable_declaration"]),
};

const BABEL_PROFILE: ComplexityProfile = {
  lang: "javascript",
  functionTypes: new Set(["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"]),
  classTypes: new Set(["ClassDeclaration"]),
  fnNameField: null,
  paramsField: "params",
  paramField: "params",
  decisionTypes: new Set(["IfStatement", "ForStatement", "WhileStatement", "SwitchStatement", "TryStatement", "ConditionalExpression"]),
  // BlockStatement is deliberately NOT a nesting type. It is the `{ }` of every function and every
  // branch, so counting it made a flat one-liner report depth 1 and inflated both nesting and
  // cognitive score ~2x against the tree-sitter languages — which silently made the per-language
  // thresholds incomparable between the two backends.
  nestingTypes: new Set(["IfStatement", "ForStatement", "WhileStatement", "DoWhileStatement", "SwitchStatement", "TryStatement"]),
  logicalOperatorTypes: new Set(["LogicalExpression"]),
  logicalOpField: "operator",
  statementTypes: new Set(["ExpressionStatement", "ReturnStatement", "VariableDeclaration", "BlockStatement"]),
};

const PYTHON_PROFILE: ComplexityProfile = {
  lang: "python",
  functionTypes: new Set(["function_definition", "async_function_definition"]),
  classTypes: new Set(["class_definition"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "while_statement", "try_statement", "except_clause", "with_statement"]),
  nestingTypes: new Set(["if_statement", "for_statement", "while_statement", "try_statement", "with_statement"]),
  logicalOperatorTypes: new Set(["boolean_operator"]),
  statementTypes: new Set(["expression_statement", "return_statement", "assignment", "global_statement"]),
};

const GO_PROFILE: ComplexityProfile = {
  lang: "go",
  functionTypes: new Set(["function_declaration", "method_declaration"]),
  classTypes: new Set([]), // Go has no classes
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "select_statement", "type_switch_statement", "expression_switch_statement"]),
  nestingTypes: new Set(["if_statement", "for_statement", "select_statement", "type_switch_statement", "expression_switch_statement"]),
  logicalOperatorTypes: new Set(["binary_expression"]), // &&, ||
  statementTypes: new Set(["expression_statement", "return_statement", "assignment", "var_declaration"]),
};

const JAVA_PROFILE: ComplexityProfile = {
  lang: "java",
  functionTypes: new Set(["method_declaration", "constructor_declaration"]),
  classTypes: new Set(["class_declaration", "interface_declaration"]),
  fnNameField: "name",
  paramsField: "formal_parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_statement", "try_statement", "catch_clause"]),
  nestingTypes: new Set(["if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_statement", "try_statement"]),
  logicalOperatorTypes: new Set(["binary_expression"]),
  statementTypes: new Set(["expression_statement", "return_statement", "variable_declaration", "local_variable_declaration"]),
};

const KOTLIN_PROFILE: ComplexityProfile = {
  lang: "kotlin",
  functionTypes: new Set(["function_declaration", "function_literal"]),
  classTypes: new Set(["class_declaration"]),
  fnNameField: "name",
  paramsField: "value_parameters",
  decisionTypes: new Set(["if_expression", "for_statement", "while_statement", "try_expression", "when_expression"]),
  nestingTypes: new Set(["if_expression", "for_statement", "while_statement", "try_expression", "when_expression"]),
  logicalOperatorTypes: new Set(["binary_expression"]),
  statementTypes: new Set(["expression_statement", "return_statement", "property_declaration"]),
};

const RUBY_PROFILE: ComplexityProfile = {
  lang: "ruby",
  functionTypes: new Set(["method", "singleton_method"]),
  classTypes: new Set(["class", "module"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if", "unless", "for", "while", "until", "case", "rescue"]),
  nestingTypes: new Set(["if", "unless", "for", "while", "until", "case", "begin"]),
  logicalOperatorTypes: new Set(["binary"]),
  statementTypes: new Set(["call", "return", "assignment"]),
};

const PHP_PROFILE: ComplexityProfile = {
  lang: "php",
  functionTypes: new Set(["function_definition", "method_declaration"]),
  classTypes: new Set(["class_declaration", "interface_declaration"]),
  fnNameField: "name",
  paramsField: "formal_parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "try_statement", "catch_clause"]),
  nestingTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "try_statement"]),
  logicalOperatorTypes: new Set(["binary_expression"]),
  statementTypes: new Set(["expression_statement", "return_statement", "declaration"]),
};

const CSHARP_PROFILE: ComplexityProfile = {
  lang: "csharp",
  functionTypes: new Set(["method_declaration"]),
  classTypes: new Set(["class_declaration", "interface_declaration"]),
  fnNameField: "name",
  paramsField: "parameter_list",
  decisionTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "try_statement", "catch_clause"]),
  nestingTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "try_statement"]),
  logicalOperatorTypes: new Set(["binary_expression"]),
  statementTypes: new Set(["expression_statement", "return_statement", "local_variable_declaration"]),
};

const LANGUAGE_PROFILES: Record<string, ComplexityProfile> = {
  python: PYTHON_PROFILE,
  go: GO_PROFILE,
  java: JAVA_PROFILE,
  kotlin: KOTLIN_PROFILE,
  ruby: RUBY_PROFILE,
  php: PHP_PROFILE,
  csharp: CSHARP_PROFILE,
  "c#": CSHARP_PROFILE,
  javascript: BABEL_PROFILE,
  typescript: BABEL_PROFILE,
  tsx: BABEL_PROFILE,
  jsx: BABEL_PROFILE,
};
