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
  /** Field name for the parameter list (tree-sitter) or property name (Babel). Some grammars
   *  (Kotlin) expose no such field — parameterCount() then falls back to scanning named children
   *  for a node whose TYPE equals this same string. */
  paramsField: string;
  /**
   * +1 (or +1+nesting, unless reached via {@link elseBranches}) per occurrence: if/for/while/
   * switch/catch/ternary. Deliberately excludes the bare try/begin keyword — SonarSource's spec
   * scores `catch`, not `try` itself.
   */
  decisionTypes: Set<string>;
  /** Types whose own body is one level deeper than their surroundings — normally the same set as
   *  decisionTypes, again excluding the bare try/begin. */
  nestingTypes: Set<string>;
  /** Node type(s) that MAY represent a logical AND/OR, pre-filtered by {@link logicalOperatorSymbols}
   *  since several grammars reuse one catch-all "binary_expression" type for every operator. */
  logicalOperatorTypes: Set<string>;
  /** The operator strings that actually count as a logical sequence break. Defaults to {"&&","||"}
   *  when unset. Python overrides to {"and","or"}. */
  logicalOperatorSymbols?: Set<string>;
  statementTypes: Set<string>;     // counted for astStatements
}

const DEFAULT_LOGICAL_SYMBOLS = new Set(["&&", "||"]);

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
  // NOTE: `tree.rootNode` is a fresh wrapper object on every access in the underlying tree-sitter
  // binding, so this WeakMap essentially never hits for tree-sitter callers — each call recomputes.
  // That's a missed optimization, not a correctness bug (a fresh parse of different content always
  // produces a structurally distinct node anyway), so it's left as-is rather than papered over with
  // an identity cache keyed on something less trustworthy than the node itself.
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

/**
 * The else/elif/else-if branch(es) of an if-like node, as direct child object references — scored
 * flat (+1, no nesting bonus) rather than as ordinary nested decisions, per the SonarSource spec's
 * worked "if / else if / else if" example (each branch is +1 regardless of chain length).
 *
 * Three tree-sitter shapes, confirmed against the real grammars rather than assumed:
 *  - flat sibling clauses: python (`elif_clause`, `else_clause`), php (`else_if_clause`, `else_clause`)
 *  - a chained `alternative` field: go, java, csharp, ruby (`if` → `elsif`)
 *  - Kotlin exposes neither — its else-if is a trailing child that repeats the node's own type
 *    (`if_expression` → `if_expression`), so it falls back to a positional check.
 * Babel uses `.alternate` directly, which may itself be a chained IfStatement or a terminal
 * BlockStatement (a plain `else`) — either way it is flat.
 */
const FLAT_SIBLING_CLAUSE_TYPES = new Set(["elif_clause", "else_clause", "else_if_clause"]);

function elseBranches(node: TsNode | AstNode, kind: "tree" | "babel"): (TsNode | AstNode)[] {
  if (kind === "babel") {
    const alt = (node as any).alternate;
    return alt ? [alt] : [];
  }

  const tsNode = node as TsNode;
  const siblings: TsNode[] = [];
  for (let i = 0; i < tsNode.namedChildCount; i++) {
    const c = tsNode.namedChild(i);
    if (c && FLAT_SIBLING_CLAUSE_TYPES.has(c.type)) siblings.push(c);
  }
  if (siblings.length > 0) return siblings;

  if (tsNode.childForFieldName) {
    const alt = tsNode.childForFieldName("alternative");
    if (alt) return [alt];
  }

  // Kotlin fallback: no field, no flat siblings — the chain link is the last named child when it
  // repeats this node's own type.
  const count = tsNode.namedChildCount;
  if (count >= 3) {
    const last = tsNode.namedChild(count - 1);
    if (last && last.type === tsNode.type) return [last];
  }
  return [];
}

/** Operator token for a logical/binary node — NOT the whole subexpression. */
function operatorSymbol(node: TsNode | AstNode, kind: "tree" | "babel"): string {
  if (kind === "tree") {
    const tsNode = node as TsNode;
    const opNode = tsNode.childForFieldName ? tsNode.childForFieldName("operator") : null;
    return opNode ? opNode.text : tsNode.text;
  }
  return (node as any).operator ?? "?";
}

/** True when `node` is a logical AND/OR — filters out grammars that reuse one catch-all binary
 *  node type (`binary_expression`) for every operator, arithmetic and comparison included. */
function isLogicalOperatorNode(node: TsNode | AstNode, profile: ComplexityProfile, kind: "tree" | "babel"): boolean {
  const type = kind === "tree" ? (node as TsNode).type : (node as AstNode).type;
  if (!profile.logicalOperatorTypes.has(type)) return false;
  const symbols = profile.logicalOperatorSymbols ?? DEFAULT_LOGICAL_SYMBOLS;
  return symbols.has(operatorSymbol(node, kind));
}

/**
 * Reference equality for AstNode (plain, stable JS objects — `===` works) does NOT hold for
 * TsNode: the underlying tree-sitter binding returns a fresh wrapper object on every
 * `namedChild()`/`childForFieldName()` call, even for the same underlying node. Two lookups of
 * "the same" child are never `===`. TsNode.id is the stable identity the binding does guarantee.
 */
function sameNode(a: TsNode | AstNode, b: TsNode | AstNode, kind: "tree" | "babel"): boolean {
  if (kind === "tree") return (a as TsNode).id === (b as TsNode).id;
  return a === b;
}

function nodeType(n: TsNode | AstNode, kind: "tree" | "babel"): string {
  return kind === "tree" ? (n as TsNode).type : (n as AstNode).type;
}

function children(n: TsNode | AstNode, kind: "tree" | "babel"): (TsNode | AstNode)[] {
  if (kind === "tree") {
    const tsNode = n as TsNode;
    const out: (TsNode | AstNode)[] = [];
    for (let i = 0; i < tsNode.namedChildCount; i++) {
      const c = tsNode.namedChild(i);
      if (c) out.push(c);
    }
    return out;
  }
  const astNode = n as AstNode;
  const out: (TsNode | AstNode)[] = [];
  for (const key in astNode) {
    const child = (astNode as any)[key];
    if (child && typeof child === "object") {
      if (Array.isArray(child)) out.push(...child.filter((x) => x && typeof x === "object"));
      else out.push(child);
    }
  }
  return out;
}

/**
 * SonarSource cognitive complexity.
 *
 * Base rule: each decision point (if/for/while/switch/catch/ternary) scores 1 + current nesting
 * depth. An else/elif/else-if branch (see {@link elseBranches}) scores a flat 1 regardless of depth
 * or chain length — the spec's `if / else if / else if` example totals 3, not 1+2+3. Each maximal
 * run of a like logical operator (`a && b && c`) scores 1; a run broken by a different operator
 * (`a && b || c`) scores 1 per run. A node's own body is one level deeper than its surroundings;
 * reaching a node via its else-branch does not add that level a second time.
 *
 * Known gaps versus the full spec: no extra increment for jumps to labels, recursive calls, or
 * nesting inside function literals passed as arguments — narrow enough edge cases that they were
 * left out rather than risk a harder-to-verify implementation.
 */
export function cognitiveComplexity(node: TsNode | AstNode, profile: ComplexityProfile, kind: "tree" | "babel" = "tree"): number {
  let total = 0;

  const walk = (n: TsNode | AstNode | null, depth: number, isElseBranch: boolean, chainOp: string | null): void => {
    if (!n) return;
    const t = nodeType(n, kind);

    if (isElseBranch) {
      total += 1; // flat — chain length and nesting depth both irrelevant
    } else if (profile.decisionTypes.has(t)) {
      total += 1 + depth;
    }

    let childChainOp: string | null = null;
    if (isLogicalOperatorNode(n, profile, kind)) {
      const op = operatorSymbol(n, kind);
      if (chainOp !== op) total += 1; // includes the first occurrence of any run (chainOp starts null)
      childChainOp = op;
    }

    const branches = elseBranches(n, kind);
    const isNesting = profile.nestingTypes.has(t);
    // A node's TRUE body is one level deeper than the node itself, whether or not the node was
    // itself reached via an else-branch — only the else-branch link itself is exempt from adding
    // depth, not what's inside it.
    const bodyDepth = isNesting ? depth + 1 : depth;

    for (const child of children(n, kind)) {
      const childIsElse = branches.some((b) => sameNode(b, child, kind));
      // An else-branch child inherits THIS node's own depth unchanged (chains never compound
      // depth); every other child gets the true-body depth.
      walk(child, childIsElse ? depth : bodyDepth, childIsElse, childChainOp);
    }
  };

  walk(node, 0, false, null);
  return total;
}

/** Max control-flow nesting depth. Same else-branch exemption as {@link cognitiveComplexity} — a
 *  10-branch if/elif chain is flat, not 10 levels deep. */
export function nestingDepth(node: TsNode | AstNode, profile: ComplexityProfile, kind: "tree" | "babel" = "tree"): number {
  let maxDepth = 0;

  const walk = (n: TsNode | AstNode | null, depth: number, isElseBranch: boolean): void => {
    if (!n) return;
    // An else-branch's OWN link doesn't count as an extra level, but its true body still can.
    if (!isElseBranch) maxDepth = Math.max(maxDepth, depth);

    const t = nodeType(n, kind);
    const branches = elseBranches(n, kind);
    const isNesting = profile.nestingTypes.has(t);
    const bodyDepth = isNesting ? depth + 1 : depth;

    for (const child of children(n, kind)) {
      const childIsElse = branches.some((b) => sameNode(b, child, kind));
      walk(child, childIsElse ? depth : bodyDepth, childIsElse);
    }
  };

  walk(node, 0, false);
  return maxDepth;
}

function parameterCount(node: TsNode | AstNode, kind: "tree" | "babel", profile: ComplexityProfile): number {
  if (kind === "tree") {
    const tsNode = node as TsNode;
    let paramsNode: TsNode | null = null;
    if (tsNode.childForFieldName) paramsNode = tsNode.childForFieldName(profile.paramsField);
    if (!paramsNode) {
      // Some grammars (Kotlin) expose no field for the parameter list; fall back to scanning named
      // children for a node whose TYPE matches the same profile value.
      for (let i = 0; i < tsNode.namedChildCount; i++) {
        const c = tsNode.namedChild(i);
        if (c && c.type === profile.paramsField) { paramsNode = c; break; }
      }
    }
    return paramsNode ? paramsNode.namedChildCount : 0;
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
    if (profile.statementTypes.has(nodeType(n, kind))) count++;
    for (const child of children(n, kind)) walk(child);
  };

  walk(node);
  return count;
}

/** ctx.language → profile (falls back to generic tree-sitter profile). */
export function profileFor(language: string): ComplexityProfile | null {
  return LANGUAGE_PROFILES[language.toLowerCase()] || null;
}

// --- Per-language profiles ---
//
// decisionTypes/nestingTypes deliberately exclude the bare try/begin keyword: SonarSource scores
// `catch`, not `try` itself, so a plain try block does not add a nesting level to its own body.

const DEFAULT_TS_PROFILE: ComplexityProfile = {
  lang: "generic-tree-sitter",
  functionTypes: new Set(["function_definition", "method_definition"]),
  classTypes: new Set(["class_definition"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "while_statement", "switch_statement", "catch_clause", "ternary_expression"]),
  nestingTypes: new Set(["if_statement", "for_statement", "while_statement", "do_statement", "switch_statement", "catch_clause"]),
  logicalOperatorTypes: new Set(["boolean_operator"]),
  statementTypes: new Set(["expression_statement", "return_statement", "assignment", "variable_declaration"]),
};

const BABEL_PROFILE: ComplexityProfile = {
  lang: "javascript",
  functionTypes: new Set(["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"]),
  classTypes: new Set(["ClassDeclaration"]),
  fnNameField: null,
  paramsField: "params",
  decisionTypes: new Set(["IfStatement", "ForStatement", "WhileStatement", "SwitchStatement", "CatchClause", "ConditionalExpression"]),
  // BlockStatement is deliberately NOT a nesting type. It is the `{ }` of every function and every
  // branch, so counting it made a flat one-liner report depth 1 and inflated both nesting and
  // cognitive score ~2x against the tree-sitter languages — which silently made the per-language
  // thresholds incomparable between the two backends.
  nestingTypes: new Set(["IfStatement", "ForStatement", "WhileStatement", "DoWhileStatement", "SwitchStatement", "CatchClause", "ConditionalExpression"]),
  logicalOperatorTypes: new Set(["LogicalExpression"]),
  statementTypes: new Set(["ExpressionStatement", "ReturnStatement", "VariableDeclaration", "BlockStatement"]),
};

const PYTHON_PROFILE: ComplexityProfile = {
  lang: "python",
  functionTypes: new Set(["function_definition", "async_function_definition"]),
  classTypes: new Set(["class_definition"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "while_statement", "except_clause", "with_statement"]),
  nestingTypes: new Set(["if_statement", "for_statement", "while_statement", "except_clause", "with_statement"]),
  logicalOperatorTypes: new Set(["boolean_operator"]),
  logicalOperatorSymbols: new Set(["and", "or"]),
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
  logicalOperatorTypes: new Set(["binary_expression"]), // catch-all node type; filtered to &&/|| by logicalOperatorSymbols
  statementTypes: new Set(["expression_statement", "return_statement", "assignment", "var_declaration"]),
};

const JAVA_PROFILE: ComplexityProfile = {
  lang: "java",
  functionTypes: new Set(["method_declaration", "constructor_declaration"]),
  classTypes: new Set(["class_declaration", "interface_declaration"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_statement", "catch_clause"]),
  nestingTypes: new Set(["if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_statement", "catch_clause"]),
  logicalOperatorTypes: new Set(["binary_expression"]),
  statementTypes: new Set(["expression_statement", "return_statement", "variable_declaration", "local_variable_declaration"]),
};

const KOTLIN_PROFILE: ComplexityProfile = {
  lang: "kotlin",
  functionTypes: new Set(["function_declaration", "function_literal"]),
  classTypes: new Set(["class_declaration"]),
  fnNameField: "name",
  // No field exposes the parameter list on function_declaration; used as a type-based fallback.
  paramsField: "function_value_parameters",
  decisionTypes: new Set(["if_expression", "for_statement", "while_statement", "catch_block", "when_expression"]),
  nestingTypes: new Set(["if_expression", "for_statement", "while_statement", "catch_block", "when_expression"]),
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
  nestingTypes: new Set(["if", "unless", "for", "while", "until", "case", "rescue"]),
  logicalOperatorTypes: new Set(["binary"]),
  statementTypes: new Set(["call", "return", "assignment"]),
};

const PHP_PROFILE: ComplexityProfile = {
  lang: "php",
  functionTypes: new Set(["function_definition", "method_declaration"]),
  classTypes: new Set(["class_declaration", "interface_declaration"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "catch_clause"]),
  nestingTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "catch_clause"]),
  logicalOperatorTypes: new Set(["binary_expression"]),
  statementTypes: new Set(["expression_statement", "return_statement", "declaration"]),
};

const CSHARP_PROFILE: ComplexityProfile = {
  lang: "csharp",
  functionTypes: new Set(["method_declaration"]),
  classTypes: new Set(["class_declaration", "interface_declaration"]),
  fnNameField: "name",
  paramsField: "parameters",
  decisionTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "catch_clause"]),
  nestingTypes: new Set(["if_statement", "for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "catch_clause"]),
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
