/** Similarity fingerprinting for function definitions.
 *
 * Computes name-token overlap and structural body hashes so rules can detect "function
 * reinvention" — a newly written function that duplicates logic already in the repo
 * but with different names/literals.
 */

import { createHash } from "crypto";
import type { TsNode, AstNode, RuleContext } from "./types.js";
import { profileFor as complexityProfileFor } from "./complexity.js";

/** Semantic tokens extracted from an identifier, lowercased and deduplicated.
 *  Excludes single-letter tokens, stopwords, and produces [] for names with no
 *  surviving content. */
export function nameTokens(name: string): string[] {
  if (!name || typeof name !== "string") return [];

  // Split on camelCase/PascalCase boundaries, underscores, hyphens, and digit runs.
  // E.g. "getUserName_v2" -> ["get", "User", "Name", "_", "v", "2"]
  const parts = name
    .replace(/([a-z])([A-Z])/g, "$1 $2") // camelCase boundary
    .replace(/([A-Z])([A-Z][a-z])/g, "$1 $2") // PascalCase boundary
    .replace(/([a-zA-Z])(\d)/g, "$1 $2") // letter-to-digit
    .replace(/(\d)([a-zA-Z])/g, "$1 $2") // digit-to-letter
    .split(/[\s_-]+/) // split on whitespace, underscore, hyphen
    .filter(p => p.length > 0);

  const stopwords = new Set([
    "get", "set", "fetch", "load", "read", "make", "create", "build",
    "do", "run", "handle", "helper", "util", "utils", "impl",
    "new", "my", "tmp", "temp", "v", "wrapper", "func", "fn", "method"
  ]);

  const tokens: string[] = [];
  const seen = new Set<string>();

  for (const part of parts) {
    const lower = part.toLowerCase();
    // Drop stopwords, single-char tokens, and duplicates.
    if (lower.length >= 2 && !stopwords.has(lower) && !seen.has(lower)) {
      tokens.push(lower);
      seen.add(lower);
    }
  }

  return tokens;
}

/** Jaccard similarity of two token sets: |intersection| / |union|.
 *  Returns 0 if either set is empty. */
export function tokenOverlap(a: string[], b: string[]): number {
  if (!a || a.length === 0 || !b || b.length === 0) return 0;

  const aSet = new Set(a);
  const bSet = new Set(b);
  let intersection = 0;
  for (const token of aSet) {
    if (bSet.has(token)) intersection++;
  }

  const union = aSet.size + bSet.size - intersection;
  return union > 0 ? intersection / union : 0;
}

/** Shape metadata for a single function definition. */
export interface FnShape {
  name: string;           // declared function name; "" for anonymous
  startLine: number;      // 1-based inclusive
  endLine: number;        // 1-based inclusive
  arity: number;          // declared parameter count
  statementCount: number; // node types collected from body
  shapeHash: string;      // "" if statementCount < 3, else sha1 hex (first 16 chars)
}

/** Per-language node-type allowlist for normalized body shape extraction.
 *  Mirrors the LanguageProfile pattern from complexity.ts. */
interface FingerprintProfile {
  lang: string;
  functionTypes: Set<string>;
  /** Node types to include in the normalized shape. */
  bodyNodeTypes: Set<string>;
}

// Babel node types that represent control flow, statements, and meaningful expressions.
// Excludes identifiers, literals, type annotations, comments.
// BlockStatement is omitted: it wraps every function body, so including it would inflate counts.
// FunctionDeclaration/ClassDeclaration are only counted when nested inside the body, not the
// outer function itself (we walk only the body, not the function node).
const BABEL_BODY_TYPES = new Set([
  // Statements
  "ExpressionStatement", "ReturnStatement", "VariableDeclaration",
  "IfStatement", "ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement",
  "DoWhileStatement", "SwitchStatement", "SwitchCase", "TryStatement", "CatchClause",
  "ThrowStatement", "BreakStatement", "ContinueStatement",
  // Nested declarations
  "FunctionDeclaration", "ClassDeclaration",
  // Expressions (control flow and structure, not values)
  "CallExpression", "MemberExpression", "BinaryExpression", "LogicalExpression",
  "ConditionalExpression", "AssignmentExpression", "UpdateExpression",
  "ObjectExpression", "ArrayExpression", "TemplateLiteral",
  "AwaitExpression", "SpreadElement",
]);

// Tree-sitter types: generic fallback covering most languages.
const TS_BODY_TYPES = new Set([
  "expression_statement", "return_statement", "variable_declaration", "block",
  "if_statement", "for_statement", "while_statement", "do_statement",
  "switch_statement", "switch_case", "try_statement", "catch_clause",
  "throw_statement", "break_statement", "continue_statement",
  "function_definition", "async_function_definition", "class_definition",
  "call_expression", "method_call", "assignment", "binary_expression",
  "boolean_operator", "ternary_expression", "object", "array", "list",
  "await_expression", "spread_element",
]);

// Per-language profiles for tree-sitter.
const PYTHON_BODY_TYPES = new Set([
  "expression_statement", "return_statement", "assign", "augmented_assignment",
  "if_statement", "for_statement", "while_statement", "with_statement",
  "try_statement", "except_clause", "raise_statement", "pass_statement",
  "break_statement", "continue_statement", "import_statement", "import_from",
  "call", "binary_operator", "boolean_operator", "conditional_expression",
  "list", "dictionary", "set", "string", "f_string",
]);

const GO_BODY_TYPES = new Set([
  "expression_statement", "return_statement", "var_declaration",
  "if_statement", "for_statement", "select_statement", "switch_statement",
  "expression_case", "type_switch_statement", "case_type_clause",
  "break_statement", "continue_statement", "fallthrough_statement",
  "call_expression", "selector_expression", "binary_expression",
  "unary_expression", "field_declaration",
]);

const JAVA_BODY_TYPES = new Set([
  "expression_statement", "return_statement", "variable_declaration",
  "if_statement", "for_statement", "enhanced_for_statement",
  "while_statement", "do_statement", "switch_statement", "switch_case",
  "try_statement", "catch_clause", "finally_clause", "throw_statement",
  "break_statement", "continue_statement", "method_declaration",
  "method_invocation", "binary_expression", "ternary_expression",
  "field_access", "array_access", "object_creation_expression",
]);

const RUBY_BODY_TYPES = new Set([
  "return", "assignment", "if", "unless", "elsif", "else",
  "case", "when", "for", "while", "until", "begin", "rescue",
  "ensure", "break", "next", "redo",
  "call", "binary", "method_call", "do_block", "block",
]);

const PHP_BODY_TYPES = new Set([
  "expression_statement", "return_statement", "variable_declaration",
  "if_statement", "else_if_clause", "else_clause", "for_statement",
  "foreach_statement", "while_statement", "do_statement", "switch_statement",
  "switch_case", "try_statement", "catch_clause", "finally_clause",
  "throw_statement", "break_statement", "continue_statement",
  "function_call_expression", "method_call_expression", "binary_expression",
  "ternary_expression", "array", "array_creation_expression",
]);

const CSHARP_BODY_TYPES = new Set([
  "expression_statement", "return_statement", "variable_declaration",
  "if_statement", "for_statement", "foreach_statement",
  "while_statement", "do_statement", "switch_statement", "switch_case",
  "try_statement", "catch_clause", "finally_clause", "throw_statement",
  "break_statement", "continue_statement", "invocation_expression",
  "member_access_expression", "binary_expression", "conditional_expression",
  "array_creation_expression", "object_creation_expression",
]);

const KOTLIN_BODY_TYPES = new Set([
  "return_expression", "variable_declaration", "property_declaration",
  "if_expression", "when_expression", "when_entry", "for_statement",
  "while_statement", "do_statement", "try_expression", "catch_block",
  "finally_block", "throw_expression", "break_expression", "continue_expression",
  "call_expression", "binary_expression", "postfix_expression",
  "lambda_literal", "function_literal",
]);

const LANGUAGE_PROFILES: Record<string, FingerprintProfile> = {
  python: {
    lang: "python",
    functionTypes: new Set(["function_definition", "async_function_definition"]),
    bodyNodeTypes: PYTHON_BODY_TYPES,
  },
  go: {
    lang: "go",
    functionTypes: new Set(["function_declaration", "method_declaration"]),
    bodyNodeTypes: GO_BODY_TYPES,
  },
  java: {
    lang: "java",
    functionTypes: new Set(["method_declaration", "constructor_declaration"]),
    bodyNodeTypes: JAVA_BODY_TYPES,
  },
  kotlin: {
    lang: "kotlin",
    functionTypes: new Set(["function_declaration", "function_literal"]),
    bodyNodeTypes: KOTLIN_BODY_TYPES,
  },
  ruby: {
    lang: "ruby",
    functionTypes: new Set(["method", "singleton_method"]),
    bodyNodeTypes: RUBY_BODY_TYPES,
  },
  php: {
    lang: "php",
    functionTypes: new Set(["function_definition", "method_declaration"]),
    bodyNodeTypes: PHP_BODY_TYPES,
  },
  csharp: {
    lang: "csharp",
    functionTypes: new Set(["method_declaration"]),
    bodyNodeTypes: CSHARP_BODY_TYPES,
  },
  "c#": {
    lang: "csharp",
    functionTypes: new Set(["method_declaration"]),
    bodyNodeTypes: CSHARP_BODY_TYPES,
  },
};

function getProfile(language: string): FingerprintProfile {
  const lang = language.toLowerCase();
  return LANGUAGE_PROFILES[lang] || {
    lang: "generic-tree-sitter",
    functionTypes: new Set(["function_definition", "method_definition"]),
    bodyNodeTypes: TS_BODY_TYPES,
  };
}

/** Extract all function definitions and their shapes from a parsed file.
 *  Supports both Babel (JS/TS) and tree-sitter (Python, Go, etc.) backends.
 *  Never throws; returns [] on parse failure. */
export function shapeFunctions(ctx: {
  language: string;
  ast?: AstNode | null;
  tsTree?: TsTree | null;
  lines: string[];
}): FnShape[] {
  if (ctx.tsTree) {
    return extractTreeShapes(ctx.tsTree, ctx.language, ctx.lines);
  }
  if (ctx.ast) {
    return extractBabelShapes(ctx.ast, ctx.lines);
  }
  return [];
}

/** Walk a tree-sitter tree and extract function shapes. */
function extractTreeShapes(root: any, language: string, lines: string[]): FnShape[] {
  try {
    const actualRoot = root.rootNode || root;
    const profile = getProfile(language);
    const shapes: FnShape[] = [];

    const walk = (node: TsNode): void => {
      if (profile.functionTypes.has(node.type)) {
        const shape = analyzeTreeFunction(node, profile, lines);
        if (shape) shapes.push(shape);
      }
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child) walk(child);
      }
    };

    walk(actualRoot);
    return shapes;
  } catch {
    return [];
  }
}

/** Walk a Babel AST and extract function shapes. */
function extractBabelShapes(root: AstNode, lines: string[]): FnShape[] {
  try {
    const babelFunctionTypes = new Set([
      "FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression",
      "ClassMethod", "MethodDefinition", "ObjectMethod", // class and object methods
    ]);
    const shapes: FnShape[] = [];

    const walk = (node: AstNode | null): void => {
      if (!node) return;
      if (babelFunctionTypes.has(node.type)) {
        const shape = analyzeBabelFunction(node, lines);
        if (shape) shapes.push(shape);
      }
      for (const key in node) {
        const child = (node as any)[key];
        if (child && typeof child === "object") {
          if (Array.isArray(child)) {
            for (const item of child) walk(item);
          } else {
            walk(child);
          }
        }
      }
    };

    walk(root);
    return shapes;
  } catch {
    return [];
  }
}

/** Analyze a single tree-sitter function node. */
function analyzeTreeFunction(node: TsNode, profile: FingerprintProfile, lines: string[]): FnShape | null {
  const name = extractTreeName(node) || "";
  // Tree-sitter rows are 0-based. Use explicit null checks (!=), not truthiness, to avoid
  // dropping functions on line 1 (row 0). A function on row 0 is valid; 0 is only falsy as a boolean.
  // See the CHANGELOG entry "if (!startLine) guard discarded first-line functions" for the same bug fixed in complexity.ts.
  const startLine = node.startPosition?.row != null ? node.startPosition.row + 1 : null;
  const endLine = node.endPosition?.row != null ? node.endPosition.row + 1 : null;

  if (startLine === null || endLine === null) return null;

  // Find the body node (typically a block or compound_statement).
  let bodyNode: TsNode | null = null;
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && (child.type === "block" || child.type.endsWith("_block") || child.type.endsWith("_body"))) {
      bodyNode = child;
      break;
    }
  }

  // If no explicit body block, the entire function's children after the signature are the body.
  if (!bodyNode) bodyNode = node;

  const arity = extractTreeArity(node);
  const { shapeHash, statementCount } = computeBodyHash(bodyNode, "tree", profile.bodyNodeTypes, lines);

  return {
    name,
    startLine,
    endLine,
    arity,
    statementCount,
    shapeHash,
  };
}

/** Analyze a single Babel function node. */
function analyzeBabelFunction(node: AstNode, lines: string[]): FnShape | null {
  const name = extractBabelName(node) || "";
  const startLine = (node as any).loc?.start?.line ?? null;
  const endLine = (node as any).loc?.end?.line ?? null;

  if (startLine === null || endLine === null) return null;

  const arity = extractBabelArity(node);

  // Extract the function body (BlockStatement or expression for arrow functions).
  let bodyNode = (node as any).body;
  // For arrow functions with an expression body (not wrapped in {}), use the expression itself.
  // For others, body should be a BlockStatement.
  if (!bodyNode) bodyNode = node;

  const { shapeHash, statementCount } = computeBodyHash(bodyNode, "babel", BABEL_BODY_TYPES, lines);

  return {
    name,
    startLine,
    endLine,
    arity,
    statementCount,
    shapeHash,
  };
}

/** Extract function name from a tree-sitter node. */
function extractTreeName(node: TsNode): string | null {
  // Try the "name" field first.
  if (node.childForFieldName) {
    const nameNode = node.childForFieldName("name");
    if (nameNode) return nameNode.text || null;
  }
  // Fallback: look for an identifier child.
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && child.type === "identifier") return child.text || null;
  }
  return null;
}

/** Extract function name from a Babel node. */
function extractBabelName(node: AstNode): string | null {
  const n = node as any;
  return n.id?.name ?? n.name ?? null;
}

/** Extract parameter count from a tree-sitter function node. */
function extractTreeArity(node: TsNode): number {
  // Try the "parameters" field.
  if (node.childForFieldName) {
    const paramsNode = node.childForFieldName("parameters");
    if (paramsNode) return paramsNode.namedChildCount;
  }
  // Fallback: scan children for a node with type containing "parameter".
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child && (child.type === "parameters" || child.type.includes("parameter"))) {
      return child.namedChildCount;
    }
  }
  return 0;
}

/** Extract parameter count from a Babel function node. */
function extractBabelArity(node: AstNode): number {
  const params = (node as any).params ?? [];
  return Array.isArray(params) ? params.length : 0;
}

/** Build normalized body shape hash for a function.
 *  Returns the sha1 hash (first 16 hex chars) and statement count.
 *  If statementCount < 3, shapeHash is "". */
function computeBodyHash(
  node: TsNode | AstNode,
  kind: "tree" | "babel",
  bodyNodeTypes: Set<string>,
  lines: string[]
): { shapeHash: string; statementCount: number } {
  const typeSequence: string[] = [];

  const walk = (n: TsNode | AstNode | null): void => {
    if (!n) return;
    const type = kind === "tree" ? (n as TsNode).type : (n as AstNode).type;

    if (bodyNodeTypes.has(type)) {
      typeSequence.push(type);
    }

    // Walk children.
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
        if (child && typeof child === "object") {
          if (Array.isArray(child)) {
            for (const item of child) walk(item);
          } else {
            walk(child);
          }
        }
      }
    }
  };

  walk(node);

  const statementCount = typeSequence.length;
  let shapeHash = "";

  // Only hash if we have enough structure to be meaningful.
  if (statementCount >= 3) {
    const normalized = typeSequence.join(",");
    const hash = createHash("sha1").update(normalized).digest("hex");
    shapeHash = hash.slice(0, 16);
  }

  return { shapeHash, statementCount };
}

// Type hint for tree-sitter tree structure (mirrors TsNode / TsTree from types.ts).
interface TsTree {
  rootNode: TsNode;
}
