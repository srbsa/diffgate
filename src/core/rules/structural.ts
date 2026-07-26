/** Structural complexity rules for LLM-written code.
 *
 * Phase 1 — universal metrics: cognitive complexity, nesting depth, function length, parameters.
 * Phase 2 — language-specific "Enterprise Reflex" anti-patterns (needless classes, premature
 *           interfaces, single-impl interfaces, over-generic types).
 * Phase 3 — pass-through wrappers, diff churn, and the graph-backed single-caller abstraction.
 *
 * All rules ship as 🟡 review-only (non-blocking) to protect the 0-false-block brand.
 * Thresholds are language-differentiated via the `languageOverrides` config section.
 */

import type { TsAstRule, AstRule, TsNode, AstNode, RuleContext, EmitFn } from "../types.js";
import { resolveThresholds } from "../language-thresholds.js";
import { analyzeComplexity, profileFor, type ComplexityProfile } from "../complexity.js";

// ===== Shared tree-sitter helpers =====

/** Call-expression node types across the tree-sitter grammars we support. */
const CALL_NODE_TYPES = new Set([
  "call",                  // python, ruby
  "call_expression",       // go, c#, kotlin
  "method_invocation",     // java
  "function_call_expression", // php
  "scoped_call_expression",
  "member_call_expression",
]);

/** 1-based source location for a tree-sitter node, in the shape `emit` expects. */
function tsLoc(node: TsNode): { start: { line: number; column: number }; end: { line: number; column: number } } {
  const s = node.startPosition;
  const e = node.endPosition;
  return {
    start: { line: (s ? s.row : 0) + 1, column: s ? s.column : 0 },
    end: { line: (e ? e.row : 0) + 1, column: e ? e.column : 0 },
  };
}

/** Declared name of a tree-sitter definition node, via the profile's name field. */
function extractTsName(node: TsNode, profile?: ComplexityProfile | null): string | null {
  const field = profile?.fnNameField ?? "name";
  const named = node.childForFieldName(field);
  if (named) return named.text;
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c && (c.type === "identifier" || c.type === "type_identifier")) return c.text;
  }
  return null;
}

/** Immediate named children of a node, as an array. */
function namedChildren(node: TsNode): TsNode[] {
  const out: TsNode[] = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c) out.push(c);
  }
  return out;
}

/** Count identifier occurrences of `name` in the tree, excluding its own declaration site. */
function countReferences(root: TsNode, name: string, declLine: number): number {
  let n = 0;
  const walk = (node: TsNode): void => {
    if ((node.type === "identifier" || node.type === "type_identifier") && node.text === name) {
      if ((node.startPosition ? node.startPosition.row : -1) !== declLine) n++;
    }
    for (const c of namedChildren(node)) walk(c);
  };
  walk(root);
  return n;
}

/**
 * True when `call`'s arguments are exactly the enclosing function's parameters, in order and
 * untouched. That is the signal that the wrapper adds nothing: no defaults, no reshaping, no
 * literals, no extra work. A zero-parameter function delegating a zero-argument call counts too.
 */
function forwardsParamsUnchanged(fn: TsNode, call: TsNode, profile: ComplexityProfile): boolean {
  const paramsNode = fn.childForFieldName(profile.paramsField);
  // No field found (e.g. Kotlin, which exposes no "parameters" field on function_declaration) means
  // we cannot see the real parameter list — that's inconclusive, not zero. Treating it as zero would
  // let a genuinely zero-arg call falsely "prove" forwarding for a function we never actually checked.
  if (!paramsNode) return false;
  const params = namedChildren(paramsNode);
  const paramNames = params.map((p) => {
    if (p.type === "identifier") return p.text;
    const id = p.childForFieldName("name");
    if (id) return id.text;
    const first = p.namedChild(0);
    return first && first.type === "identifier" ? first.text : null;
  });
  // An unnameable parameter (destructuring, varargs, defaults) means we cannot prove forwarding.
  if (paramNames.some((n) => n === null)) return false;

  const argsNode = call.childForFieldName("arguments") ?? call.childForFieldName("argument_list");
  const args = argsNode ? namedChildren(argsNode) : [];
  if (args.length !== paramNames.length) return false;
  return args.every((a, i) => a.type === "identifier" && a.text === paramNames[i]);
}

/** Babel counterpart of {@link forwardsParamsUnchanged}. */
function babelForwardsParamsUnchanged(fn: AstNode, call: AstNode): boolean {
  const params = ((fn as { params?: AstNode[] }).params ?? []);
  // Defaults, rest, and destructuring mean we cannot prove a clean forward.
  if (!params.every((p) => p.type === "Identifier")) return false;
  const args = ((call as { arguments?: AstNode[] }).arguments ?? []);
  if (args.length !== params.length) return false;
  return args.every(
    (a, i) =>
      a.type === "Identifier" &&
      (a as { name?: string }).name === (params[i] as { name?: string }).name
  );
}

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
      });
    }
  },
};

/**
 * py-unnecessary-class: a class whose only members are `__init__` and one other method is a
 * function wearing a costume. Deliberately narrow — any base class, any decorator, or any extra
 * method means the author had a reason, so we stay quiet.
 */
export const PyUnnecessaryClassTsAst: TsAstRule = {
  id: "py-unnecessary-class",
  type: "tsast",
  title: "Class has a single method beyond __init__",
  tier: "yellow",
  blocking: false,
  languages: ["python"],
  sinkQuery: "(class_definition) @sink",
  visit: (node: TsNode, ctx: RuleContext, emit: EmitFn) => {
    if (node.type !== "class_definition") return;
    // @dataclass / @attrs / any decorator → the shape is intentional.
    if (node.parent && node.parent.type === "decorated_definition") return;
    // Any base (ABC, Protocol, NamedTuple, Enum, Exception, a framework model) → intentional.
    const supers = node.childForFieldName("superclasses");
    if (supers && supers.namedChildCount > 0) return;

    const body = node.childForFieldName("body");
    if (!body) return;

    const methods: TsNode[] = [];
    for (const child of namedChildren(body)) {
      // A decorated member (@property, @staticmethod, @cached_property) → intentional.
      if (child.type === "decorated_definition") return;
      if (child.type === "function_definition") methods.push(child);
    }

    const names = methods.map((m) => extractTsName(m) ?? "");
    if (!names.includes("__init__")) return;              // no constructor → a different smell
    const others = names.filter((n) => n !== "__init__");
    if (others.length !== 1) return;                      // 0 → data holder; 2+ → a real class
    if (others[0].startsWith("__")) return;               // dunder-only → protocol-ish, leave alone

    const className = extractTsName(node);
    emit({
      loc: tsLoc(node),
      symbol: className,
      message: `⚡ Class ${className || "(anonymous)"} has only \`${others[0]}\` beyond \`__init__\`. A plain function taking the constructor's arguments is usually simpler.`,
    });
  },
};

/**
 * py-unnecessary-abc: an ABC with at most one concrete implementation in the same file. Abstraction
 * ahead of a second implementor is speculative.
 */
export const PyUnnecessaryAbcTsAst: TsAstRule = {
  id: "py-unnecessary-abc",
  type: "tsast",
  title: "Abstract base class with a single implementation",
  tier: "yellow",
  blocking: false,
  languages: ["python"],
  sinkQuery: "(class_definition) @sink",
  visit: (node: TsNode, ctx: RuleContext, emit: EmitFn) => {
    if (node.type !== "class_definition") return;
    const supers = node.childForFieldName("superclasses");
    if (!supers) return;
    // Only fire for a declared ABC — `ABC`, `abc.ABC`, or `metaclass=ABCMeta`.
    if (!/\bABC(Meta)?\b/.test(supers.text)) return;

    const className = extractTsName(node);
    if (!className) return;

    const root = ctx.tsTree ? ctx.tsTree.rootNode : null;
    if (!root) return;

    // Count classes in this file that name it as a base.
    let impls = 0;
    const walk = (n: TsNode): void => {
      if (n.type === "class_definition" && n !== node) {
        const s = n.childForFieldName("superclasses");
        if (s && new RegExp(`\\b${className}\\b`).test(s.text)) impls++;
      }
      for (const c of namedChildren(n)) walk(c);
    };
    walk(root);

    if (impls > 1) return; // a second implementor justifies the abstraction

    emit({
      loc: tsLoc(node),
      symbol: className,
      message: `⚡ Abstract class ${className} has ${impls} implementation${impls === 1 ? "" : "s"} here. Defer the abstraction until a second one exists.`,
    });
  },
};

/**
 * go-premature-interface: a small interface that nothing in the file consumes. Go's idiom is to
 * accept interfaces at the call site and return concrete structs — an interface declared before a
 * consumer exists is speculation.
 */
export const GoPrematureInterfaceTsAst: TsAstRule = {
  id: "go-premature-interface",
  type: "tsast",
  title: "Interface declared before a second implementation exists",
  tier: "yellow",
  blocking: false,
  languages: ["go"],
  sinkQuery: "(type_spec) @sink",
  visit: (node: TsNode, ctx: RuleContext, emit: EmitFn) => {
    if (node.type !== "type_spec") return;
    const kids = namedChildren(node);
    const iface = kids.find((c) => c.type === "interface_type");
    if (!iface) return;

    const methods = namedChildren(iface).filter(
      (c) => c.type === "method_elem" || c.type === "method_spec"
    );
    if (methods.length === 0 || methods.length > 2) return; // marker or rich interface → leave alone

    const name = extractTsName(node);
    if (!name) return;

    const root = ctx.tsTree ? ctx.tsTree.rootNode : null;
    if (!root) return;
    const declRow = node.startPosition ? node.startPosition.row : -1;
    if (countReferences(root, name, declRow) > 1) return; // genuinely consumed

    emit({
      loc: tsLoc(node),
      symbol: name,
      message: `⚡ Interface ${name} has ${methods.length} method${methods.length === 1 ? "" : "s"} and no consumer here. Go idiom: accept interfaces at the call site, return concrete structs.`,
    });
  },
};

/**
 * java-single-impl-interface: the classic `Foo` + `FooImpl` pair. Fires only when exactly one class
 * in the file implements the interface.
 */
export const JavaSingleImplInterfaceTsAst: TsAstRule = {
  id: "java-single-impl-interface",
  type: "tsast",
  title: "Interface with exactly one implementation",
  tier: "yellow",
  blocking: false,
  languages: ["java"],
  sinkQuery: "(interface_declaration) @sink",
  visit: (node: TsNode, ctx: RuleContext, emit: EmitFn) => {
    if (node.type !== "interface_declaration") return;
    const name = extractTsName(node);
    if (!name) return;

    const root = ctx.tsTree ? ctx.tsTree.rootNode : null;
    if (!root) return;

    const implementors: string[] = [];
    const walk = (n: TsNode): void => {
      if (n.type === "class_declaration") {
        const supers = n.childForFieldName("interfaces");
        const text = supers ? supers.text : namedChildren(n).find((c) => c.type === "super_interfaces")?.text;
        if (text && new RegExp(`\\b${name}\\b`).test(text)) {
          const cn = extractTsName(n);
          if (cn) implementors.push(cn);
        }
      }
      for (const c of namedChildren(n)) walk(c);
    };
    walk(root);

    if (implementors.length !== 1) return; // 0 → external impl likely; 2+ → justified

    emit({
      loc: tsLoc(node),
      symbol: name,
      message: `⚡ Interface ${name} has a single implementation (${implementors[0]}). Inline it unless multiple implementations are planned.`,
    });
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

    // Only a *pass-through* when the call forwards the parameters untouched — same arity, same
    // identifiers, same order. Without this the rule fires on every `x => transform(x, 2)` and
    // every `() => doThing()` callback, which is most of a normal codebase.
    if (returnExpr?.type !== "CallExpression") return;
    if (!babelForwardsParamsUnchanged(node, returnExpr)) return;

    emit({
      loc: node.loc,
      symbol: (node as { id?: { name?: string } }).id?.name ?? null,
      message: `⚡ Function only delegates to another call without transforming its arguments. Inline the call site unless the indirection is load-bearing.`,
    });
  },
};

export const PassThroughWrapperTsAst: TsAstRule = {
  id: "pass-through-wrapper",
  type: "tsast",
  title: "Function is a pass-through wrapper with no added value",
  tier: "yellow",
  blocking: false,
  languages: ["python", "go", "java", "kotlin", "ruby", "php", "csharp"],
  visit: (node: TsNode, ctx: RuleContext, emit: EmitFn) => {
    const profile = profileFor(ctx.language);
    if (!profile || !profile.functionTypes.has(node.type)) return;

    const body = node.childForFieldName("body");
    if (!body) return;

    // The body must be exactly one statement. Some grammars (Go) wrap it in an extra
    // statement_list; unwrap a lone container before counting.
    let block = body;
    if (block.namedChildCount === 1) {
      const only = block.namedChild(0);
      if (only && (only.type === "statement_list" || only.type === "block")) block = only;
    }
    if (block.namedChildCount !== 1) return;

    const stmt = block.namedChild(0);
    if (!stmt) return;

    // A bare delegation: `return f(...)` or a lone `f(...)` expression statement.
    let call: TsNode | null = null;
    if (stmt.type === "return_statement" || stmt.type === "expression_statement") {
      const inner = stmt.namedChild(0);
      if (inner && CALL_NODE_TYPES.has(inner.type)) call = inner;
    } else if (CALL_NODE_TYPES.has(stmt.type)) {
      call = stmt;
    }
    if (!call) return;

    // Only a *pass-through* if the call forwards the parameters untouched. A wrapper that
    // reshapes arguments, injects defaults, or adds a literal is doing real work.
    if (!forwardsParamsUnchanged(node, call, profile)) return;

    emit({
      loc: tsLoc(node),
      symbol: extractTsName(node, profile),
      message: `⚡ Function ${extractTsName(node, profile) || "(anonymous)"} only delegates to another call without transforming its arguments. Inline the call site unless the indirection is load-bearing.`,
    });
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
  visit: (node: AstNode, _parent: AstNode | null, ctx: RuleContext, emit: EmitFn) => {
    // File-level rule: compute the ratio once, at the root.
    if (node.type !== "Program") return;

    const changed = ctx.changedLines;
    const changedCount = changed ? changed.size : ctx.lines.length;
    if (changedCount <= 20) return; // a small diff can't be "sprawl"

    const complexities = analyzeComplexity(ctx);
    const totalStatements = complexities.reduce((sum, fn) => sum + fn.metrics.astStatements, 0);
    if (totalStatements <= 0) return;

    const thresholds = resolveThresholds(ctx.language, ctx.config);
    const maxChurnRatio = thresholds.maxDiffChurnRatio ?? 15;
    const ratio = changedCount / totalStatements;
    if (ratio <= maxChurnRatio) return;

    // Anchor to a line that is actually in the diff — emit() drops anything inChange() rejects,
    // so anchoring at line 1 would silently discard this finding on most diffs.
    const anchor = changed && changed.size > 0 ? Math.min(...changed) : 1;

    emit({
      loc: { start: { line: anchor, column: 0 }, end: { line: anchor, column: 0 } },
      message: `⚡ Diff spans ${changedCount} lines for ${totalStatements} logic statement${totalStatements === 1 ? "" : "s"} (ratio ${ratio.toFixed(1)}, threshold ${maxChurnRatio}). Check for boilerplate or redundant error handling.`,
    });
  },
};

/**
 * single-caller-abstraction (detector half).
 *
 * Emits optimistically for every new class/interface in the diff; `attachStructuralImpact` then
 * confirms or retracts it using the code graph's caller count. On its own this rule proves nothing,
 * which is why the attach-pass drops every finding it cannot positively confirm — including when no
 * graph is available at all.
 */
export const SingleCallerAbstractionTsAst: TsAstRule = {
  id: "single-caller-abstraction",
  type: "tsast",
  title: "New abstraction with no more than one caller",
  // Inert without a code graph: the detector alone cannot tell a speculative abstraction from a
  // used one, and attachStructuralImpact drops anything it cannot confirm. Opt in with
  // rules: { "single-caller-abstraction": { "enabled": true } } or the "structural" pack.
  enabledByDefault: false,
  tier: "yellow",
  blocking: false,
  languages: ["python", "go", "java", "kotlin", "ruby", "php", "csharp"],
  visit: (node: TsNode, ctx: RuleContext, emit: EmitFn) => {
    const profile = profileFor(ctx.language);
    if (!profile || !profile.classTypes.has(node.type)) return;
    const name = extractTsName(node, profile);
    if (!name) return;
    emit({
      loc: tsLoc(node),
      symbol: name,
      message: `⚡ Speculative abstraction: ${name}`,
    });
  },
};

export const SingleCallerAbstractionAst: AstRule = {
  id: "single-caller-abstraction",
  type: "ast",
  title: "New abstraction with no more than one caller",
  // Inert without a code graph: the detector alone cannot tell a speculative abstraction from a
  // used one, and attachStructuralImpact drops anything it cannot confirm. Opt in with
  // rules: { "single-caller-abstraction": { "enabled": true } } or the "structural" pack.
  enabledByDefault: false,
  tier: "yellow",
  blocking: false,
  languages: ["javascript", "typescript", "jsx", "tsx"],
  visit: (node: AstNode, _parent: AstNode | null, ctx: RuleContext, emit: EmitFn) => {
    if (node.type !== "ClassDeclaration" && node.type !== "TSInterfaceDeclaration") return;
    const name = (node as { id?: { name?: string } }).id?.name;
    if (!name) return;
    emit({
      loc: node.loc,
      symbol: name,
      message: `⚡ Speculative abstraction: ${name}`,
    });
  },
};

// Export arrays for bulk registration in builtin.ts
export const STRUCTURAL_TSAST_RULES: TsAstRule[] = [
  // Phase 1 — universal metrics
  CognitiveComplexityTsAst,
  DeepNestingTsAst,
  LongFunctionTsAst,
  TooManyParametersTsAst,
  // Phase 2 — language-specific anti-patterns
  PyUnnecessaryClassTsAst,
  PyUnnecessaryAbcTsAst,
  GoPrematureInterfaceTsAst,
  JavaSingleImplInterfaceTsAst,
  // Phase 3
  PassThroughWrapperTsAst,
  SingleCallerAbstractionTsAst,
];

export const STRUCTURAL_AST_RULES: AstRule[] = [
  // Phase 1 — universal metrics
  CognitiveComplexityAst,
  DeepNestingAst,
  LongFunctionAst,
  TooManyParametersAst,
  // Phase 2 — language-specific anti-patterns
  TsOverGenericAst,
  // Phase 3
  PassThroughWrapperAst,
  DiffChurnRatioAst,
  SingleCallerAbstractionAst,
];
