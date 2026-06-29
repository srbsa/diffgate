// Shared tree-sitter rule engine. Python and PHP (and future languages) re-implement the SAME
// data-flow algorithm — static-constant resolution across intra-file def-use, dynamic-part
// extraction, sanitizer-aware down-tiering, request-taint following — over a DIFFERENT node
// vocabulary. This module factors that algorithm out once, parameterized by a `LanguageProfile`
// that supplies only the per-language vocabulary and the genuinely-irreducible predicates
// (PHP single-quote-doesn't-interpolate, Python f-string, magic constants, …).
//
// The precision logic lives HERE and stays imperative: tree-sitter S-expression queries can match
// structure but cannot resolve an identifier to its declaration and ask "is THAT a static
// constant?" — which is exactly what lets these rules block without false positives. Queries are
// used only for the cheap sink-discovery layer (see `sinkQuery` in rules/index.ts).

import type { TsNode, RuleContext, EmitFn, FindingEmitArg, Tier } from "../types.js";

export const MAX_RESOLVE_DEPTH = 6;

/** SQL keywords used by `looksLikeSql` — shared across languages (the SQL surface is universal). */
export const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|MERGE)\b/i;

/**
 * Per-language vocabulary + irreducible predicates that adapt the shared engine to one grammar.
 * Everything a new language needs to reach the same precision tier; the security semantics
 * (sink/sanitizer/source name-sets) stay in the language's rule file.
 */
export interface LanguageProfile {
  lang: string;
  /** Node type wrapping a parenthesized expression (stripped by `unwrap`). */
  parenthesizedType: string;
  /** Bare-identifier / variable node type that may resolve to a declaration (`identifier` | `variable_name`). */
  identifierType: string;
  /** Assignment statement node type(s) for intra-file def-use (`assignment` | `assignment_expression`;
   *  Go needs several: `short_var_declaration`, `assignment_statement`, `var_spec`, `const_spec`). */
  assignmentType: string | string[];
  /** List-wrapper node holding the LHS/RHS of a (possibly multi-target) assignment — Go `expression_list`
   *  in `a, b := x, y` and the `value` of a `var`/`const` spec. Absent for languages with a bare LHS. */
  assignmentListType?: string;
  /** Node types that are unconditionally compile-time constants (numbers, bools, null/none). */
  staticLiteralTypes: Set<string>;
  /** String node types whose staticness is CONDITIONAL on `isInterpolating` (plain literal = static). */
  stringTypes: Set<string>;
  /** Concatenation node types whose operands compose (`binary_operator`/`concatenated_string` | `binary_expression`). */
  concatTypes: Set<string>;
  /** Whether a string/concat node carries at least one interpolated dynamic value. */
  isInterpolating(node: TsNode): boolean;
  /** The interpolated sub-expressions inside an interpolating string. */
  interpolatedExprs(node: TsNode): TsNode[];
  /** The literal/template text of a node with interpolations stripped — for SQL-keyword detection. */
  staticText(node: TsNode): string;
  /** Function/method definition node types whose name `enclosingFunction` reports for blast-radius. */
  enclosingFnTypes: Set<string>;
  /** Field name holding a definition's name (`name` for both current grammars). */
  fnNameField: string;
  /** Call node type searched for nested sanitizer calls (`call` | `function_call_expression`). */
  callDescendantType: string;
  /** Field on a call node holding the callee, for sanitizer detection in `requestSanitized`. Defaults to
   *  `"function"` (Python/PHP/Go); Java uses `"name"`. */
  calleeField?: string;
  /** PHP recurses into nested concatenations to reach dynamic leaves; Python pushes the nest whole.
   *  Preserved per-language so a fully-sanitized nested concat down-tiers exactly as it does today. */
  recurseNestedConcat: boolean;
  /** Safe value casts that neutralize a tainted value (PHP `(int)`/`(float)`); absent for languages
   *  without C-style casts. */
  safeCasts?: Set<string>;
  /** Language-unique static-constant cases beyond literals/concat/identifier (PHP magic constants,
   *  `dirname(...)`). Return true/false to decide, or null to fall through to the default (not static). */
  resolveStaticExtra?(node: TsNode, root: TsNode, recurse: (n: TsNode) => boolean): boolean | null;
  /** Language-unique dynamic-part cases beyond interpolation/concat (Python `.format`, PHP `sprintf`).
   *  Return the injected sub-expressions, or null to fall through to identifier resolution. */
  resolveDynamicExtra?(node: TsNode, root: TsNode, recurse: (n: TsNode) => TsNode[]): TsNode[] | null;
}

/** Strip parenthesized-expression wrappers. */
export function unwrap(node: TsNode, p: LanguageProfile): TsNode {
  let n = node;
  while (n.type === p.parenthesizedType) {
    const inner = n.namedChild(0);
    if (!inner) break;
    n = inner;
  }
  return n;
}

export function lineOf(node: TsNode): number {
  return node.startPosition.row + 1;
}

export function mkLoc(node: TsNode) {
  return {
    start: { line: lineOf(node), column: node.startPosition.column },
    end: { line: node.endPosition.row + 1, column: node.endPosition.column },
  };
}

/** Last value assigned to a bare identifier/variable anywhere in the file (intra-file def-use). */
export function declInit(name: string, root: TsNode, p: LanguageProfile): TsNode | null {
  let found: TsNode | null = null;
  const types = Array.isArray(p.assignmentType) ? p.assignmentType : [p.assignmentType];
  for (const t of types) {
    for (const assign of root.descendantsOfType(t)) {
      const v = boundValue(assign, name, p);
      if (v) found = v;
    }
  }
  return found;
}

/** The value bound to `name` by a single assignment-family node, or null. Handles three shapes:
 *  a bare `left`/`right` (Python `assignment`, PHP `assignment_expression`), a list-wrapped `left`/`right`
 *  (Go `a, b := x, y` where both sides are `expression_list`), and a `name`/`value` spec (Go `var x = …`). */
function boundValue(assign: TsNode, name: string, p: LanguageProfile): TsNode | null {
  const left = assign.childForFieldName("left");
  const right = assign.childForFieldName("right");
  if (left && right) {
    if (left.type === p.identifierType && left.text === name) return right;
    if (p.assignmentListType && left.type === p.assignmentListType && right.type === p.assignmentListType) {
      const ls = left.namedChildren, rs = right.namedChildren;
      const i = ls.findIndex((l) => l.type === p.identifierType && l.text === name);
      if (i >= 0 && i < rs.length) return rs[i]; // positional match a,b := x,y
    }
    return null;
  }
  const nm = assign.childForFieldName("name");
  if (nm && nm.type === p.identifierType && nm.text === name) {
    const val = assign.childForFieldName("value");
    if (val) return p.assignmentListType && val.type === p.assignmentListType ? (val.namedChild(0) ?? val) : val;
    // C# `variable_declarator` exposes a `name` field but the initializer is a positional sibling
    // (`q = "a" + id` → [identifier, binary_expression]); take the last named child if it isn't the name.
    const kids = assign.namedChildren;
    const last = kids[kids.length - 1];
    if (last && last.id !== nm.id) return last;
  }
  return null;
}

/** Nearest enclosing function/method name, for the graph reachability/blast-radius lookup. */
export function enclosingFunction(node: TsNode, p: LanguageProfile): string | null {
  let n: TsNode | null = node.parent;
  while (n) {
    if (p.enclosingFnTypes.has(n.type)) {
      const name = n.childForFieldName(p.fnNameField);
      return name ? name.text : null;
    }
    n = n.parent;
  }
  return null;
}

/** A value that resolves to a compile-time constant (literal, static concat, or an identifier bound
 *  to one), following intra-file def-use. */
export function isStaticConst(node: TsNode | null, root: TsNode, p: LanguageProfile, depth = 0): boolean {
  if (!node || depth > MAX_RESOLVE_DEPTH) return false;
  const n = unwrap(node, p);
  if (p.staticLiteralTypes.has(n.type)) return true;
  if (p.stringTypes.has(n.type)) return !p.isInterpolating(n); // plain literal = static; interpolating = dynamic
  if (p.concatTypes.has(n.type)) return n.namedChildren.every((c) => isStaticConst(c, root, p, depth + 1));
  if (n.type === p.identifierType) {
    const init = declInit(n.text, root, p);
    return init ? isStaticConst(init, root, p, depth + 1) : false;
  }
  const extra = p.resolveStaticExtra?.(n, root, (x) => isStaticConst(x, root, p, depth + 1));
  if (extra !== undefined && extra !== null) return extra;
  return false;
}

/** The dynamic (non-constant) sub-expressions interpolated/concatenated into a string-building value. */
export function dynamicParts(node: TsNode, root: TsNode, p: LanguageProfile, depth = 0): TsNode[] {
  if (depth > MAX_RESOLVE_DEPTH) return [];
  const n = unwrap(node, p);
  if (p.stringTypes.has(n.type) && p.isInterpolating(n)) {
    return p.interpolatedExprs(n).filter((e) => !isStaticConst(e, root, p));
  }
  if (p.concatTypes.has(n.type)) {
    const out: TsNode[] = [];
    for (const c of n.namedChildren) {
      if (p.stringTypes.has(c.type) && !p.isInterpolating(c)) continue; // plain literal operand is safe
      if (isStaticConst(c, root, p)) continue;
      const nestedConcat = p.recurseNestedConcat && p.concatTypes.has(c.type);
      const interpStr = p.stringTypes.has(c.type) && p.isInterpolating(c);
      if (nestedConcat || interpStr) {
        out.push(...dynamicParts(c, root, p, depth + 1));
        continue;
      }
      out.push(c);
    }
    return out;
  }
  const extra = p.resolveDynamicExtra?.(n, root, (x) => dynamicParts(x, root, p, depth + 1));
  if (extra !== undefined && extra !== null) return extra;
  if (n.type === p.identifierType) {
    const init = declInit(n.text, root, p);
    if (init) return dynamicParts(init, root, p, depth + 1);
  }
  return [];
}

/** True when the node's static text contains a SQL keyword (resolving identifiers via `staticText`). */
export function looksLikeSql(node: TsNode, p: LanguageProfile): boolean {
  return SQL_KEYWORDS.test(p.staticText(node));
}

/** True when an expression (resolving identifiers intra-file) carries data matching `sourceRe`. */
export function taintedByRequest(node: TsNode, root: TsNode, p: LanguageProfile, sourceRe: RegExp, depth = 0): boolean {
  if (depth > MAX_RESOLVE_DEPTH) return false;
  const n = unwrap(node, p);
  if (sourceRe.test(n.text)) return true; // covers inline subgroups: `"x" . $_GET['a']`
  if (n.type === p.identifierType) {
    const init = declInit(n.text, root, p);
    return init ? taintedByRequest(init, root, p, sourceRe, depth + 1) : false;
  }
  return false;
}

/** Generic "is this whole value neutralized by a recognized sanitizer" check, parameterized by a
 *  per-class predicate. Handles a top-level sanitizer call plus nested concatenation; never hides a
 *  raw value (a mix of escaped + raw stays unsanitized). */
export function valueSanitized(
  node: TsNode, root: TsNode, p: LanguageProfile, pred: (n: TsNode) => boolean, depth = 0
): boolean {
  if (depth > MAX_RESOLVE_DEPTH) return false;
  const n = unwrap(node, p);
  if (pred(n)) return true;
  if (n.type === p.identifierType) {
    const init = declInit(n.text, root, p);
    return init ? valueSanitized(init, root, p, pred, depth + 1) : false;
  }
  const dyn = dynamicParts(n, root, p);
  return dyn.length > 0 && dyn.every((d) => valueSanitized(d, root, p, pred, depth + 1));
}

/** True when EVERY value matching `sourceRe` reaching here is wrapped in a recognized sanitizer:
 *  strike out the sanitizer-call (and safe-cast) subtrees, then check no raw source remains. A mix
 *  of sanitized + raw stays blocking. Used for request-tainted sinks (XSS, path). */
export function requestSanitized(
  node: TsNode, root: TsNode, p: LanguageProfile, sourceRe: RegExp, sanitizerRe: RegExp, depth = 0
): boolean {
  if (depth > MAX_RESOLVE_DEPTH) return false;
  const n = unwrap(node, p);
  if (n.type === p.identifierType) {
    const init = declInit(n.text, root, p);
    return init ? requestSanitized(init, root, p, sourceRe, sanitizerRe, depth + 1) : false;
  }
  if (!sourceRe.test(n.text)) return false; // nothing to sanitize
  let remaining = n.text;
  let sawSanitizer = false;
  const calls = n.type === p.callDescendantType
    ? [n, ...n.descendantsOfType(p.callDescendantType)]
    : n.descendantsOfType(p.callDescendantType);
  for (const call of calls) {
    const fn = call.childForFieldName(p.calleeField ?? "function");
    if (fn && sanitizerRe.test(fn.text)) { sawSanitizer = true; remaining = remaining.split(call.text).join(" "); }
  }
  if (p.safeCasts) {
    for (const cast of n.descendantsOfType("cast_expression")) {
      const t = cast.childForFieldName("type");
      if (t && p.safeCasts.has(`(${t.text})`)) { sawSanitizer = true; remaining = remaining.split(cast.text).join(" "); }
    }
  }
  return sawSanitizer && !sourceRe.test(remaining);
}

/** Emit a finding, down-tiering to a non-blocking review note when `sanitized`. Never suppresses. */
export function emitFinding(
  node: TsNode, ctx: RuleContext, emit: EmitFn, p: LanguageProfile,
  opts: { sanitized: boolean; message: string; sanitizedNote: string }
): void {
  const loc = mkLoc(node);
  const code = (ctx.lines[lineOf(node) - 1] || "").trim();
  const symbol = enclosingFunction(node, p);
  const base: FindingEmitArg = { loc, code, symbol };
  if (opts.sanitized) {
    emit({ ...base, tier: "yellow" as Tier, blocking: false, tierAdjusted: "deescalated", message: `${opts.message}\n\n${opts.sanitizedNote}` });
  } else {
    emit({ ...base, message: opts.message });
  }
}
