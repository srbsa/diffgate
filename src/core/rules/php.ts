// PHP AST-precision rules (tree-sitter). Same precision tier and safety posture as the Python and JS
// sql-injection rules: blocking orange on local evidence, down-tier only on a recognized sanitizer,
// never suppress. PHP specifics that the regex candidate can't get right:
//   • single-quoted strings DON'T interpolate — `'… WHERE id = $id'` is the literal text `$id`, not
//     an injection. Only double-quoted (`encapsed_string`) and heredoc interpolate.
//   • a prepared statement with a placeholder (`->prepare("… = ?")`) is safe; the same call with an
//     interpolated value (`->prepare("… = $id")`) is the anti-pattern — sink-targeting catches both
//     correctly because one has an interpolated variable and the other does not.
//   • `(int)$id` / `intval($id)` and the escapers (`mysqli_real_escape_string`, `$pdo->quote`) are
//     recognized sanitizers → down-tier, not block.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";

const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|MERGE)\b/i;

// Query sinks. Function-style (`mysqli_query($conn, $sql)`, `pg_query($sql)`) and method/static-style
// (`$pdo->query($sql)`, `$wpdb->get_results($sql)`, `DB::statement($sql)`).
const SINK_FUNCS = new Set([
  "mysqli_query", "mysql_query", "mysqli_multi_query", "mysqli_real_query",
  "pg_query", "pg_send_query", "sqlite_query", "sqlite_unbuffered_query", "mssql_query",
]);
const SINK_METHODS = new Set([
  "query", "exec", "prepare", "multi_query", "real_query", "unprepared", "statement", "raw",
  "get_results", "get_var", "get_row", "get_col",
]);

// Recognized value sanitizers/escapers; an int/float cast is also a complete defense.
const SANITIZER_FUNCS = /(?:^|\\)(?:mysqli_real_escape_string|mysql_real_escape_string|pg_escape_string|pg_escape_literal|pg_escape_identifier|addslashes|intval|floatval|quote)$/i;
const SAFE_CASTS = new Set(["(int)", "(integer)", "(float)", "(double)", "(real)", "(bool)", "(boolean)"]);

// Tree-sitter-php node types that represent an interpolated value inside a double-quoted/heredoc string.
const INTERP_TYPES = ["variable_name", "member_access_expression", "subscript_expression", "nullsafe_member_access_expression", "scoped_property_access_expression"];

const MAX_RESOLVE_DEPTH = 6;

function lineOf(node: TsNode): number {
  return node.startPosition.row + 1;
}

/** Method/function name a call node targets, for sink matching. */
function callName(call: TsNode): string | null {
  if (call.type === "function_call_expression") {
    const fn = call.childForFieldName("function");
    return fn ? fn.text.replace(/^\\/, "") : null;
  }
  if (call.type === "member_call_expression" || call.type === "nullsafe_member_call_expression" || call.type === "scoped_call_expression") {
    const n = call.childForFieldName("name");
    return n ? n.text : null;
  }
  return null;
}

function isSink(call: TsNode): boolean {
  const name = callName(call);
  if (!name) return false;
  if (call.type === "function_call_expression") return SINK_FUNCS.has(name.toLowerCase());
  return SINK_METHODS.has(name);
}

/** The argument expressions of a call (unwrapping `argument` nodes). */
function callArgs(call: TsNode): TsNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  return args.namedChildren.map((a) => (a.type === "argument" ? a.namedChild(0) : a)).filter((a): a is TsNode => !!a);
}

/** Nearest enclosing function/method name, for the graph reachability/blast-radius lookup. */
function enclosingFunction(node: TsNode): string | null {
  let n: TsNode | null = node.parent;
  while (n) {
    if (n.type === "function_definition" || n.type === "method_declaration") {
      const name = n.childForFieldName("name");
      return name ? name.text : null;
    }
    n = n.parent;
  }
  return null;
}

/** Last value assigned to a `$var` anywhere in the file (intra-file def-use). */
function declInit(varText: string, root: TsNode): TsNode | null {
  let found: TsNode | null = null;
  for (const assign of root.descendantsOfType("assignment_expression")) {
    const left = assign.childForFieldName("left");
    const right = assign.childForFieldName("right");
    if (left && right && left.type === "variable_name" && left.text === varText) found = right;
  }
  return found;
}

/** A double-quoted/heredoc string with at least one interpolated variable/member/subscript. */
function isInterpolating(node: TsNode): boolean {
  if (node.type !== "encapsed_string" && node.type !== "heredoc") return false;
  return node.descendantsOfType(INTERP_TYPES).length > 0;
}

function interpolatedExprs(node: TsNode): TsNode[] {
  return node.descendantsOfType(INTERP_TYPES);
}

function staticText(node: TsNode): string {
  if (node.type === "encapsed_string" || node.type === "heredoc") {
    // Drop interpolations so SQL-keyword detection sees only the literal template text.
    return node.text.replace(/\{[^}]*\}/g, " ").replace(/\$[A-Za-z_][\w]*(?:->\w+|\[[^\]]*\])?/g, " ");
  }
  if (node.type === "binary_expression") {
    return node.namedChildren.map(staticText).join(" ");
  }
  return node.text; // single-quoted string / other literal
}

function looksLikeSql(node: TsNode): boolean {
  return SQL_KEYWORDS.test(staticText(node));
}

function isStaticConst(node: TsNode | null, root: TsNode, depth = 0): boolean {
  if (!node || depth > MAX_RESOLVE_DEPTH) return false;
  switch (node.type) {
    case "string":
    case "integer":
    case "float":
    case "boolean":
      return true;
    case "encapsed_string":
    case "heredoc":
      return !isInterpolating(node);
    case "binary_expression":
      return node.namedChildren.every((c) => isStaticConst(c, root, depth + 1));
    case "variable_name": {
      const init = declInit(node.text, root);
      return init ? isStaticConst(init, root, depth + 1) : false;
    }
    default:
      return false;
  }
}

function dynamicParts(node: TsNode, root: TsNode, depth = 0): TsNode[] {
  if (depth > MAX_RESOLVE_DEPTH) return [];
  if ((node.type === "encapsed_string" || node.type === "heredoc") && isInterpolating(node)) {
    return interpolatedExprs(node).filter((e) => !isStaticConst(e, root));
  }
  if (node.type === "binary_expression") {
    const out: TsNode[] = [];
    for (const c of node.namedChildren) {
      if (c.type === "string") continue; // single-quoted literal operand is safe
      if ((c.type === "encapsed_string" || c.type === "heredoc") && !isInterpolating(c)) continue;
      if (isStaticConst(c, root)) continue;
      // Recurse into nested concatenations and interpolations to reach the actual dynamic leaves —
      // `"a" . esc($x) . "b"` parses left-associative, so the escaper is nested one level down.
      if (c.type === "binary_expression" || ((c.type === "encapsed_string" || c.type === "heredoc") && isInterpolating(c))) {
        out.push(...dynamicParts(c, root, depth + 1));
        continue;
      }
      out.push(c);
    }
    return out;
  }
  if (node.type === "variable_name") {
    const init = declInit(node.text, root);
    if (init) return dynamicParts(init, root, depth + 1);
  }
  return [];
}

function isDynamicSql(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > MAX_RESOLVE_DEPTH) return false;
  if (!looksLikeSql(node)) {
    if (node.type === "variable_name") {
      const init = declInit(node.text, root);
      return init ? isDynamicSql(init, root, depth + 1) : false;
    }
    return false;
  }
  if (node.type === "string") return false; // single-quoted: literal, never interpolates
  if (node.type === "encapsed_string" || node.type === "heredoc") return isInterpolating(node) && dynamicParts(node, root).length > 0;
  if (node.type === "binary_expression") return dynamicParts(node, root).length > 0;
  if (node.type === "variable_name") {
    const init = declInit(node.text, root);
    return init ? isDynamicSql(init, root, depth + 1) : false;
  }
  return false;
}

/** A node that neutralizes its value: an escaper/quoter call, or an int/float cast. */
function isSanitizerCall(node: TsNode): boolean {
  if (node.type === "cast_expression") {
    const t = node.childForFieldName("type");
    return !!t && SAFE_CASTS.has(`(${t.text})`);
  }
  if (node.type === "function_call_expression") {
    const fn = node.childForFieldName("function");
    return !!fn && SANITIZER_FUNCS.test(fn.text);
  }
  if (node.type === "member_call_expression" || node.type === "scoped_call_expression") {
    const n = node.childForFieldName("name");
    return !!n && /^quote$/i.test(n.text); // $pdo->quote(...) / PDO::quote(...)
  }
  return false;
}

const MESSAGE =
  "A SQL query is assembled from an interpolated or concatenated value rather than a parameterized " +
  "query. If any interpolated value is user-controlled, an attacker can read, modify, or delete " +
  "arbitrary data. Use a prepared statement with bound parameters — e.g. " +
  "`$stmt = $pdo->prepare(\"… WHERE id = ?\"); $stmt->execute([$id]);` — and never build SQL by " +
  "interpolating request data into a double-quoted string.";

function sanitizedNote(): string {
  return (
    "Every dynamic part here is wrapped in a recognized escaper/cast (e.g. `mysqli_real_escape_string`, " +
    "`(int)`) — likely safe, but escaping is weaker than a bound parameter; verify it covers every " +
    "value and context. Down-tiered from a blocking finding to review."
  );
}

function emitIfSink(node: TsNode, root: TsNode, ctx: RuleContext, emit: EmitFn): void {
  const isCall = node.type === "function_call_expression" || node.type === "member_call_expression" ||
    node.type === "nullsafe_member_call_expression" || node.type === "scoped_call_expression";
  if (isCall && isSink(node)) {
    const dynamicArg = callArgs(node).find((a) => isDynamicSql(a, root));
    if (dynamicArg) {
      let src = dynamicArg;
      if (src.type === "variable_name") src = declInit(src.text, root) || src;
      const dyn = dynamicParts(src, root);
      const sanitized = dyn.length > 0 && dyn.every(isSanitizerCall);
      const line = lineOf(node);
      const loc = {
        start: { line, column: node.startPosition.column },
        end: { line: node.endPosition.row + 1, column: node.endPosition.column },
      };
      const code = (ctx.lines[line - 1] || "").trim();
      const symbol = enclosingFunction(node);
      emit(
        sanitized
          ? { loc, code, symbol, tier: "yellow", blocking: false, tierAdjusted: "deescalated", message: `${MESSAGE}\n\n${sanitizedNote()}` }
          : { loc, code, symbol }
      );
    }
  }
}

export const PHP_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["php"],
    message: MESSAGE,
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      emitIfSink(node, ctx.tsTree!.rootNode, ctx, emit);
    },
  },
];
