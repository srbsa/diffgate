// Python AST-precision rules (tree-sitter). Mirrors the JS sql-injection AST rule's precision tier:
//   • sink-targeting   — only flag a dynamic SQL string that flows INTO a query sink (.execute,
//                        .executemany, .raw, sqlalchemy text(), …), so a log line that merely
//                        mentions SELECT is never flagged.
//   • static clearing  — an f-string whose every `{…}` resolves to a static constant (a module/local
//                        literal) is NOT user-controlled → not flagged. `f"SELECT … {TABLE}"`.
//   • parameter aware  — a plain placeholder string (`"… WHERE id = %s"`, params passed separately)
//                        is parameterized → not flagged, even though it concatenates nothing.
//   • sanitizer aware  — when every dynamic part is wrapped in a recognized identifier-quoting
//                        sanitizer (psycopg2 `sql.Identifier`, `quote_ident`, …) we DOWN-tier to a
//                        review note rather than blocking. A missed sanitizer keeps it blocking.
//
// Safety posture (identical to the JS rule): blocking orange by default; we only ever DOWN-tier on a
// recognized sanitizer, never suppress. The graph reachability/blast-radius pass composes on top.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";

const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|TRUNCATE|MERGE)\b/i;

// Query sinks: a dynamic SQL string reaching one of these is the injection. Attribute calls
// (`cur.execute`, `qs.raw`, `conn.exec_driver_sql`, `cur.mogrify`) and the SQLAlchemy `text(...)` fn.
const SINK_ATTRS = new Set([
  "execute", "executemany", "executescript", "exec_driver_sql", "raw", "mogrify",
]);
const SINK_FUNCS = new Set(["text"]);

// Recognized identifier/value quoting sanitizers — wrapping every dynamic part in one of these
// neutralizes the injection (down-tier, don't block).
const SANITIZERS = /(?:^|\.)(?:Identifier|SQL|Literal|quote_ident|quote_name|escape_string|quote)$/;

const MAX_RESOLVE_DEPTH = 6;

function lineOf(node: TsNode): number {
  return node.startPosition.row + 1;
}

/** Name of the method/function being called, for sink matching. `cur.execute` → "execute". */
function calleeInfo(call: TsNode): { attr: string | null; func: string | null } {
  const fn = call.childForFieldName("function");
  if (!fn) return { attr: null, func: null };
  if (fn.type === "attribute") {
    const a = fn.childForFieldName("attribute");
    return { attr: a ? a.text : null, func: null };
  }
  if (fn.type === "identifier") return { attr: null, func: fn.text };
  return { attr: null, func: null };
}

function isSink(call: TsNode): boolean {
  const { attr, func } = calleeInfo(call);
  return (attr !== null && SINK_ATTRS.has(attr)) || (func !== null && SINK_FUNCS.has(func));
}

/** Nearest enclosing `def` name, so the graph can look up reachability/blast-radius for the sink. */
function enclosingFunction(node: TsNode): string | null {
  let n: TsNode | null = node.parent;
  while (n) {
    if (n.type === "function_definition") {
      const name = n.childForFieldName("name");
      return name ? name.text : null;
    }
    n = n.parent;
  }
  return null;
}

/** Last value assigned to a bare identifier anywhere in the file (intra-file def-use, like the JS rule). */
function declInit(name: string, root: TsNode): TsNode | null {
  let found: TsNode | null = null;
  for (const assign of root.descendantsOfType("assignment")) {
    const left = assign.childForFieldName("left");
    const right = assign.childForFieldName("right");
    if (left && right && left.type === "identifier" && left.text === name) found = right;
  }
  return found;
}

function unwrap(node: TsNode): TsNode {
  let n = node;
  while (n.type === "parenthesized_expression") {
    const inner = n.namedChild(0);
    if (!inner) break;
    n = inner;
  }
  return n;
}

/** The f-string prefix letters (`f`, `rf`, `F`…) of a string node, or "" for a plain string. */
function stringPrefix(node: TsNode): string {
  return (node.text.match(/^[A-Za-z]*/) || [""])[0];
}

function isFString(node: TsNode): boolean {
  return /f/i.test(stringPrefix(node)) || node.descendantsOfType("interpolation").length > 0;
}

/** The interpolated expression inside an f-string `{…}` placeholder. */
function interpExpr(interp: TsNode): TsNode | null {
  return interp.namedChild(0);
}

/** Static text of a node with interpolations/dynamic parts stripped — for SQL-keyword detection. */
function staticText(node: TsNode): string {
  const n = unwrap(node);
  if (n.type === "string") {
    return n.descendantsOfType("string_content").map((c) => c.text).join(" ");
  }
  if (n.type === "binary_operator" || n.type === "concatenated_string") {
    return n.namedChildren.map(staticText).join(" ");
  }
  if (n.type === "call") {
    const fn = n.childForFieldName("function");
    if (fn && fn.type === "attribute") {
      const obj = fn.childForFieldName("object");
      if (obj) return staticText(obj); // "…".format(x) → the template's static text
    }
  }
  return "";
}

function looksLikeSql(node: TsNode): boolean {
  return SQL_KEYWORDS.test(staticText(node));
}

/** A value that resolves to a literal constant (string/number/bool/None, or an identifier bound to one). */
function isStaticConst(node: TsNode | null, root: TsNode, depth = 0): boolean {
  if (!node || depth > MAX_RESOLVE_DEPTH) return false;
  const n = unwrap(node);
  switch (n.type) {
    case "string":
      return !isFString(n); // a plain literal is static; an f-string may interpolate
    case "integer":
    case "float":
    case "true":
    case "false":
    case "none":
      return true;
    case "binary_operator":
    case "concatenated_string":
      return n.namedChildren.every((c) => isStaticConst(c, root, depth + 1));
    case "identifier": {
      const init = declInit(n.text, root);
      return init ? isStaticConst(init, root, depth + 1) : false;
    }
    default:
      return false;
  }
}

/** The dynamic (non-constant) sub-expressions that get injected into the SQL string. */
function dynamicParts(node: TsNode, root: TsNode, depth = 0): TsNode[] {
  if (depth > MAX_RESOLVE_DEPTH) return [];
  const n = unwrap(node);
  if (n.type === "string" && isFString(n)) {
    return n.descendantsOfType("interpolation")
      .map(interpExpr)
      .filter((e): e is TsNode => !!e && !isStaticConst(e, root));
  }
  if (n.type === "binary_operator") {
    const out: TsNode[] = [];
    for (const c of n.namedChildren) {
      if (c.type === "string" && !isFString(c)) continue; // a plain SQL literal operand is safe
      if (isStaticConst(c, root)) continue;
      if (c.type === "string" && isFString(c)) { out.push(...dynamicParts(c, root, depth + 1)); continue; }
      out.push(c);
    }
    return out;
  }
  if (n.type === "call") {
    // "…{}".format(args) — the format arguments are the injected values.
    const args = n.childForFieldName("arguments");
    if (args) return args.namedChildren.filter((a) => !isStaticConst(a, root));
  }
  if (n.type === "identifier") {
    const init = declInit(n.text, root);
    if (init) return dynamicParts(init, root, depth + 1);
  }
  return [];
}

/** Is `node` (the sink's first argument) a SQL string built from a dynamic, non-constant value? */
function isDynamicSql(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > MAX_RESOLVE_DEPTH) return false;
  const n = unwrap(node);
  if (!looksLikeSql(n)) {
    // An identifier may resolve to a SQL string elsewhere in the file.
    if (n.type === "identifier") {
      const init = declInit(n.text, root);
      return init ? isDynamicSql(init, root, depth + 1) : false;
    }
    return false;
  }
  if (n.type === "string") return isFString(n) && dynamicParts(n, root).length > 0;
  if (n.type === "binary_operator" || n.type === "call" || n.type === "concatenated_string") {
    return dynamicParts(n, root).length > 0;
  }
  if (n.type === "identifier") {
    const init = declInit(n.text, root);
    return init ? isDynamicSql(init, root, depth + 1) : false;
  }
  return false;
}

/** A call node that is itself a recognized sanitizer (psycopg2 `sql.Identifier(x)`, `quote_ident(x)`). */
function isSanitizerCall(node: TsNode): boolean {
  const n = unwrap(node);
  if (n.type !== "call") return false;
  const fn = n.childForFieldName("function");
  return !!fn && SANITIZERS.test(fn.text);
}

const MESSAGE =
  "A SQL query is assembled from a dynamic value (f-string, concatenation, or `.format`) rather than " +
  "a parameterized query. If any interpolated value is user-controlled, an attacker can read, modify, " +
  "or delete arbitrary data. Pass values as query parameters instead — e.g. " +
  "`cur.execute(\"… WHERE id = %s\", (uid,))` — and never build SQL from request data.";

function sanitizedNote(): string {
  return (
    "Every dynamic part here is wrapped in a recognized identifier/value quoter (e.g. " +
    "`psycopg2.sql.Identifier`) — likely safe, but verify it neutralizes every value on this path. " +
    "Down-tiered from a blocking finding to review."
  );
}

export const PYTHON_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["python"],
    message: MESSAGE,
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call" || !isSink(node)) return;
      const args = node.childForFieldName("arguments");
      const a0 = args ? args.namedChild(0) : null;
      if (!a0) return;
      const root = ctx.tsTree!.rootNode;
      if (!isDynamicSql(a0, root)) return;

      const dyn = dynamicParts(unwrap(a0).type === "identifier" ? (declInit(unwrap(a0).text, root) || a0) : a0, root);
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
    },
  },
];
