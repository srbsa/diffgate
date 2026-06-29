// Kotlin AST-precision rules (tree-sitter). Kotlin runs on the JVM, so the sink vocabulary is largely
// shared with Java (JDBC, Runtime.exec/ProcessBuilder, ObjectInputStream). Kotlin specifics:
//   • Kotlin HAS string templates — `"… $x …"` (simple) and `"… ${expr} …"` (braced) — so a dynamic
//     query/command is built by a template, `+` concatenation, or `String.format`. A plain literal is static.
//   • The community grammar (@tree-sitter-grammars/tree-sitter-kotlin) is FIELD-LESS on calls/navigation,
//     and represents a simple `$x` template as `string_content "$"` + `string_content "x"` (only braced
//     `${…}` produces an `interpolation` node). This file uses positional helpers and handles both forms.
//
// Coverage: sql-injection · command-injection · unsafe-deserialization · path-traversal.
// Honest gaps (future): XSS (Android WebView/templating), Android SQLite specifics beyond rawQuery/execSQL,
// XXE, SSRF, Ktor-specific request sources beyond the common ones.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";
import {
  type LanguageProfile,
  unwrap, declInit, isStaticConst, dynamicParts, looksLikeSql,
  taintedByRequest as coreTaintedByRequest, emitFinding as coreEmitFinding,
} from "./tsast-core.js";

// SQL sinks that GUARANTEE query context (no keyword gate). JDBC + JPA/Hibernate + Android SQLite.
const SQL_FRAGMENT_METHODS = new Set([
  "executeQuery", "executeUpdate", "executeLargeUpdate", "prepareStatement", "prepareCall",
  "createQuery", "createNativeQuery", "createSQLQuery", "rawQuery", "execSQL",
]);
// Generic-named SQL sinks — require a SQL keyword to fire.
const SQL_KEYWORD_METHODS = new Set(["execute", "update", "query", "queryForObject", "queryForList"]);

// Command-execution sinks (method names): `Runtime…exec(...)`, `ProcessBuilder(...)`.
const CMD_METHODS = new Set(["exec", "ProcessBuilder"]);

// Native deserialization (JVM): `…readObject()` / `…readUnshared()` on a receiver.
const DESER_METHODS = new Set(["readObject", "readUnshared"]);

// Filesystem sinks: constructor-style calls and static methods (path = arg0).
const PT_CTORS = new Set(["File", "FileInputStream", "FileReader", "FileOutputStream", "FileWriter", "RandomAccessFile"]);
const PT_METHODS = new Set(["readAllBytes", "readAllLines", "newInputStream", "newBufferedReader", "get", "readText", "readBytes"]);
// Untrusted request data: servlet / Spring MVC / Ktor.
const KT_REQUEST_SOURCE = /\.getParameter\s*\(|\.getHeader\s*\(|\.getQueryString\s*\(|\.queryParameters\b|\bcall\.parameters\b|@RequestParam\b|@PathVariable\b/;
// `FilenameUtils.getName(...)` strips directory components (down-tier). The `File(...).name` PROPERTY form
// is a navigation, not a call, so it isn't detected here — such a path stays an advisory (never blocks).
const PT_SANITIZERS = /^getName$/;

const SIMPLE_VAR = /^[A-Za-z_]\w*$/;

// --- Kotlin vocabulary (field-less — positional access) ----------------------

/** `{receiver, method, args}` of a `call_expression`, or null. The callee is the first named child:
 *  a `navigation_expression` (`a.b(...)` → receiver=a, method=b) or a bare `identifier` (`File(...)`). */
function ktCall(node: TsNode): { receiver: TsNode | null; method: string; args: TsNode[] } | null {
  if (node.type !== "call_expression") return null;
  const callee = node.namedChild(0);
  if (!callee) return null;
  let receiver: TsNode | null = null;
  let method: string | null = null;
  if (callee.type === "navigation_expression") {
    const kids = callee.namedChildren;
    receiver = kids[0] ?? null;
    method = kids.length > 1 ? kids[kids.length - 1].text : null;
  } else if (callee.type === "identifier") {
    method = callee.text;
  } else return null;
  if (!method) return null;
  const va = node.namedChildren.find((c) => c.type === "value_arguments");
  const args = va ? va.namedChildren.map((a) => (a.type === "value_argument" ? a.namedChild(0) : a)).filter((a): a is TsNode => !!a) : [];
  return { receiver, method, args };
}

function isInterpolating(node: TsNode): boolean {
  if (node.type !== "string_literal") return false;
  if (node.descendantsOfType("interpolation").length > 0) return true; // braced ${…}
  return /\$[A-Za-z_{]/.test(node.text); // simple $var
}

function interpolatedExprs(node: TsNode): TsNode[] {
  const out: TsNode[] = [];
  for (const interp of node.descendantsOfType("interpolation")) out.push(...interp.namedChildren); // ${expr}
  const cs = node.descendantsOfType("string_content");
  for (let i = 0; i < cs.length - 1; i++) {
    if (cs[i].text === "$" && SIMPLE_VAR.test(cs[i + 1].text)) out.push(cs[i + 1]); // simple $var → the name node
  }
  return out;
}

function staticText(node: TsNode): string {
  const n = unwrap(node, kotlinProfile);
  if (n.type === "string_literal") return n.descendantsOfType("string_content").filter((c) => c.text !== "$").map((c) => c.text).join(" ");
  if (n.type === "binary_expression") return n.namedChildren.map(staticText).join(" ");
  return "";
}

export const kotlinProfile: LanguageProfile = {
  lang: "kotlin",
  parenthesizedType: "parenthesized_expression",
  identifierType: "identifier",
  assignmentType: ["property_declaration", "assignment"],
  declNameWrapper: "variable_declaration",
  staticLiteralTypes: new Set(["integer_literal", "real_literal", "long_literal", "hex_literal", "bin_literal", "boolean_literal", "null_literal", "character_literal"]),
  stringTypes: new Set(["string_literal"]),
  concatTypes: new Set(["binary_expression"]),
  isInterpolating,
  interpolatedExprs,
  staticText,
  enclosingFnTypes: new Set(["function_declaration"]),
  fnNameField: "name",
  callDescendantType: "call_expression",
  recurseNestedConcat: true,
  // A simple `$name` template is represented as a `string_content` holding the name — resolve it through
  // intra-file def-use so `"… $CONST"` (a `val CONST = "…"`) clears as static and `"… $id"` (a param) does not.
  resolveStaticExtra(n, root, recurse) {
    if (n.type === "string_content" && SIMPLE_VAR.test(n.text)) {
      const init = declInit(n.text, root, kotlinProfile);
      return init ? recurse(init) : false;
    }
    return null;
  },
};

// --- shared helpers ----------------------------------------------------------

function emitFinding(
  node: TsNode, ctx: RuleContext, emit: EmitFn,
  opts: { sanitized: boolean; message: string; sanitizedNote: string }
): void {
  coreEmitFinding(node, ctx, emit, kotlinProfile, opts);
}

/** A value that builds a string from a dynamic template / concatenation, following intra-file def-use. */
function isDynamicStr(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, kotlinProfile);
  if (n.type === "string_literal") return isInterpolating(n) && dynamicParts(n, root, kotlinProfile).length > 0;
  if (n.type === "binary_expression") return dynamicParts(n, root, kotlinProfile).length > 0;
  if (n.type === "identifier") {
    const init = declInit(n.text, root, kotlinProfile);
    return init ? isDynamicStr(init, root, depth + 1) : false;
  }
  return false;
}

function taintedByRequest(node: TsNode, root: TsNode): boolean {
  return coreTaintedByRequest(node, root, kotlinProfile, KT_REQUEST_SOURCE);
}

/** True when every request-source reference in `node` sits inside a recognized path sanitizer call.
 *  (Hand-rolled because the field-less grammar can't use the shared `requestSanitized`.) */
function pathSanitized(node: TsNode, root: TsNode): boolean {
  const n = unwrap(node, kotlinProfile);
  if (!KT_REQUEST_SOURCE.test(n.text)) return false;
  let remaining = n.text;
  let sawSanitizer = false;
  const calls = n.type === "call_expression" ? [n, ...n.descendantsOfType("call_expression")] : n.descendantsOfType("call_expression");
  for (const c of calls) {
    const info = ktCall(c);
    if (info && PT_SANITIZERS.test(info.method)) { sawSanitizer = true; remaining = remaining.split(c.text).join(" "); }
  }
  return sawSanitizer && !KT_REQUEST_SOURCE.test(remaining);
}

// --- messages ----------------------------------------------------------------

const SQL_MESSAGE =
  "A SQL query is assembled with a string template (`\"… $x\"`/`\"… ${expr}\"`), concatenation, or " +
  "`String.format` rather than a parameterized statement. If any value is user-controlled, an attacker can " +
  "read, modify, or delete arbitrary data. Use a `PreparedStatement` with `?` placeholders (or named JPA " +
  "parameters) and bind the values; never build SQL from request data.";

const CMD_MESSAGE =
  "An OS command is built from a dynamic value (string template / concatenation) and passed to " +
  "`Runtime.exec`/`ProcessBuilder`. If any part is user-controlled, an attacker can run arbitrary commands. " +
  "Pass a fixed program with arguments as separate elements, validate against an allowlist, and never build " +
  "a command line from request data.";

const DESER_MESSAGE =
  "Untrusted data is deserialized with Java native serialization (`ObjectInputStream.readObject`). " +
  "Deserializing attacker-controlled bytes enables gadget-chain RCE. Avoid native serialization for " +
  "untrusted input — use a data format (JSON) with a strict type allowlist, or set an `ObjectInputFilter`.";

const PT_MESSAGE =
  "A filesystem path is built from request data (`getParameter`/`@RequestParam`/Ktor `call.parameters`/…) " +
  "and passed to a file sink (`File(...)`/`Files.readAllBytes`/…) without containment. An attacker can read " +
  "or write arbitrary files via `../../etc/passwd`. Reduce the path with `FilenameUtils.getName`, or resolve " +
  "it under a fixed base directory and verify it stays within; never open a request path directly.";
const PT_SANITIZED =
  "The request value here is reduced with `FilenameUtils.getName`, which strips directory traversal — likely " +
  "safe, but confirm it actually contains the path. Down-tiered from a blocking finding to review.";

// --- rules -------------------------------------------------------------------

export const KOTLIN_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["kotlin"],
    message: SQL_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = ktCall(node);
      if (!c) return;
      const fragment = SQL_FRAGMENT_METHODS.has(c.method);
      const keyworded = SQL_KEYWORD_METHODS.has(c.method);
      if (!fragment && !keyworded) return;
      const root = ctx.tsTree!.rootNode;
      const arg0 = c.args[0];
      if (!arg0 || !isDynamicStr(arg0, root)) return;
      let src = arg0;
      if (unwrap(src, kotlinProfile).type === "identifier") src = declInit(unwrap(src, kotlinProfile).text, root, kotlinProfile) || src;
      if (keyworded && !fragment && !looksLikeSql(unwrap(src, kotlinProfile), kotlinProfile)) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: SQL_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "command-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "OS command injection sink",
    languages: ["kotlin"],
    message: CMD_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = ktCall(node);
      if (!c || !CMD_METHODS.has(c.method)) return;
      const root = ctx.tsTree!.rootNode;
      if (!c.args.some((a) => isDynamicStr(a, root) || taintedByRequest(a, root))) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: CMD_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "unsafe-deserialization",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Unsafe deserialization sink",
    languages: ["kotlin"],
    message: DESER_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = ktCall(node);
      if (!c || !DESER_METHODS.has(c.method) || !c.receiver) return; // require a receiver (ois.readObject())
      emitFinding(node, ctx, emit, { sanitized: false, message: DESER_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "path-traversal",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Path traversal sink",
    languages: ["kotlin"],
    message: PT_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = ktCall(node);
      if (!c) return;
      const isSink = (c.receiver === null && PT_CTORS.has(c.method)) || PT_METHODS.has(c.method);
      if (!isSink) return;
      const root = ctx.tsTree!.rootNode;
      const tainted = c.args.find((a) => taintedByRequest(a, root));
      if (!tainted) return;
      const sanitized = pathSanitized(tainted, root);
      emitFinding(node, ctx, emit, { sanitized, message: PT_MESSAGE, sanitizedNote: PT_SANITIZED });
    },
  },
];
