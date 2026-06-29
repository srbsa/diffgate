// Ruby AST-precision rules (tree-sitter). Same precision tier and safety posture as the other languages:
// blocking findings fire on local structural evidence, down-tier (never suppress) on a recognized
// sanitizer, and the graph reachability/blast-radius pass composes on top. Ruby specifics:
//   • The dominant injection vector is `#{…}` string interpolation. A `string`/`subshell` node carries
//     `interpolation` children; a value interpolating only a constant (`#{TABLE}`) is static, not input.
//   • ActiveRecord raw-SQL methods (`where`/`find_by_sql`/`order`/…) are FRAGMENT sinks: the method name
//     guarantees SQL context, so a fragment like `"age > #{x}"` (no SELECT keyword) is still injection.
//     The safe forms — placeholder array `where("age > ?", x)` and hash `where(age: x)` — interpolate
//     nothing, so the query string is static and is correctly not flagged.
//   • Ruby runs a single-string command through the shell; the multi-argument form does NOT — so
//     `system("git", "checkout", x)` is safe just like Go's `exec.Command`. Backticks / `%x{}` (`subshell`)
//     always use the shell.
//
// Coverage: sql-injection · command-injection · code-injection · unsafe-deserialization · xss-sink.
// Honest gaps (future): mass-assignment, open-redirect, `render inline:` SSTI, dynamic `send`/`constantize`.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";
import {
  type LanguageProfile,
  unwrap, declInit, isStaticConst, dynamicParts,
  valueSanitized, emitFinding as coreEmitFinding,
} from "./tsast-core.js";

// ActiveRecord raw-SQL methods (fragment sinks — no SQL-keyword gate). A string argument with dynamic
// interpolation is the injection. `select`/`order`/`group`/`joins`/`from` are AR query builders; in their
// string-argument form a dynamic interpolation is SQL injection (Brakeman flags the same set).
const SQL_AR_METHODS = new Set([
  "where", "find_by_sql", "exists?", "having", "order", "group", "joins", "from", "reorder",
  "select", "pluck", "calculate", "find_by", "destroy_by", "delete_by", "where_not",
]);
// Connection-level raw SQL (receiver is a connection/AR base). Always raw SQL.
const SQL_CONN_METHODS = new Set([
  "execute", "exec_query", "exec_update", "exec_delete", "exec_insert",
  "select_all", "select_one", "select_value", "select_values", "select_rows", "query",
]);
// Recognized SQL escapers/quoters (down-tier, never suppress).
const SQL_SANITIZERS = /(?:^|\.)(?:quote|quote_column_name|quote_table_name|sanitize_sql|sanitize_sql_for_conditions|sanitize_sql_array)$/;

// OS-command sinks. Bare Kernel methods, and receiver-qualified families. The single-string form shells;
// the multi-argument / array form does not.
const CMD_BARE = new Set(["system", "exec", "spawn"]);
const CMD_RECV: Record<string, Set<string>> = {
  Kernel: new Set(["system", "exec", "spawn"]),
  Process: new Set(["spawn"]),
  IO: new Set(["popen"]),
  PTY: new Set(["spawn", "getpty"]),
  Open3: new Set(["capture2", "capture2e", "capture3", "popen2", "popen2e", "popen3", "pipeline", "pipeline_r", "pipeline_w", "pipeline_rw", "pipeline_start"]),
};
// `Shellwords.escape(x)` / `Shellwords.shellescape(x)` / `x.shellescape` neutralize a shell argument.
const CMD_SANITIZERS = /(?:^|\.)(?:shellescape)$|Shellwords\.escape$/;

// Dynamic-code-execution sinks. `eval` and the `*_eval` family evaluate a string as Ruby.
const CODE_METHODS = new Set(["eval", "instance_eval", "class_eval", "module_eval"]);

// Unsafe deserialization: receiver → unsafe method names. `YAML.safe_load` is the safe API (not a sink).
const DESER_RECV: Record<string, Set<string>> = {
  Marshal: new Set(["load", "restore"]),
  YAML: new Set(["load", "unsafe_load"]),
  Psych: new Set(["load", "unsafe_load"]),
  Oj: new Set(["load", "object_load"]),
};

// HTML-output sinks (reflected XSS): `raw(x)` helper and `x.html_safe` mark a string un-escaped.
const XSS_HELPERS = new Set(["raw", "html_safe", "safe_concat"]);
// Recognized HTML escapers — wrapping the value neutralizes the injection (down-tier).
const XSS_SANITIZERS = /(?:^|\.)(?:h|html_escape|escape_html|escapeHTML|sanitize|strip_tags)$/;

const INTERP_PARENTS = ["string", "subshell"]; // nodes whose interpolation makes them dynamic

// --- Ruby vocabulary ---------------------------------------------------------

function callParts(node: TsNode): { receiver: TsNode | null; method: string; args: TsNode[] } | null {
  if (node.type !== "call") return null;
  const m = node.childForFieldName("method");
  if (!m) return null;
  const argsNode = node.childForFieldName("arguments");
  return {
    receiver: node.childForFieldName("receiver"),
    method: m.text,
    args: argsNode ? argsNode.namedChildren : [],
  };
}

function isInterpolating(node: TsNode): boolean {
  if (!INTERP_PARENTS.includes(node.type)) return false;
  return node.descendantsOfType("interpolation").length > 0;
}

function interpolatedExprs(node: TsNode): TsNode[] {
  return node.descendantsOfType("interpolation").flatMap((i) => i.namedChildren);
}

function staticText(node: TsNode): string {
  const n = unwrap(node, rubyProfile);
  if (n.type === "string" || n.type === "subshell") {
    return n.descendantsOfType("string_content").map((c) => c.text).join(" ");
  }
  if (n.type === "binary") return n.namedChildren.map(staticText).join(" ");
  return "";
}

export const rubyProfile: LanguageProfile = {
  lang: "ruby",
  parenthesizedType: "parenthesized_statements",
  identifierType: "identifier",
  assignmentType: "assignment",
  staticLiteralTypes: new Set(["integer", "float", "true", "false", "nil", "simple_symbol", "complex", "rational"]),
  stringTypes: new Set(["string", "subshell"]),
  concatTypes: new Set(["binary"]),
  isInterpolating,
  interpolatedExprs,
  staticText,
  enclosingFnTypes: new Set(["method", "singleton_method"]),
  fnNameField: "name",
  callDescendantType: "call",
  recurseNestedConcat: true,
  // A bare `Constant` / `Foo::BAR` reference is a runtime constant, not attacker input → static.
  resolveStaticExtra(n) {
    if (n.type === "constant" || n.type === "scope_resolution") return true;
    return null;
  },
};

// --- shared helpers ----------------------------------------------------------

function emitFinding(
  node: TsNode, ctx: RuleContext, emit: EmitFn,
  opts: { sanitized: boolean; message: string; sanitizedNote: string }
): void {
  coreEmitFinding(node, ctx, emit, rubyProfile, opts);
}

/** A value that builds a string from a dynamic (non-constant) interpolation or concatenation, following
 *  intra-file def-use through a local variable. */
function isDynamicStr(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, rubyProfile);
  if (n.type === "string" || n.type === "subshell") return isInterpolating(n) && dynamicParts(n, root, rubyProfile).length > 0;
  if (n.type === "binary") return dynamicParts(n, root, rubyProfile).length > 0;
  if (n.type === "identifier") {
    const init = declInit(n.text, root, rubyProfile);
    return init ? isDynamicStr(init, root, depth + 1) : false;
  }
  return false;
}

/** A value that is NOT a compile-time constant (used by code/deser/xss where any dynamic value is unsafe). */
function isDynamicValue(node: TsNode, root: TsNode): boolean {
  return !isStaticConst(node, root, rubyProfile);
}

/** A call whose method matches `re` (Ruby's callee is the `method` field, not `function`). */
function callMethodMatches(node: TsNode, re: RegExp): boolean {
  const n = unwrap(node, rubyProfile);
  const c = callParts(n);
  if (!c) return false;
  const full = c.receiver ? `${c.receiver.text}.${c.method}` : c.method;
  return re.test(full) || re.test(c.method);
}

// --- messages ----------------------------------------------------------------

const SQL_MESSAGE =
  "A SQL fragment is built with `#{…}` string interpolation (or concatenation) inside an ActiveRecord/raw " +
  "query method. If any interpolated value is user-controlled, an attacker can read, modify, or delete " +
  "arbitrary data. Use bound parameters — `where(\"age > ?\", x)` or the hash form `where(age: x)` — and " +
  "never interpolate request data into a query string.";
const SQL_SANITIZED =
  "Every dynamic part here is wrapped in a recognized quoter (e.g. `connection.quote`, `sanitize_sql`) — " +
  "likely safe, but quoting is weaker than a bound parameter; verify it covers every value. Down-tiered to review.";

const CMD_MESSAGE =
  "An OS command is built with `#{…}` interpolation and run through the shell (`system \"…\"`, backticks, " +
  "`%x{}`, `IO.popen`, `Open3`, …). If any part is user-controlled, an attacker can run arbitrary commands. " +
  "Pass the command as separate arguments (`system(\"git\", \"checkout\", x)`) — that form does not use a " +
  "shell — or escape each argument with `Shellwords.escape`.";
const CMD_SANITIZED =
  "Every dynamic part here is wrapped in `Shellwords.escape`/`shellescape` — likely safe, but shell escaping " +
  "is brittle; prefer the multi-argument form. Down-tiered from a blocking finding to review.";

const CODE_MESSAGE =
  "A dynamic value is executed as Ruby code (`eval`/`instance_eval`/`class_eval`/`module_eval`). If any part " +
  "is user-controlled this is remote code execution. There is no safe way to escape code — remove the dynamic " +
  "`eval` and dispatch on the value through an allowlist/`case` instead.";

const DESER_MESSAGE =
  "Untrusted data is deserialized with `Marshal.load`/`YAML.load`/`Oj.load`, which can construct arbitrary " +
  "objects and execute code (RCE) on attacker-controlled input. Use a safe format (`JSON.parse`) for untrusted " +
  "data, or `YAML.safe_load` for YAML.";

const XSS_MESSAGE =
  "A dynamic value is marked HTML-safe (`raw(…)` / `.html_safe`), bypassing Rails' auto-escaping. If any part " +
  "is user-controlled, an attacker can inject arbitrary HTML/JavaScript (XSS). Let Rails escape the value " +
  "(plain `<%= %>`), or sanitize it (`sanitize`, `ERB::Util.html_escape`) before marking it safe.";
const XSS_SANITIZED =
  "The value here is wrapped in a recognized HTML escaper (e.g. `sanitize`/`h`) — likely safe, but verify it " +
  "covers every dynamic part and the right context. Down-tiered from a blocking finding to review.";

// --- rules -------------------------------------------------------------------

export const RUBY_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["ruby"],
    message: SQL_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = callParts(node);
      if (!c) return;
      if (!SQL_AR_METHODS.has(c.method) && !SQL_CONN_METHODS.has(c.method)) return;
      const root = ctx.tsTree!.rootNode;
      // Only the SQL fragment is the injection vector — arg0 (or element 0 of an array arg
      // `["age > ?", x]`). Subsequent arguments are BOUND values: `where("id = ?", "#{x}")` is SAFE even
      // though the value interpolates, because the binding escapes it.
      let frag = c.args[0];
      if (!frag) return;
      const u0 = unwrap(frag, rubyProfile);
      if (u0.type === "array") { const first = u0.namedChild(0); if (first) frag = first; }
      if (!isDynamicStr(frag, root)) return;
      let src = frag;
      if (unwrap(src, rubyProfile).type === "identifier") src = declInit(unwrap(src, rubyProfile).text, root, rubyProfile) || src;
      const dyn = dynamicParts(src, root, rubyProfile);
      const sanitized = dyn.length > 0 && dyn.every((d) => callMethodMatches(d, SQL_SANITIZERS));
      emitFinding(node, ctx, emit, { sanitized, message: SQL_MESSAGE, sanitizedNote: SQL_SANITIZED });
    },
  },
  {
    id: "command-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "OS command injection sink",
    languages: ["ruby"],
    message: CMD_MESSAGE,
    sinkQuery: "[(subshell) (call)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      // Backticks / %x{} — always a shell. Flag dynamic interpolation.
      if (node.type === "subshell") {
        if (!isInterpolating(node)) return;
        const dyn = dynamicParts(node, root, rubyProfile);
        const sanitized = dyn.length > 0 && dyn.every((d) => callMethodMatches(d, CMD_SANITIZERS));
        emitFinding(node, ctx, emit, { sanitized, message: CMD_MESSAGE, sanitizedNote: CMD_SANITIZED });
        return;
      }
      const c = callParts(node);
      if (!c) return;
      const recvName = c.receiver ? c.receiver.text : null;
      const isSink = (recvName === null && CMD_BARE.has(c.method)) || (recvName !== null && CMD_RECV[recvName]?.has(c.method));
      if (!isSink) return;
      // Only the SINGLE-string form invokes a shell; the multi-argument / array form does not.
      if (c.args.length !== 1) return;
      const arg0 = c.args[0];
      if (unwrap(arg0, rubyProfile).type === "array") return; // explicit argv → no shell
      if (!isDynamicStr(arg0, root)) return;
      const sanitized = valueSanitized(arg0, root, rubyProfile, (n) => callMethodMatches(n, CMD_SANITIZERS));
      emitFinding(node, ctx, emit, { sanitized, message: CMD_MESSAGE, sanitizedNote: CMD_SANITIZED });
    },
  },
  {
    id: "code-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Dynamic code execution sink",
    languages: ["ruby"],
    message: CODE_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = callParts(node);
      if (!c || !CODE_METHODS.has(c.method)) return;
      // `obj.instance_eval` is a sink; a plain `eval` (no receiver) is too. `foo.eval` on an unrelated
      // object is rare — require the method name, which for eval-family is unambiguous enough.
      const arg0 = c.args[0];
      if (!arg0) return;
      const root = ctx.tsTree!.rootNode;
      if (!isDynamicValue(arg0, root)) return; // eval("1 + 1") on a literal is not injectable
      emitFinding(node, ctx, emit, { sanitized: false, message: CODE_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "unsafe-deserialization",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Unsafe deserialization sink",
    languages: ["ruby"],
    message: DESER_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = callParts(node);
      if (!c || !c.receiver) return;
      if (!DESER_RECV[c.receiver.text]?.has(c.method)) return;
      const arg0 = c.args[0];
      if (!arg0) return;
      const root = ctx.tsTree!.rootNode;
      if (!isDynamicValue(arg0, root)) return; // a literal payload is a fixture, not untrusted input
      emitFinding(node, ctx, emit, { sanitized: false, message: DESER_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "xss-sink",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "XSS sink",
    languages: ["ruby"],
    message: XSS_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = callParts(node);
      if (!c || !XSS_HELPERS.has(c.method)) return;
      const root = ctx.tsTree!.rootNode;
      // `raw(value)` / `safe_concat(value)` mark their ARGUMENT safe; `value.html_safe` marks the RECEIVER.
      const value = c.method === "html_safe" ? c.receiver : c.args[0];
      if (!value) return;
      if (!isDynamicValue(value, root)) return; // a static HTML literal is safe
      const sanitized = valueSanitized(value, root, rubyProfile, (n) => callMethodMatches(n, XSS_SANITIZERS));
      emitFinding(node, ctx, emit, { sanitized, message: XSS_MESSAGE, sanitizedNote: XSS_SANITIZED });
    },
  },
];
