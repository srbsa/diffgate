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
//
// The data-flow algorithm (static-const resolution, dynamic-part extraction, def-use, taint) lives in
// `tsast-core`; this file supplies only the Python vocabulary (`pythonProfile`), the Python-specific
// string/sink predicates, and the rule definitions.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";
import {
  type LanguageProfile,
  unwrap, declInit, isStaticConst, dynamicParts, looksLikeSql,
  taintedByRequest as coreTaintedByRequest, requestSanitized, valueSanitized, emitFinding,
} from "./tsast-core.js";

// Query sinks: a dynamic SQL string reaching one of these is the injection. Attribute calls
// (`cur.execute`, `qs.raw`, `conn.exec_driver_sql`, `cur.mogrify`) and the SQLAlchemy `text(...)` fn.
const SINK_ATTRS = new Set([
  "execute", "executemany", "executescript", "exec_driver_sql", "raw", "mogrify",
]);
const SINK_FUNCS = new Set(["text"]);

// Recognized identifier/value quoting sanitizers — wrapping every dynamic part in one of these
// neutralizes the injection (down-tier, don't block).
const SANITIZERS = /(?:^|\.)(?:Identifier|SQL|Literal|quote_ident|quote_name|escape_string|quote)$/;

// --- Python vocabulary -------------------------------------------------------

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
  const n = unwrap(node, pythonProfile);
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

export const pythonProfile: LanguageProfile = {
  lang: "python",
  parenthesizedType: "parenthesized_expression",
  identifierType: "identifier",
  assignmentType: "assignment",
  staticLiteralTypes: new Set(["integer", "float", "true", "false", "none"]),
  stringTypes: new Set(["string"]),
  concatTypes: new Set(["binary_operator", "concatenated_string"]),
  isInterpolating: isFString,
  interpolatedExprs: (node) => node.descendantsOfType("interpolation").map(interpExpr).filter((e): e is TsNode => !!e),
  staticText,
  enclosingFnTypes: new Set(["function_definition"]),
  fnNameField: "name",
  callDescendantType: "call",
  recurseNestedConcat: false, // Python pushes a nested concatenation whole (preserves current behavior)
  // `"…{}".format(args)` — the format arguments are the injected values.
  resolveDynamicExtra(n, root) {
    if (n.type === "call") {
      const args = n.childForFieldName("arguments");
      if (args) return args.namedChildren.filter((a) => !isStaticConst(a, root, pythonProfile));
    }
    return null;
  },
};

// --- SQL injection ----------------------------------------------------------

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

/** Is `node` (the sink's first argument) a SQL string built from a dynamic, non-constant value? */
function isDynamicSql(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, pythonProfile);
  if (!looksLikeSql(n, pythonProfile)) {
    // An identifier may resolve to a SQL string elsewhere in the file.
    if (n.type === "identifier") {
      const init = declInit(n.text, root, pythonProfile);
      return init ? isDynamicSql(init, root, depth + 1) : false;
    }
    return false;
  }
  if (n.type === "string") return isFString(n) && dynamicParts(n, root, pythonProfile).length > 0;
  if (n.type === "binary_operator" || n.type === "call" || n.type === "concatenated_string") {
    return dynamicParts(n, root, pythonProfile).length > 0;
  }
  if (n.type === "identifier") {
    const init = declInit(n.text, root, pythonProfile);
    return init ? isDynamicSql(init, root, depth + 1) : false;
  }
  return false;
}

/** A call node that is itself a recognized sanitizer (psycopg2 `sql.Identifier(x)`, `quote_ident(x)`). */
function isSanitizerCall(node: TsNode): boolean {
  const n = unwrap(node, pythonProfile);
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

// --- XSS (HTML-injection) ---------------------------------------------------
// Mirrors the JS `xss-sink` AST rule for Python's server-side templating idioms: explicitly marking a
// dynamic string safe-for-HTML is the injection. Sink-targeted (the function call that trusts the
// string), dynamic-aware (a fully static literal is safe), and sanitizer-aware (an `escape(...)`-
// wrapped value down-tiers to review). Same safety posture: orange by default, never suppress.
//
//   • mark_safe / Markup           — Django / MarkupSafe: stamp a string as not-to-be-escaped.
//   • render_template_string       — Flask/Jinja: a dynamic template is SSTI *and* XSS.
const XSS_SINK_FUNCS = new Set(["mark_safe", "Markup", "render_template_string"]);

// Recognized HTML/value escapers — wrapping the value neutralizes the injection (down-tier).
const XSS_SANITIZERS = /(?:^|\.)(?:escape|conditional_escape|clean|escape_html|quote|quote_plus)$/;

/** A call to one of the XSS sinks (bare `mark_safe(...)` or attribute `django.utils.safestring.mark_safe(...)`). */
function isXssSink(call: TsNode): boolean {
  const fn = call.childForFieldName("function");
  if (!fn) return false;
  if (fn.type === "identifier") return XSS_SINK_FUNCS.has(fn.text);
  if (fn.type === "attribute") {
    const a = fn.childForFieldName("attribute");
    return !!a && XSS_SINK_FUNCS.has(a.text);
  }
  return false;
}

/** A value that is NOT a compile-time-constant string — i.e. potentially attacker-influenced HTML.
 *  Mirrors the JS rule's `isDynamicString` (anything that isn't a static literal is dynamic). */
function isDynamicHtml(node: TsNode, root: TsNode): boolean {
  return !isStaticConst(node, root, pythonProfile);
}

/** The value (or all of its dynamic parts) is wrapped in a recognized HTML escaper. */
function isXssSanitized(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, pythonProfile);
  if (n.type === "call") {
    const fn = n.childForFieldName("function");
    if (fn && XSS_SANITIZERS.test(fn.text)) return true;
  }
  if (n.type === "identifier") {
    const init = declInit(n.text, root, pythonProfile);
    return init ? isXssSanitized(init, root, depth + 1) : false;
  }
  return false;
}

const XSS_MESSAGE =
  "A dynamic value is marked safe-for-HTML (`mark_safe`/`Markup`) or rendered as a template " +
  "(`render_template_string`) without escaping. If any part is user-controlled, an attacker can inject " +
  "arbitrary HTML/JavaScript (XSS) — or, for a dynamic template, server-side template injection. " +
  "Escape the value (`django.utils.html.escape`, `markupsafe.escape`) before marking it safe, and never " +
  "build a template string from request data.";

function xssSanitizedNote(): string {
  return (
    "The value here is wrapped in a recognized HTML escaper (e.g. `escape`) — likely safe, but verify it " +
    "covers every dynamic part and the right context. Down-tiered from a blocking finding to review."
  );
}

// --- path traversal --------------------------------------------------------
// Mirrors the JS `path-traversal` rule, and improves on it: it is **wrapper-aware** — a request value
// neutralized by `secure_filename`/`basename`/`safe_join` down-tiers to review instead of blocking.
// Sink-targeted (`open`/`send_file`/`send_static_file`) and only fires when the path carries request data.
const PT_REQUEST_SOURCE = /\brequest\.(?:args|form|values|GET|POST|data|json|files|query_params|params)\b/;
const PT_SANITIZERS = /(?:^|\.)(?:secure_filename|basename|safe_join)$/;

/** If `call` is a path-read sink, its argument expressions; else null. `open` only as the builtin
 *  (identifier) — `x.open(...)` on a file object is not a path sink. */
function ptSinkArgs(call: TsNode): TsNode[] | null {
  const fn = call.childForFieldName("function");
  if (!fn) return null;
  let name: string | null = null, viaAttr = false;
  if (fn.type === "identifier") name = fn.text;
  else if (fn.type === "attribute") { const a = fn.childForFieldName("attribute"); name = a ? a.text : null; viaAttr = true; }
  if (!name) return null;
  const ok = (name === "open" && !viaAttr) || name === "send_file" || name === "send_static_file";
  if (!ok) return null;
  const args = call.childForFieldName("arguments");
  return args ? args.namedChildren : [];
}

/** True when an expression (resolving identifiers intra-file) carries HTTP request data. */
function taintedByRequest(node: TsNode, root: TsNode): boolean {
  return coreTaintedByRequest(node, root, pythonProfile, PT_REQUEST_SOURCE);
}

/** True when EVERY request value in the path is wrapped in a recognized sanitizer. */
function pathSanitized(node: TsNode, root: TsNode): boolean {
  return requestSanitized(node, root, pythonProfile, PT_REQUEST_SOURCE, PT_SANITIZERS);
}

const PT_MESSAGE =
  "A file path is built from request-controlled data (`request.args`/`request.GET`/…) and opened " +
  "without containment. An attacker can read or write arbitrary files via `../../etc/passwd`. " +
  "Resolve the path and assert it stays under an allowed base directory, or use " +
  "`werkzeug.utils.safe_join` / `secure_filename`; never open a path built from request data directly.";

function ptSanitizedNote(): string {
  return (
    "The request value here is wrapped in a recognized path sanitizer (e.g. `secure_filename`/`safe_join`) " +
    "— likely safe, but verify it actually contains the path. Down-tiered from a blocking finding to review."
  );
}

// --- permissive CORS -------------------------------------------------------
// Python equivalents of the JS `permissive-cors` rule: flask-cors `CORS(...)`/`@cross_origin()` that
// default to (or explicitly set) any-origin, django-cors-headers' allow-all settings, and a manual
// `Access-Control-Allow-Origin: *` header. Unsafe forms are unambiguous → precise, not coarse.
const CORS_STAR = /["']\*["']/;

/** A flask-cors `CORS(...)` / `cross_origin(...)` call that allows any origin (explicit `*` or the
 *  permissive default — no origin-restricting kwarg at all). */
function corsCallPermissive(call: TsNode): boolean {
  const fn = call.childForFieldName("function");
  let name: string | null = null;
  if (fn?.type === "identifier") name = fn.text;
  else if (fn?.type === "attribute") { const a = fn.childForFieldName("attribute"); name = a ? a.text : null; }
  if (name !== "CORS" && name !== "cross_origin") return false;
  const args = call.childForFieldName("arguments");
  const kwargs = args ? args.namedChildren.filter((a) => a.type === "keyword_argument") : [];
  const originKw = kwargs.find((k) => {
    const n = k.childForFieldName("name");
    return !!n && (n.text === "origins" || n.text === "resources" || n.text === "allow_origins" || n.text === "origin");
  });
  if (!originKw) return true; // bare CORS(app) / cross_origin() → default allows all origins
  const val = originKw.childForFieldName("value");
  return !!val && CORS_STAR.test(val.text); // origins="*" / ["*"] / resources {... "*"}
}

/** A header write that sets `Access-Control-Allow-Origin` to `*` via a method call (`headers.add(...)`). */
function isHeaderStarCall(call: TsNode): boolean {
  const fn = call.childForFieldName("function");
  if (fn?.type !== "attribute") return false;
  const m = fn.childForFieldName("attribute");
  if (!m || !/^(?:add|set|setdefault|append|update|__setitem__)$/.test(m.text)) return false;
  return /access-control-allow-origin/i.test(call.text) && CORS_STAR.test(call.text);
}

const CORS_MESSAGE =
  "CORS is configured to allow any origin (`*`, or the permissive flask-cors / django-cors-headers " +
  "default). If cookies or tokens are used, arbitrary sites can make credentialed cross-origin requests. " +
  "Set an explicit allowlist of trusted origins (`CORS(app, origins=[...])`, `CORS_ALLOWED_ORIGINS=[...]`).";

// --- shared call helpers ----------------------------------------------------

/** First positional argument of a call node, or null. */
function arg0(call: TsNode): TsNode | null {
  const args = call.childForFieldName("arguments");
  return args ? args.namedChild(0) : null;
}

/** The `object`/`attribute` of an attribute-call (`subprocess.run` → {obj:"subprocess", attr:"run"}). */
function attrCall(call: TsNode): { obj: string; attr: string } | null {
  const fn = call.childForFieldName("function");
  if (!fn || fn.type !== "attribute") return null;
  const o = fn.childForFieldName("object");
  const a = fn.childForFieldName("attribute");
  if (!o || !a) return null;
  return { obj: o.text, attr: a.text };
}

/** Whether the call passes a truthy `shell=True` keyword (the gate that makes subprocess use a shell). */
function hasShellTrue(call: TsNode): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  return args.namedChildren.some((a) => {
    if (a.type !== "keyword_argument") return false;
    const n = a.childForFieldName("name");
    const v = a.childForFieldName("value");
    return !!n && n.text === "shell" && !!v && v.type === "true";
  });
}

// --- command injection ------------------------------------------------------
// `os.system`/`os.popen` and `subprocess.getoutput`/`getstatusoutput` ALWAYS run via the shell, so any
// dynamic argument is injection. `subprocess.run`/`call`/`Popen`/… use the shell ONLY with `shell=True`
// — the list-argument form (`run(["ls", x])`) bypasses the shell and is safe. `shlex.quote` down-tiers.
const CMD_COND_SHELL = new Set(["run", "call", "check_call", "check_output", "Popen"]);
const CMD_SHLEX_QUOTE = /(?:^|\.)(?:shlex|pipes)\.quote$/;

/** If `call` is an OS-command sink, the command argument plus whether it always invokes a shell. */
function cmdSink(call: TsNode): { arg: TsNode; alwaysShell: boolean } | null {
  const c = attrCall(call);
  if (!c) return null;
  const a = arg0(call);
  if (!a) return null;
  if (c.obj === "os" && (c.attr === "system" || c.attr === "popen")) return { arg: a, alwaysShell: true };
  if ((c.obj === "subprocess" || c.obj === "commands") && (c.attr === "getoutput" || c.attr === "getstatusoutput"))
    return { arg: a, alwaysShell: true };
  if (c.obj === "subprocess" && CMD_COND_SHELL.has(c.attr)) return { arg: a, alwaysShell: false };
  return null;
}

/** A `shlex.quote(...)` / `pipes.quote(...)` call — escapes a single shell argument. */
function isShlexQuote(node: TsNode): boolean {
  const n = unwrap(node, pythonProfile);
  if (n.type !== "call") return false;
  const fn = n.childForFieldName("function");
  return !!fn && CMD_SHLEX_QUOTE.test(fn.text);
}

const CMD_MESSAGE =
  "An OS command is built from a dynamic value and run through the shell (`os.system`, " +
  "`subprocess(..., shell=True)`, …). If any part is user-controlled, an attacker can run arbitrary " +
  "commands. Avoid the shell: pass an argument list (`subprocess.run([\"prog\", arg])`, no `shell=True`), " +
  "or escape every argument with `shlex.quote()`.";
function cmdSanitizedNote(): string {
  return (
    "Every dynamic part here is wrapped in `shlex.quote` — likely safe, but shell escaping is brittle " +
    "(quoting context, multiple args); prefer an argument list. Down-tiered from a blocking finding to review."
  );
}

// --- code injection ---------------------------------------------------------
// `eval`/`exec`/`compile` of a dynamic, non-literal value is arbitrary code execution. There is no safe
// escape — the fix is to remove the dynamic eval and use a data-driven dispatch (a dict/allowlist).
const CODE_SINKS = new Set(["eval", "exec", "compile"]);

/** The code argument of an `eval`/`exec`/`compile(...)` builtin call, or null. */
function codeSinkArg(call: TsNode): TsNode | null {
  const fn = call.childForFieldName("function");
  if (!fn || fn.type !== "identifier" || !CODE_SINKS.has(fn.text)) return null;
  return arg0(call);
}

const CODE_MESSAGE =
  "A dynamic value is executed as Python code (`eval`/`exec`/`compile`). If any part is user-controlled " +
  "this is remote code execution. There is no safe way to escape code — remove the dynamic " +
  "`eval`/`exec` and dispatch on the value through a dict/allowlist instead.";

// --- unsafe deserialization -------------------------------------------------
// `pickle`/`marshal`/`dill` `.load`/`.loads` deserialize arbitrary objects → RCE on untrusted input.
// `yaml.load(x)` is unsafe unless a safe `Loader=` is given (`yaml.safe_load` is the safe API, not a sink).
const PICKLE_MODULES = new Set(["pickle", "cPickle", "_pickle", "dill"]);
const DESER_ATTRS = new Set(["load", "loads"]);
const YAML_SAFE_LOADER = /(?:^|\.)(?:SafeLoader|CSafeLoader|BaseLoader)$/;

/** If `call` deserializes untrusted data, the data argument plus whether a safe loader neutralizes it. */
function deserSink(call: TsNode): { arg: TsNode; sanitized: boolean } | null {
  const c = attrCall(call);
  if (!c) return null;
  const a = arg0(call);
  if (!a) return null;
  const leaf = c.obj.split(".").pop() || c.obj; // `foo.pickle.loads` → match on `pickle`
  if ((PICKLE_MODULES.has(leaf) || leaf === "marshal") && DESER_ATTRS.has(c.attr)) return { arg: a, sanitized: false };
  if (leaf === "yaml" && c.attr === "load") return { arg: a, sanitized: hasSafeLoader(call) };
  return null;
}

/** `yaml.load(x, Loader=SafeLoader)` / `yaml.load(x, SafeLoader)` — a safe loader forbids object construction. */
function hasSafeLoader(call: TsNode): boolean {
  const args = call.childForFieldName("arguments");
  if (!args) return false;
  return args.namedChildren.some((a) => {
    if (a.type === "keyword_argument") {
      const n = a.childForFieldName("name");
      const v = a.childForFieldName("value");
      return !!n && n.text === "Loader" && !!v && YAML_SAFE_LOADER.test(v.text);
    }
    return YAML_SAFE_LOADER.test(a.text); // positional Loader
  });
}

const DESER_MESSAGE =
  "Untrusted data is deserialized with `pickle`/`marshal`/`yaml.load`, which can construct arbitrary " +
  "objects and execute code (RCE) on attacker-controlled input. Use a safe format (`json.loads`) for " +
  "untrusted data, or `yaml.safe_load` / `yaml.load(x, Loader=yaml.SafeLoader)` for YAML.";
function deserSanitizedNote(): string {
  return (
    "A safe YAML loader (`SafeLoader`/`BaseLoader`) is set, so arbitrary object construction is prevented " +
    "— likely safe, but confirm the loader covers every call on this path. Down-tiered from a blocking finding to review."
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
    // call nodes only; the imperative core decides whether arg0 is a dynamic SQL string.
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call" || !isSink(node)) return;
      const args = node.childForFieldName("arguments");
      const a0 = args ? args.namedChild(0) : null;
      if (!a0) return;
      const root = ctx.tsTree!.rootNode;
      if (!isDynamicSql(a0, root)) return;

      const dyn = dynamicParts(unwrap(a0, pythonProfile).type === "identifier" ? (declInit(unwrap(a0, pythonProfile).text, root, pythonProfile) || a0) : a0, root, pythonProfile);
      const sanitized = dyn.length > 0 && dyn.every(isSanitizerCall);
      emitFinding(node, ctx, emit, pythonProfile,
        sanitized ? { sanitized: true, message: MESSAGE, sanitizedNote: sanitizedNote() } : { sanitized: false, message: MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "xss-sink",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "XSS sink",
    languages: ["python"],
    message: XSS_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call" || !isXssSink(node)) return;
      const args = node.childForFieldName("arguments");
      const a0 = args ? args.namedChild(0) : null;
      if (!a0) return;
      const root = ctx.tsTree!.rootNode;
      if (!isDynamicHtml(a0, root)) return; // a fully static HTML literal is safe

      const sanitized = isXssSanitized(a0, root);
      emitFinding(node, ctx, emit, pythonProfile,
        sanitized ? { sanitized: true, message: XSS_MESSAGE, sanitizedNote: xssSanitizedNote() } : { sanitized: false, message: XSS_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "path-traversal",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Path traversal sink",
    languages: ["python"],
    message: PT_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call") return;
      const args = ptSinkArgs(node);
      if (!args) return;
      const root = ctx.tsTree!.rootNode;
      const tainted = args.find((a) => taintedByRequest(a, root));
      if (!tainted) return;
      const sanitized = pathSanitized(tainted, root);
      emitFinding(node, ctx, emit, pythonProfile,
        sanitized ? { sanitized: true, message: PT_MESSAGE, sanitizedNote: ptSanitizedNote() } : { sanitized: false, message: PT_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "permissive-cors",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Permissive CORS policy",
    languages: ["python"],
    message: CORS_MESSAGE,
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      let hit = false;
      if (node.type === "call") {
        if (corsCallPermissive(node) || isHeaderStarCall(node)) hit = true;
      } else if (node.type === "assignment") {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (left && right) {
          if (left.type === "identifier" && /^(?:CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL)$/.test(left.text) && right.type === "true") hit = true;
          else if (/access-control-allow-origin/i.test(left.text) && CORS_STAR.test(right.text)) hit = true;
        }
      }
      if (!hit) return;
      const line = node.startPosition.row + 1;
      const loc = {
        start: { line, column: node.startPosition.column },
        end: { line: node.endPosition.row + 1, column: node.endPosition.column },
      };
      const code = (ctx.lines[line - 1] || "").trim();
      emit({ loc, code });
    },
  },
  {
    id: "command-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "OS command injection sink",
    languages: ["python"],
    message: CMD_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call") return;
      const sink = cmdSink(node);
      if (!sink) return;
      // subprocess.run/Popen/… are only a shell sink with shell=True; the list-arg form is always safe.
      if (!sink.alwaysShell && !hasShellTrue(node)) return;
      if (unwrap(sink.arg, pythonProfile).type === "list") return; // argument-list form bypasses the shell
      const root = ctx.tsTree!.rootNode;
      if (isStaticConst(sink.arg, root, pythonProfile)) return; // a static command string is not injectable
      const sanitized = valueSanitized(sink.arg, root, pythonProfile, isShlexQuote);
      emitFinding(node, ctx, emit, pythonProfile,
        sanitized ? { sanitized: true, message: CMD_MESSAGE, sanitizedNote: cmdSanitizedNote() } : { sanitized: false, message: CMD_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "code-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Dynamic code execution sink",
    languages: ["python"],
    message: CODE_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call") return;
      const target = codeSinkArg(node);
      if (!target) return;
      const root = ctx.tsTree!.rootNode;
      if (isStaticConst(target, root, pythonProfile)) return; // eval("1 + 1") on a literal is not injectable
      emitFinding(node, ctx, emit, pythonProfile, { sanitized: false, message: CODE_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "unsafe-deserialization",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Unsafe deserialization sink",
    languages: ["python"],
    message: DESER_MESSAGE,
    sinkQuery: "(call) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call") return;
      const sink = deserSink(node);
      if (!sink) return;
      const root = ctx.tsTree!.rootNode;
      if (isStaticConst(sink.arg, root, pythonProfile)) return; // a literal payload is a fixture, not untrusted input
      emitFinding(node, ctx, emit, pythonProfile,
        sink.sanitized ? { sanitized: true, message: DESER_MESSAGE, sanitizedNote: deserSanitizedNote() } : { sanitized: false, message: DESER_MESSAGE, sanitizedNote: "" });
    },
  },
];
