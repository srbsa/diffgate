// Go AST-precision rules (tree-sitter). Same precision tier and safety posture as the JS/Python/PHP
// rules: blocking findings fire on local structural evidence, down-tier (never suppress) on a recognized
// sanitizer, and the graph reachability/blast-radius pass composes on top. Go specifics the regex
// candidates can't get right:
//   • Go has NO string interpolation — a dynamic query is built ONLY by concatenation (`+`) or
//     `fmt.Sprintf`. A plain string literal (interpreted or raw `backtick`) is always static.
//   • A parameterized query is a static string with `?`/`$1` placeholders and args passed separately —
//     `db.Query("… WHERE id = ?", id)` is safe because the query argument is a static literal.
//   • `exec.Command(name, args...)` does NOT use a shell: `exec.Command("git", "checkout", branch)` is
//     SAFE even when `branch` is tainted. Command injection in Go is specifically (a) a dynamic program
//     NAME, or (b) a shell program (`sh`/`bash`/`cmd`) with a dynamic argument it will interpret.
//
// Coverage (each a separate `tsast` rule sharing the helpers in `tsast-core`):
//   sql-injection · command-injection · path-traversal · ssrf · permissive-cors.
// Honest gaps (future): `text/template`-vs-`html/template` XSS (incl. the `template.HTML(tainted)` cast),
// unsafe deserialization (gob/yaml on untrusted input).

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";
import {
  type LanguageProfile,
  unwrap, declInit, isStaticConst, dynamicParts, looksLikeSql,
  taintedByRequest as coreTaintedByRequest, requestSanitized, emitFinding as coreEmitFinding,
} from "./tsast-core.js";

// --- SQL ----------------------------------------------------------------------
// database/sql, sqlx, and gorm query methods. The query string is found by scanning args for a dynamic
// SQL string (so the method's arg position — arg0, or arg1 after a ctx/dest — doesn't matter), gated by
// the SQL-keyword check so a generic `cache.Get(key)` is never mistaken for a query.
// SQL-distinctive method names only. `Get`/`Select` are deliberately EXCLUDED despite sqlx using them:
// they collide with caches/config/collections (`cache.Get("SELECT_KEY" + x)`) and the SQL-keyword gate
// can't tell them apart — including them risks a false BLOCK, which the zero-false-block brand forbids.
// The sqlx `Get`/`Select` injection form is an honest false negative; the distinctive sqlx names remain.
const SQL_SINK_METHODS = new Set([
  "Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext", "Prepare", "PrepareContext",
  "Queryx", "QueryRowx", "NamedQuery", "NamedExec", "MustExec", "Raw",
]);

// OS-command execution. `exec.Command`/`exec.CommandContext` — the program name and its argument vector.
const SHELL_PROGRAMS = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/sh", "/usr/bin/bash",
  "/usr/bin/env", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
]);

// Filesystem sinks (operand → field set → which argument index(es) hold the PATH). `http.ServeFile`'s
// path is arg2 (`w, r, name`). `os.ReadFile`/`Open`/… take the path at arg0.
const PT_SINKS: Array<{ op: string; fields: Set<string>; idx: number[] }> = [
  { op: "os", fields: new Set(["Open", "Create", "ReadFile", "Remove", "RemoveAll", "OpenFile", "ReadDir", "Mkdir", "MkdirAll", "WriteFile"]), idx: [0] },
  { op: "ioutil", fields: new Set(["ReadFile", "WriteFile", "ReadDir"]), idx: [0] },
  { op: "http", fields: new Set(["ServeFile"]), idx: [2] },
];
// Untrusted HTTP request data: net/http accessors and gorilla/mux path vars. Shared by the path and
// command rules (a request-tainted value is the clear-cut signal in both).
const GO_REQUEST_SOURCE = /\.(?:FormValue|PostFormValue|PathValue)\s*\(|\.URL\.Query\s*\(\s*\)|\bmux\.Vars\s*\(|\.URL\.Path\b|\.Header\.Get\s*\(/;
// `filepath.Base`/`path.Base` strips directory components (down-tier). `filepath.Clean` is deliberately
// NOT here — Clean does not prevent traversal (`../../etc/passwd` cleans to itself).
const PT_SANITIZERS = /(?:^|\.)(?:filepath|path)\.Base$/;

// --- Go vocabulary -----------------------------------------------------------

/** The args of a call (Go `argument_list` children are the args directly — no `argument` wrapper). */
function goArgs(call: TsNode): TsNode[] {
  const a = call.childForFieldName("arguments");
  return a ? a.namedChildren : [];
}

/** `{operand, field}` of a selector-style call (`db.Query` → {op:"db", field:"Query"}), or null. */
function selectorCall(call: TsNode): { op: string; field: string } | null {
  const fn = call.childForFieldName("function");
  if (!fn || fn.type !== "selector_expression") return null;
  const op = fn.childForFieldName("operand");
  const field = fn.childForFieldName("field");
  if (!op || !field) return null;
  return { op: op.text, field: field.text };
}

/** The literal text of a Go string with its quotes stripped (`"sh"` → `sh`). */
function stringContent(node: TsNode): string {
  const n = unwrap(node, goProfile);
  if (n.type === "interpreted_string_literal" || n.type === "raw_string_literal") {
    const c = n.namedChildren.find((x) => x.type.endsWith("_content"));
    return c ? c.text : n.text.replace(/^[`"]|[`"]$/g, "");
  }
  return "";
}

/** `fmt.Sprintf(...)` — the Go analogue of Python `.format` / PHP `sprintf`. */
function isSprintf(node: TsNode): boolean {
  if (node.type !== "call_expression") return false;
  const c = selectorCall(node);
  return !!c && c.op === "fmt" && /^Sprintf$|^Sprint$|^Sprintln$/.test(c.field);
}

function staticText(node: TsNode): string {
  const n = unwrap(node, goProfile);
  if (n.type === "interpreted_string_literal" || n.type === "raw_string_literal") return n.text;
  if (n.type === "binary_expression") return n.namedChildren.map(staticText).join(" ");
  if (n.type === "call_expression" && isSprintf(n)) {
    const f = goArgs(n)[0];
    return f ? staticText(f) : "";
  }
  return "";
}

export const goProfile: LanguageProfile = {
  lang: "go",
  parenthesizedType: "parenthesized_expression",
  identifierType: "identifier",
  assignmentType: ["short_var_declaration", "assignment_statement", "var_spec", "const_spec"],
  assignmentListType: "expression_list",
  staticLiteralTypes: new Set(["int_literal", "float_literal", "imaginary_literal", "rune_literal", "true", "false", "nil", "iota"]),
  stringTypes: new Set(["interpreted_string_literal", "raw_string_literal"]),
  concatTypes: new Set(["binary_expression"]),
  isInterpolating: () => false, // Go strings never interpolate — dynamism comes from concat / Sprintf
  interpolatedExprs: () => [],
  staticText,
  enclosingFnTypes: new Set(["function_declaration", "method_declaration"]),
  fnNameField: "name",
  callDescendantType: "call_expression",
  recurseNestedConcat: true, // `"a" + esc(x) + "b"` parses left-associative; recurse to the leaves
  // `fmt.Sprintf("… %s …", a, b)` — the format args (after arg0) are the injected values.
  resolveDynamicExtra(n, root) {
    if (n.type === "call_expression" && isSprintf(n)) {
      return goArgs(n).slice(1).filter((a) => !isStaticConst(a, root, goProfile));
    }
    return null;
  },
};

// --- thin Go wrappers over the shared core -----------------------------------

function taintedByRequest(node: TsNode, root: TsNode): boolean {
  return coreTaintedByRequest(node, root, goProfile, GO_REQUEST_SOURCE);
}
function pathSanitized(node: TsNode, root: TsNode): boolean {
  return requestSanitized(node, root, goProfile, GO_REQUEST_SOURCE, PT_SANITIZERS);
}
function emitFinding(
  node: TsNode, ctx: RuleContext, emit: EmitFn,
  opts: { sanitized: boolean; message: string; sanitizedNote: string }
): void {
  coreEmitFinding(node, ctx, emit, goProfile, opts);
}

// --- SQL injection predicate -------------------------------------------------

function isSqlSink(call: TsNode): boolean {
  const c = selectorCall(call);
  return !!c && SQL_SINK_METHODS.has(c.field);
}

/** Is `node` a SQL string built from a dynamic (non-constant) value? */
function isDynamicSql(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, goProfile);
  if (!looksLikeSql(n, goProfile)) {
    if (n.type === "identifier") {
      const init = declInit(n.text, root, goProfile);
      return init ? isDynamicSql(init, root, depth + 1) : false;
    }
    return false;
  }
  if (n.type === "interpreted_string_literal" || n.type === "raw_string_literal") return false; // static literal
  if (n.type === "binary_expression" || n.type === "call_expression") return dynamicParts(n, root, goProfile).length > 0;
  if (n.type === "identifier") {
    const init = declInit(n.text, root, goProfile);
    return init ? isDynamicSql(init, root, depth + 1) : false;
  }
  return false;
}

// --- command-injection predicate ---------------------------------------------

/** The program name + the remaining argument vector of an `exec.Command`/`exec.CommandContext` call. */
function execCommand(call: TsNode): { name: TsNode; rest: TsNode[] } | null {
  const c = selectorCall(call);
  if (!c || c.op !== "exec" || (c.field !== "Command" && c.field !== "CommandContext")) return null;
  const args = goArgs(call);
  const nameIdx = c.field === "CommandContext" ? 1 : 0; // CommandContext(ctx, name, args...)
  const name = args[nameIdx];
  if (!name) return null;
  return { name, rest: args.slice(nameIdx + 1) };
}

// --- path-traversal predicate ------------------------------------------------

/** The path argument(s) of a filesystem sink, or null when `call` is not one. */
function ptSinkPathArgs(call: TsNode): TsNode[] | null {
  const c = selectorCall(call);
  if (!c) return null;
  const sink = PT_SINKS.find((s) => s.op === c.op && s.fields.has(c.field));
  if (!sink) return null;
  const args = goArgs(call);
  return sink.idx.map((i) => args[i]).filter((a): a is TsNode => !!a);
}

// --- SSRF --------------------------------------------------------------------
// net/http outbound requests whose URL is request-tainted. `http.Get`/`Post`/`Head`/`PostForm` take the
// URL at arg0; `http.NewRequest(method, url, body)` at arg1; `NewRequestWithContext(ctx, method, url, …)` at arg2.
const SSRF_HTTP_FUNCS = new Map<string, number>([
  ["Get", 0], ["Post", 0], ["Head", 0], ["PostForm", 0], ["NewRequest", 1], ["NewRequestWithContext", 2],
]);

function ssrfUrlArg(call: TsNode): TsNode | null {
  const c = selectorCall(call);
  if (!c || c.op !== "http") return null;
  const idx = SSRF_HTTP_FUNCS.get(c.field);
  return idx === undefined ? null : (goArgs(call)[idx] ?? null);
}

const SSRF_MESSAGE =
  "An outbound HTTP request (`http.Get`/`http.NewRequest`/…) is made to a request-controlled URL " +
  "(`r.FormValue`/`r.URL.Query()`/…). An attacker can point it at internal services or the cloud metadata " +
  "endpoint (`169.254.169.254`) — server-side request forgery. Validate the URL against an allowlist of " +
  "permitted hosts (not a denylist), and re-check the host after any redirects.";

// --- permissive CORS -----------------------------------------------------------
// Wildcard / reflected `Access-Control-Allow-Origin`. Every trigger is config-string-shaped and
// distinctive (the same near-zero-FP reason the JS/Python/PHP cors rules earn a finding):
//   • raw header write: `w.Header().Set/Add("Access-Control-Allow-Origin", "*")`, or the request's own
//     Origin reflected back (`r.Header.Get("Origin")`) — reflection + credentials is the exploitable combo.
//   • gin-contrib/cors: `cors.Default()` (allows all origins), `AllowAllOrigins: true`,
//     `AllowOrigins: []string{"*"}`, `AllowOriginFunc: func(...) bool { return true }`.
//   • rs/cors: `cors.AllowAll()`, `AllowedOrigins: []string{"*"}`.
const CORS_HEADER_RE = /access-control-allow-origin/i;
const GO_ORIGIN_REFLECT = /\.Header\.Get\s*\(\s*"Origin"\s*\)/i;
const CORS_ALLOW_ALL_FIELD = /^Allow(?:All)?(?:ed)?Origins$/; // AllowAllOrigins | AllowOrigins | AllowedOrigins
const CORS_ORIGIN_FUNC_FIELD = /^AllowOrigin(?:Request|WithContext)?Func$/;
const RETURN_TRUE_BODY = /\{\s*return\s+true;?\s*\}\s*$/;

/** `{key, value}` pairs of a composite literal's keyed elements (`cors.Config{A: b, C: d}`). */
function keyedElements(lit: TsNode): Array<{ key: string; value: TsNode }> {
  const out: Array<{ key: string; value: TsNode }> = [];
  for (const el of lit.descendantsOfType("keyed_element")) {
    const kids = el.namedChildren;
    if (kids.length >= 2) out.push({ key: kids[0].text, value: kids[kids.length - 1] });
  }
  return out;
}

/** True when a call/composite-literal configures a permissive (any-origin / reflected) CORS policy. */
function isCorsPermissive(node: TsNode, root: TsNode): boolean {
  if (node.type === "composite_literal") {
    return keyedElements(node).some(({ key, value }) =>
      (key === "AllowAllOrigins" && value.text === "true") ||
      (CORS_ALLOW_ALL_FIELD.test(key) && key !== "AllowAllOrigins" && /"\s*\*\s*"/.test(value.text)) ||
      (CORS_ORIGIN_FUNC_FIELD.test(key) && RETURN_TRUE_BODY.test(value.text.replace(/\s+/g, " ")))
    );
  }
  if (node.type !== "call_expression") return false;
  const c = selectorCall(node);
  if (!c) return false;
  // `cors.Default()` (gin-contrib: allows all origins) / `cors.AllowAll()` (rs/cors).
  if (c.op === "cors" && (c.field === "Default" || c.field === "AllowAll")) return true;
  // `….Set/Add("Access-Control-Allow-Origin", <"*"|reflected Origin>)`.
  if (c.field !== "Set" && c.field !== "Add") return false;
  const args = goArgs(node);
  if (args.length < 2 || !CORS_HEADER_RE.test(args[0].text)) return false;
  return stringContent(args[1]).trim() === "*" || coreTaintedByRequest(args[1], root, goProfile, GO_ORIGIN_REFLECT);
}

const CORS_MESSAGE =
  "CORS is configured to allow any origin — a wildcard `Access-Control-Allow-Origin: *`, an allow-all " +
  "config (`AllowAllOrigins: true` / `cors.Default()` / `cors.AllowAll()`), or the request's own Origin " +
  "reflected back. If cookies or tokens are used, arbitrary websites can make credentialed cross-origin " +
  "requests to this API. Set an explicit allowlist of trusted origins; never send `*` (or a reflected " +
  "origin) alongside credentials.";

// --- messages ----------------------------------------------------------------

const SQL_MESSAGE =
  "A SQL query is assembled from a dynamic value via `fmt.Sprintf` or string concatenation rather than a " +
  "parameterized query. If any interpolated value is user-controlled, an attacker can read, modify, or " +
  "delete arbitrary data. Use placeholders and pass values as arguments — e.g. " +
  "`db.Query(\"… WHERE id = ?\", id)` (or `$1` for pq) — and never build SQL with `Sprintf`/`+`.";

const CMD_MESSAGE =
  "An OS command is executed with a dynamic program name, or a shell (`sh`/`bash`/`cmd`) is invoked with " +
  "a dynamic argument it will interpret. If any part is user-controlled, an attacker can run arbitrary " +
  "commands. Pass a fixed program with the arguments as separate vector elements " +
  "(`exec.Command(\"git\", \"checkout\", branch)`) — Go does not use a shell, so that form is safe.";

const PT_MESSAGE =
  "A filesystem path is built from request data (`r.FormValue`/`r.URL.Query()`/`mux.Vars`/…) and passed " +
  "to a file sink (`os.ReadFile`/`os.Open`/`http.ServeFile`/…) without containment. An attacker can read " +
  "or write arbitrary files via `../../etc/passwd`. Reduce the path with `filepath.Base`, or join under a " +
  "fixed base directory and verify the cleaned path stays within it; never open a request path directly.";
const PT_SANITIZED =
  "The request value here is reduced with `filepath.Base`/`path.Base`, which strips directory traversal " +
  "— likely safe, but confirm it actually contains the path. Down-tiered from a blocking finding to review.";

// --- rules -------------------------------------------------------------------

export const GO_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["go"],
    message: SQL_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call_expression" || !isSqlSink(node)) return;
      const root = ctx.tsTree!.rootNode;
      const dynamicArg = goArgs(node).find((a) => isDynamicSql(a, root));
      if (!dynamicArg) return;
      // Go has no recognized SQL value escaper (the fix is placeholders), so there's nothing to down-tier:
      // a dynamic SQL string reaching a sink is always blocking.
      emitFinding(node, ctx, emit, { sanitized: false, message: SQL_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "command-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "OS command injection sink",
    languages: ["go"],
    message: CMD_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call_expression") return;
      const sink = execCommand(node);
      if (!sink) return;
      const root = ctx.tsTree!.rootNode;
      const block = () => emitFinding(node, ctx, emit, { sanitized: false, message: CMD_MESSAGE, sanitizedNote: "" });
      // (a) a static SHELL program with a dynamic argument it will interpret (`sh -c <dynamic>`). The
      // shell metacharacter risk is unambiguous regardless of where the argument came from.
      if (isStaticConst(sink.name, root, goProfile)) {
        if (SHELL_PROGRAMS.has(stringContent(sink.name))) {
          if (sink.rest.some((a) => !isStaticConst(a, root, goProfile))) block();
        }
        return; // fixed non-shell program with vector args → Go runs it without a shell → safe.
      }
      // (b) a dynamic program NAME, but only when it is request-tainted. A bare dynamic name is often a
      // configured binary path (safe) — flagging it unconditionally is the noisy gosec-G204 failure mode
      // that breaks the zero-false-block guarantee; require request taint for the clear-cut RCE.
      if (taintedByRequest(sink.name, root)) block();
    },
  },
  {
    id: "ssrf",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "SSRF sink",
    languages: ["go"],
    message: SSRF_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call_expression") return;
      const url = ssrfUrlArg(node);
      if (!url) return;
      const root = ctx.tsTree!.rootNode;
      if (!taintedByRequest(url, root)) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: SSRF_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "path-traversal",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Path traversal sink",
    languages: ["go"],
    message: PT_MESSAGE,
    sinkQuery: "(call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "call_expression") return;
      const args = ptSinkPathArgs(node);
      if (!args) return;
      const root = ctx.tsTree!.rootNode;
      const tainted = args.find((a) => taintedByRequest(a, root));
      if (!tainted) return;
      const sanitized = pathSanitized(tainted, root);
      emitFinding(node, ctx, emit, { sanitized, message: PT_MESSAGE, sanitizedNote: PT_SANITIZED });
    },
  },
  {
    id: "permissive-cors",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Permissive CORS policy",
    languages: ["go"],
    message: CORS_MESSAGE,
    sinkQuery: "[(call_expression) (composite_literal)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (!isCorsPermissive(node, ctx.tsTree!.rootNode)) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: CORS_MESSAGE, sanitizedNote: "" });
    },
  },
];
