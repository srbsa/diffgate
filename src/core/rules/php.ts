// PHP AST-precision rules (tree-sitter). Same precision tier and safety posture as the JS/Python rules:
// blocking findings fire only on local structural evidence, down-tier (never suppress) on a recognized
// sanitizer, and the graph reachability/blast-radius pass composes on top. PHP specifics the regex
// candidates can't get right:
//   • single-quoted strings DON'T interpolate — `'… WHERE id = $id'` is the literal text `$id`, not a
//     finding. Only double-quoted (`encapsed_string`), heredoc, and backticks interpolate.
//   • a prepared statement with a placeholder (`->prepare("… = ?")`) is safe; the same call with an
//     interpolated value (`->prepare("… = $id")`) is the anti-pattern.
//   • `(int)$id` / `intval($id)` / escapers down-tier SQL; `escapeshellarg`/`escapeshellcmd` down-tier
//     command-exec; `basename` down-tiers path/include; `htmlspecialchars`/`htmlentities` down-tier XSS.
//
// Coverage (each a separate `tsast` rule sharing the helpers below):
//   sql-injection · command-injection · code-injection · file-inclusion · unsafe-deserialization ·
//   xss-sink · path-traversal.
//
// The data-flow algorithm lives in `tsast-core`; this file supplies the PHP vocabulary (`phpProfile`),
// the PHP-specific string/sink/cast predicates, and the rule definitions.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";
import {
  type LanguageProfile,
  unwrap, declInit, isStaticConst, dynamicParts, looksLikeSql,
  valueSanitized, taintedByRequest as coreTaintedByRequest, requestSanitized as coreRequestSanitized,
  emitFinding as coreEmitFinding,
} from "./tsast-core.js";

// SQL query sinks. Function-style (`mysqli_query($conn, $sql)`) and method/static-style
// (`$pdo->query($sql)`, `$wpdb->get_results($sql)`, `DB::statement($sql)`).
const SINK_FUNCS = new Set([
  "mysqli_query", "mysql_query", "mysqli_multi_query", "mysqli_real_query",
  "pg_query", "pg_send_query", "sqlite_query", "sqlite_unbuffered_query", "mssql_query",
]);
const SINK_METHODS = new Set([
  "query", "exec", "prepare", "multi_query", "real_query", "unprepared", "statement", "raw",
  "get_results", "get_var", "get_row", "get_col",
]);
// Laravel raw-SQL fragment builders. The method name itself guarantees SQL context, so a *fragment*
// like `"age > $x"` (no SELECT/WHERE keyword) is still injection — these skip the SQL-keyword gate and
// flag any dynamic arg0. The safe form is a placeholder with bindings: `whereRaw("age > ?", [$x])`.
const SINK_FRAGMENT_METHODS = new Set([
  "whereRaw", "orWhereRaw", "havingRaw", "orHavingRaw", "orderByRaw", "groupByRaw", "selectRaw", "fromRaw",
]);

// Recognized SQL value sanitizers/escapers; an int/float cast is also a complete defense.
const SANITIZER_FUNCS = /(?:^|\\)(?:mysqli_real_escape_string|mysql_real_escape_string|pg_escape_string|pg_escape_literal|pg_escape_identifier|addslashes|intval|floatval|quote)$/i;
const SAFE_CASTS = new Set(["(int)", "(integer)", "(float)", "(double)", "(real)", "(bool)", "(boolean)"]);

// OS-command sinks (shell-out) and their escapers.
const CMD_SINK_FUNCS = new Set(["exec", "shell_exec", "passthru", "system", "proc_open", "popen", "pcntl_exec"]);
const CMD_SANITIZERS = /(?:^|\\)(?:escapeshellarg|escapeshellcmd)$/i;

// Dynamic-code-execution sinks. `eval`/`assert` evaluate arg0; `create_function` evaluates its body (arg1).
const CODE_SINK_ARG0 = new Set(["eval", "assert"]);
const CODE_SINK_ARG1 = new Set(["create_function"]);

// `include`/`require` family — a dynamic path here is local/remote file inclusion (→ RCE).
const INCLUDE_TYPES = new Set(["include_expression", "include_once_expression", "require_expression", "require_once_expression"]);
const FILE_PATH_SANITIZERS = /(?:^|\\)(?:basename)$/i;

// Filesystem sinks for path traversal (read OR write) → which argument index(es) carry the PATH.
// `file_put_contents(path, DATA)` — only arg0 is the path (arg1 is content, not a traversal vector);
// `copy(src, dst)` / `rename(old, new)` take two paths. `file_get_contents`/`fopen` of a URL is also
// SSRF. `realpath` is deliberately NOT a sink — it canonicalizes a path (a sanitizer, below).
const PT_SINK_FUNCS = new Map<string, number[]>([
  ["fopen", [0]], ["file_get_contents", [0]], ["file_put_contents", [0]], ["readfile", [0]],
  ["file", [0]], ["unlink", [0]], ["scandir", [0]], ["opendir", [0]],
  ["copy", [0, 1]], ["rename", [0, 1]],
]);
const PT_SANITIZERS = /(?:^|\\)(?:basename|realpath)$/i;

// HTML-output sinks for reflected XSS, and the escapers that neutralize them.
const XSS_SINK_FUNCS = new Set(["printf", "vprintf", "print_r", "var_dump"]);
const XSS_SANITIZERS = /(?:^|\\)(?:htmlspecialchars|htmlentities|strip_tags|urlencode|rawurlencode|intval|floatval)$/i;

// Untrusted HTTP request sources. `$_SERVER` carries attacker-settable headers (Referer/User-Agent),
// `php://input` is the raw body. `$_SESSION`/`$GLOBALS` are intentionally NOT here.
const REQUEST_SOURCE = /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$HTTP_RAW_POST_DATA\b|php:\/\/input/;

// Tree-sitter-php node types that represent an interpolated value inside a double-quoted/heredoc/backtick string.
const INTERP_TYPES = ["variable_name", "member_access_expression", "subscript_expression", "nullsafe_member_access_expression", "scoped_property_access_expression"];

// --- PHP vocabulary ----------------------------------------------------------

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

/** The argument expressions of a call (unwrapping `argument` nodes). */
function callArgs(call: TsNode): TsNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  return args.namedChildren.map((a) => (a.type === "argument" ? a.namedChild(0) : a)).filter((a): a is TsNode => !!a);
}

/** A double-quoted/heredoc/backtick string with at least one interpolated variable/member/subscript. */
function isInterpolating(node: TsNode): boolean {
  if (node.type !== "encapsed_string" && node.type !== "heredoc" && node.type !== "shell_command_expression") return false;
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

/** `sprintf`/`vsprintf` — builds a string from a format + args, the PHP analogue of Python `.format`. */
function isSprintf(node: TsNode): boolean {
  if (node.type !== "function_call_expression") return false;
  const fn = node.childForFieldName("function");
  return !!fn && /(?:^|\\)v?sprintf$/i.test(fn.text);
}

export const phpProfile: LanguageProfile = {
  lang: "php",
  parenthesizedType: "parenthesized_expression",
  identifierType: "variable_name",
  assignmentType: "assignment_expression",
  staticLiteralTypes: new Set(["integer", "float", "boolean"]),
  // `string` (single-quoted) never interpolates → static; encapsed/heredoc/shell are static iff not interpolating.
  stringTypes: new Set(["string", "encapsed_string", "heredoc", "shell_command_expression"]),
  concatTypes: new Set(["binary_expression"]),
  isInterpolating,
  interpolatedExprs,
  staticText,
  enclosingFnTypes: new Set(["function_definition", "method_declaration"]),
  fnNameField: "name",
  callDescendantType: "function_call_expression",
  recurseNestedConcat: true, // `"a" . esc($x) . "b"` parses left-associative; recurse to reach the leaves
  safeCasts: SAFE_CASTS,
  // A bare `name` is a constant reference (magic constant `__DIR__`/`__FILE__`, or a user `const`/`define`)
  // → runtime-constant, not attacker input. `dirname(...)` is static when its args are.
  resolveStaticExtra(n, _root, recurse) {
    if (n.type === "name") return true;
    if (n.type === "function_call_expression") {
      const fn = n.childForFieldName("function");
      if (fn && /(?:^|\\)dirname$/i.test(fn.text)) return callArgs(n).every(recurse);
      return false;
    }
    return null;
  },
  // sprintf("… %s …", $a, $b) — the format args (after arg0) are the injected values.
  resolveDynamicExtra(n, root) {
    if (isSprintf(n)) return callArgs(n).slice(1).filter((a) => !isStaticConst(a, root, phpProfile));
    return null;
  },
};

// --- thin PHP wrappers over the shared core (preserve call sites) ------------

function isDynamicValue(node: TsNode | null, root: TsNode): boolean {
  if (!node) return false;
  return !isStaticConst(node, root, phpProfile);
}

function taintedByRequest(node: TsNode, root: TsNode): boolean {
  return coreTaintedByRequest(node, root, phpProfile, REQUEST_SOURCE);
}

function requestSanitized(node: TsNode, root: TsNode, re: RegExp): boolean {
  return coreRequestSanitized(node, root, phpProfile, REQUEST_SOURCE, re);
}

function emitFinding(
  node: TsNode, ctx: RuleContext, emit: EmitFn,
  opts: { sanitized: boolean; message: string; sanitizedNote: string }
): void {
  coreEmitFinding(node, ctx, emit, phpProfile, opts);
}

// --- sink-specific predicates ------------------------------------------------

function isSqlSink(call: TsNode): boolean {
  const name = callName(call);
  if (!name) return false;
  if (call.type === "function_call_expression") return SINK_FUNCS.has(name.toLowerCase());
  return SINK_METHODS.has(name);
}

/** A Laravel raw-fragment sink (`->whereRaw(...)`, …) — method-name only, no SQL-keyword gate. */
function isFragmentSink(call: TsNode): boolean {
  if (call.type !== "member_call_expression" && call.type !== "nullsafe_member_call_expression" && call.type !== "scoped_call_expression") return false;
  const name = callName(call);
  return !!name && SINK_FRAGMENT_METHODS.has(name);
}

function isSqlDynamic(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, phpProfile);
  if (!looksLikeSql(n, phpProfile)) {
    if (n.type === "variable_name") {
      const init = declInit(n.text, root, phpProfile);
      return init ? isSqlDynamic(init, root, depth + 1) : false;
    }
    return false;
  }
  if (n.type === "string") return false; // single-quoted: literal, never interpolates
  if (n.type === "encapsed_string" || n.type === "heredoc") return isInterpolating(n) && dynamicParts(n, root, phpProfile).length > 0;
  if (n.type === "binary_expression") return dynamicParts(n, root, phpProfile).length > 0;
  if (n.type === "function_call_expression" && isSprintf(n)) {
    const args = callArgs(n);
    return args.length > 0 && looksLikeSql(args[0], phpProfile) && args.slice(1).some((a) => !isStaticConst(a, root, phpProfile));
  }
  if (n.type === "variable_name") {
    const init = declInit(n.text, root, phpProfile);
    return init ? isSqlDynamic(init, root, depth + 1) : false;
  }
  return false;
}

/** A node that neutralizes its value: a SQL escaper/quoter call, or an int/float cast. */
function isSqlSanitizerCall(node: TsNode): boolean {
  const n = unwrap(node, phpProfile);
  if (n.type === "cast_expression") {
    const t = n.childForFieldName("type");
    return !!t && SAFE_CASTS.has(`(${t.text})`);
  }
  if (n.type === "function_call_expression") {
    const fn = n.childForFieldName("function");
    return !!fn && SANITIZER_FUNCS.test(fn.text);
  }
  if (n.type === "member_call_expression" || n.type === "scoped_call_expression") {
    const m = n.childForFieldName("name");
    return !!m && /^quote$/i.test(m.text); // $pdo->quote(...) / PDO::quote(...)
  }
  return false;
}

/** A simple-function-call sanitizer-call predicate keyed by name regex. */
function callMatches(node: TsNode, re: RegExp): boolean {
  const n = unwrap(node, phpProfile);
  if (n.type !== "function_call_expression") return false;
  const fn = n.childForFieldName("function");
  return !!fn && re.test(fn.text);
}

/** The named sibling immediately before `node` (TsNode exposes no `previousSibling`), matched by
 *  start position. Used to detect a PHP short-echo `<?= … ?>`, whose value parses as a bare
 *  `expression_statement` preceded by a `<?=` tag. */
function prevNamedSibling(node: TsNode): TsNode | null {
  const p = node.parent;
  if (!p) return null;
  const kids = p.namedChildren;
  for (let i = 0; i < kids.length; i++) {
    if (kids[i].startPosition.row === node.startPosition.row && kids[i].startPosition.column === node.startPosition.column) {
      return i > 0 ? kids[i - 1] : null;
    }
  }
  return null;
}

/** A bare `expression_statement` that is the body of a PHP short-echo `<?= … ?>` (its preceding tag
 *  text contains `<?=`). The expression is echoed to the HTML response, so it's an XSS output sink. */
function shortEchoValue(node: TsNode): TsNode | null {
  if (node.type !== "expression_statement") return null;
  const prev = prevNamedSibling(node);
  if (!prev || !prev.text.includes("<?=")) return null;
  return node.namedChild(0);
}

const CALL_TYPES = new Set(["function_call_expression", "member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression"]);
const isCall = (n: TsNode): boolean => CALL_TYPES.has(n.type);

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

const SQL_MESSAGE =
  "A SQL query is assembled from an interpolated or concatenated value rather than a parameterized " +
  "query. If any interpolated value is user-controlled, an attacker can read, modify, or delete " +
  "arbitrary data. Use a prepared statement with bound parameters — e.g. " +
  "`$stmt = $pdo->prepare(\"… WHERE id = ?\"); $stmt->execute([$id]);` — and never build SQL by " +
  "interpolating request data into a double-quoted string.";
const SQL_SANITIZED =
  "Every dynamic part here is wrapped in a recognized escaper/cast (e.g. `mysqli_real_escape_string`, " +
  "`(int)`) — likely safe, but escaping is weaker than a bound parameter; verify it covers every value " +
  "and context. Down-tiered from a blocking finding to review.";

const CMD_MESSAGE =
  "An OS command is built from a dynamic value and passed to a shell-out sink (`exec`, `shell_exec`, " +
  "`system`, backticks, …). If any part is user-controlled, an attacker can run arbitrary commands. " +
  "Avoid the shell: pass a fixed program with an argument array, or escape every argument with " +
  "`escapeshellarg()` (and the program name with `escapeshellcmd()`).";
const CMD_SANITIZED =
  "Every dynamic part here is wrapped in `escapeshellarg`/`escapeshellcmd` — likely safe, but shell " +
  "escaping is brittle (quoting context, multiple args); prefer an argument array. Down-tiered to review.";

const CODE_MESSAGE =
  "A dynamic value is executed as PHP code (`eval`, `assert` of a string, or `create_function`). If any " +
  "part is user-controlled this is remote code execution. There is no safe way to escape code — remove " +
  "the dynamic `eval`/`create_function` and use a data-driven dispatch (an allowlist/`match`) instead.";

const INCLUDE_MESSAGE =
  "A file path passed to `include`/`require` is built from a dynamic value. If it is user-controlled, an " +
  "attacker can include local files (and, with `allow_url_include`, remote code) — a common path to RCE " +
  "(`?page=../../etc/passwd`, `php://filter` chains). Map requests to a fixed allowlist of file paths; " +
  "never build an include path from request data.";
const INCLUDE_SANITIZED =
  "The path here is reduced with `basename()` — this strips directory traversal but still allows " +
  "including any file in the target directory; confirm that directory holds only safe includes. " +
  "Down-tiered from a blocking finding to review.";

const DESERIALIZE_MESSAGE =
  "`unserialize()` is called on a dynamic value. PHP deserialization of attacker-controlled data enables " +
  "object injection / POP-chain RCE (and DoS) via magic methods (`__wakeup`/`__destruct`). Use a safe " +
  "format (`json_decode`) for untrusted input, or pass `['allowed_classes' => false]` to forbid object " +
  "instantiation.";
const DESERIALIZE_SANITIZED =
  "`allowed_classes => false` is set, so no objects are instantiated — object injection is prevented. " +
  "Verify the value still can't cause type-confusion downstream. Down-tiered from a blocking finding to review.";

const XSS_MESSAGE =
  "Request data is written to the HTML response (`echo`/`print`/`printf`) without escaping. An attacker " +
  "can inject arbitrary HTML/JavaScript (reflected XSS). Escape on output with " +
  "`htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` (or your template engine's auto-escaping), and set a " +
  "Content-Security-Policy.";
const XSS_SANITIZED =
  "The request value here is wrapped in a recognized escaper (e.g. `htmlspecialchars`) — likely safe, " +
  "but verify the escaping context (HTML body vs attribute vs JS) matches. Down-tiered to review.";

// SSRF — URL/host-fetch sinks (curl, sockets). `file_get_contents`/`fopen` of a URL are deliberately left
// to the path-traversal rule (which already flags request data and notes the SSRF overlap), so no double report.
const SSRF_FUNCS = new Map<string, number[]>([
  ["curl_init", [0]], ["get_headers", [0]], ["fsockopen", [0]], ["pfsockopen", [0]], ["stream_socket_client", [0]],
]);

/** The URL/host argument(s) of an SSRF sink, or []. `curl_setopt($ch, CURLOPT_URL, $url)` → arg2. */
function ssrfUrlArgs(call: TsNode): TsNode[] {
  if (call.type !== "function_call_expression") return [];
  const name = callName(call);
  if (!name) return [];
  const lower = name.toLowerCase();
  const args = callArgs(call);
  if (lower === "curl_setopt") return args[1] && /CURLOPT_URL/.test(args[1].text) && args[2] ? [args[2]] : [];
  const idxs = SSRF_FUNCS.get(lower);
  return idxs ? idxs.map((i) => args[i]).filter((a): a is TsNode => !!a) : [];
}

const SSRF_MESSAGE =
  "An outbound request is made to a request-controlled URL/host (`curl`, `fsockopen`, `get_headers`). An " +
  "attacker can point it at internal services or the cloud metadata endpoint (`169.254.169.254`) — server-side " +
  "request forgery. Validate the URL against an allowlist of permitted hosts (not a denylist), disable " +
  "following redirects (or re-check the host after each), and reject non-HTTP schemes.";

const PT_MESSAGE =
  "A filesystem path is built from request data and passed to a file sink (`fopen`, `file_get_contents`, " +
  "`readfile`, `unlink`, …) without containment. An attacker can read or write arbitrary files via " +
  "`../../etc/passwd` — and `file_get_contents($url)` on a request URL is also SSRF. Resolve the path " +
  "with `realpath()` and assert it stays under an allowed base directory, or reduce it with `basename()`.";
const PT_SANITIZED =
  "The request value here is wrapped in a recognized path sanitizer (`basename`/`realpath`) — likely " +
  "safe, but verify it actually contains the path. Down-tiered from a blocking finding to review.";

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export const PHP_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["php"],
    message: SQL_MESSAGE,
    sinkQuery: "[(function_call_expression) (member_call_expression) (nullsafe_member_call_expression) (scoped_call_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (!isCall(node)) return;
      const root = ctx.tsTree!.rootNode;
      let dynamicArg: TsNode | undefined;
      if (isFragmentSink(node)) {
        // raw fragment: any dynamic arg0 is injection (a `?` placeholder string is static → safe).
        const a0 = callArgs(node)[0];
        if (a0 && isDynamicValue(a0, root)) dynamicArg = a0;
      } else if (isSqlSink(node)) {
        dynamicArg = callArgs(node).find((a) => isSqlDynamic(a, root));
      }
      if (!dynamicArg) return;
      let src = dynamicArg;
      if (unwrap(src, phpProfile).type === "variable_name") src = declInit(unwrap(src, phpProfile).text, root, phpProfile) || src;
      const dyn = dynamicParts(src, root, phpProfile);
      const sanitized = dyn.length > 0 && dyn.every(isSqlSanitizerCall);
      emitFinding(node, ctx, emit, { sanitized, message: SQL_MESSAGE, sanitizedNote: SQL_SANITIZED });
    },
  },

  {
    id: "command-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "OS command injection sink",
    languages: ["php"],
    message: CMD_MESSAGE,
    sinkQuery: "[(shell_command_expression) (function_call_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      // Backtick command string with an interpolated value.
      if (node.type === "shell_command_expression") {
        if (!isInterpolating(node)) return;
        const dyn = dynamicParts(node, root, phpProfile);
        const sanitized = dyn.length > 0 && dyn.every((d) => callMatches(d, CMD_SANITIZERS));
        emitFinding(node, ctx, emit, { sanitized, message: CMD_MESSAGE, sanitizedNote: CMD_SANITIZED });
        return;
      }
      if (node.type !== "function_call_expression") return;
      const name = callName(node);
      if (!name || !CMD_SINK_FUNCS.has(name.toLowerCase())) return;
      const arg0 = callArgs(node)[0];
      if (!arg0) return;
      if (unwrap(arg0, phpProfile).type === "array_creation_expression") return; // arg-array form bypasses the shell
      if (!isDynamicValue(arg0, root)) return;
      const sanitized = valueSanitized(arg0, root, phpProfile, (n) => callMatches(n, CMD_SANITIZERS));
      emitFinding(node, ctx, emit, { sanitized, message: CMD_MESSAGE, sanitizedNote: CMD_SANITIZED });
    },
  },

  {
    id: "code-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Dynamic code execution sink",
    languages: ["php"],
    message: CODE_MESSAGE,
    sinkQuery: "(function_call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "function_call_expression") return;
      const name = callName(node);
      if (!name) return;
      const lower = name.toLowerCase();
      const args = callArgs(node);
      let target: TsNode | undefined;
      if (CODE_SINK_ARG0.has(lower)) target = args[0];
      else if (CODE_SINK_ARG1.has(lower)) target = args[1];
      else return;
      if (!target) return;
      const root = ctx.tsTree!.rootNode;
      // `assert($x === 1)` / `assert(is_array($x))` are normal boolean assertions — only a STRING-valued
      // arg is evaluated as code. Require a string-shaped node (literal/interpolated/heredoc, or a `$var`
      // resolving to one); a comparison/call `binary_expression` is not code. `eval` is always code.
      if (lower === "assert") {
        const STR = new Set(["string", "encapsed_string", "heredoc"]);
        const isStringish = (n: TsNode, d = 0): boolean => {
          if (d > 6) return false;
          const u = unwrap(n, phpProfile);
          if (STR.has(u.type)) return true;
          if (u.type === "variable_name") { const i = declInit(u.text, root, phpProfile); return !!i && isStringish(i, d + 1); }
          return false;
        };
        if (!isStringish(target)) return;
      }
      if (!isDynamicValue(target, root)) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: CODE_MESSAGE, sanitizedNote: "" });
    },
  },

  {
    id: "file-inclusion",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "File inclusion sink (LFI/RFI)",
    languages: ["php"],
    message: INCLUDE_MESSAGE,
    sinkQuery: "[(include_expression) (include_once_expression) (require_expression) (require_once_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (!INCLUDE_TYPES.has(node.type)) return;
      const target = node.namedChild(0);
      if (!target) return;
      const root = ctx.tsTree!.rootNode;
      if (!isDynamicValue(target, root)) return;
      const sanitized = valueSanitized(target, root, phpProfile, (n) => callMatches(n, FILE_PATH_SANITIZERS));
      emitFinding(node, ctx, emit, { sanitized, message: INCLUDE_MESSAGE, sanitizedNote: INCLUDE_SANITIZED });
    },
  },

  {
    id: "unsafe-deserialization",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Unsafe deserialization sink",
    languages: ["php"],
    message: DESERIALIZE_MESSAGE,
    sinkQuery: "(function_call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "function_call_expression") return;
      const name = callName(node);
      if (!name || name.toLowerCase() !== "unserialize") return;
      const args = callArgs(node);
      const arg0 = args[0];
      if (!arg0) return;
      const root = ctx.tsTree!.rootNode;
      if (!isDynamicValue(arg0, root)) return;
      // `['allowed_classes' => false]` in the options arg forbids object instantiation → safe from POP chains.
      const optsArg = args[1];
      const sanitized = !!optsArg && /allowed_classes/.test(optsArg.text) && /\bfalse\b|\[\s*\]/.test(optsArg.text);
      emitFinding(node, ctx, emit, { sanitized, message: DESERIALIZE_MESSAGE, sanitizedNote: DESERIALIZE_SANITIZED });
    },
  },

  {
    id: "xss-sink",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "XSS sink",
    languages: ["php"],
    message: XSS_MESSAGE,
    sinkQuery: "[(echo_statement) (print_intrinsic) (function_call_expression) (expression_statement)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      let value: TsNode | undefined;
      if (node.type === "echo_statement") {
        value = node.namedChildren.find((c) => taintedByRequest(c, root));
      } else if (node.type === "print_intrinsic") {
        const v = node.namedChild(0);
        if (v && taintedByRequest(v, root)) value = v;
      } else if (node.type === "function_call_expression") {
        const name = callName(node);
        if (name && XSS_SINK_FUNCS.has(name.toLowerCase())) {
          value = callArgs(node).find((a) => taintedByRequest(a, root));
        }
      } else if (node.type === "expression_statement") {
        const v = shortEchoValue(node); // `<?= $_GET['x'] ?>`
        if (v && taintedByRequest(v, root)) value = v;
      }
      if (!value) return;
      const sanitized = requestSanitized(value, root, XSS_SANITIZERS);
      emitFinding(node, ctx, emit, { sanitized, message: XSS_MESSAGE, sanitizedNote: XSS_SANITIZED });
    },
  },

  {
    id: "ssrf",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "SSRF sink",
    languages: ["php"],
    message: SSRF_MESSAGE,
    sinkQuery: "(function_call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "function_call_expression") return;
      const root = ctx.tsTree!.rootNode;
      const tainted = ssrfUrlArgs(node).find((a) => taintedByRequest(a, root));
      if (!tainted) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: SSRF_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "path-traversal",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Path traversal sink",
    languages: ["php"],
    message: PT_MESSAGE,
    sinkQuery: "(function_call_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (node.type !== "function_call_expression") return;
      const name = callName(node);
      const pathIdxs = name ? PT_SINK_FUNCS.get(name.toLowerCase()) : undefined;
      if (!pathIdxs) return;
      const root = ctx.tsTree!.rootNode;
      const args = callArgs(node);
      const tainted = pathIdxs.map((i) => args[i]).find((a) => a && taintedByRequest(a, root));
      if (!tainted) return;
      const sanitized = requestSanitized(tainted, root, PT_SANITIZERS);
      emitFinding(node, ctx, emit, { sanitized, message: PT_MESSAGE, sanitizedNote: PT_SANITIZED });
    },
  },
];
