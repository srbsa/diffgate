// C# AST-precision rules (tree-sitter). Same precision tier and safety posture as the other languages.
// C# specifics:
//   • C# HAS string interpolation (`$"… {x} …"`), so a dynamic query/command is built by interpolation,
//     `+` concatenation, or `string.Format`. A plain `string_literal`/verbatim `@"…"` is static.
//   • A parameterized command uses `@name` placeholders + `cmd.Parameters.Add(...)`; the query string is
//     then a static literal and is not flagged. (Note: EF Core `FromSqlInterpolated`/`ExecuteSqlInterpolated`
//     parameterize an interpolated string and are intentionally NOT treated as sinks — only the `…Raw`
//     variants are.)
//   • `BinaryFormatter.Deserialize` (and friends) is the canonical .NET deserialization RCE sink.
//
// Coverage: sql-injection · command-injection · unsafe-deserialization · path-traversal · xss-sink · ssrf · xxe.
// Honest gaps (future): Json.NET `TypeNameHandling`, LDAP injection.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";
import {
  type LanguageProfile,
  unwrap, declInit, isStaticConst, dynamicParts, looksLikeSql,
  taintedByRequest as coreTaintedByRequest, requestSanitized, valueSanitized, emitFinding as coreEmitFinding,
} from "./tsast-core.js";

// SQL command objects — `new SqlCommand(dynamicSql)` (fragment: SQL context guaranteed).
const SQL_NEW_TYPES = new Set(["SqlCommand", "MySqlCommand", "NpgsqlCommand", "OleDbCommand", "OdbcCommand", "SqliteCommand", "SQLiteCommand"]);
// EF Core raw-SQL methods (fragment). The `…Interpolated` variants parameterize and are NOT sinks.
const SQL_FRAGMENT_METHODS = new Set(["FromSqlRaw", "ExecuteSqlRaw", "FromSqlRawAsync", "ExecuteSqlRawAsync", "ExecuteSqlCommand"]);
// Dapper / ADO query methods — generic names, so require a SQL keyword to fire.
const SQL_KEYWORD_METHODS = new Set([
  "Query", "QueryAsync", "Execute", "ExecuteAsync", "QueryFirst", "QueryFirstOrDefault", "QuerySingle",
  "QuerySingleOrDefault", "QueryFirstAsync", "QueryMultiple", "ExecuteScalar", "ExecuteScalarAsync",
]);

// Command-execution sinks.
const UNSAFE_FORMATTERS = new Set(["BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter", "ObjectStateFormatter", "FastJSON"]);

// Filesystem sinks. `System.IO.File.*` static methods and stream/reader constructors (path = arg0).
const PT_FILE_METHODS = new Set(["ReadAllText", "ReadAllBytes", "ReadAllLines", "ReadLines", "Open", "OpenRead", "OpenText", "OpenWrite", "Create", "WriteAllText", "WriteAllBytes", "AppendAllText", "Delete", "Copy", "Move"]);
const PT_NEW_TYPES = new Set(["FileStream", "StreamReader", "StreamWriter", "FileInfo"]);
// Untrusted HTTP request data (ASP.NET / ASP.NET Core).
const CS_REQUEST_SOURCE = /\bRequest\.(?:Query|QueryString|Form|Params|Headers|Cookies)\b|\bRequest\.Query\s*\[|\.QueryString\s*\[/;
// `Path.GetFileName` strips directory components (down-tier).
const PT_SANITIZERS = /(?:^|\.)GetFileName$/;

// HTML-output sinks (XSS): `Html.Raw(x)`, `Response.Write(x)`, `new HtmlString(x)`.
const XSS_METHODS = new Set(["Raw", "Write"]);
const XSS_NEW_TYPES = new Set(["HtmlString"]);
const XSS_SANITIZERS = /(?:^|\.)(?:HtmlEncode|Encode)$/;

const STRING_TYPES = ["string_literal", "verbatim_string_literal", "raw_string_literal", "interpolated_string_expression"];
const INTERP_NON_EXPR = new Set(["interpolation_brace", "interpolation_format_clause", "interpolation_alignment_clause"]);

// --- C# vocabulary -----------------------------------------------------------

/** Unwrapped arguments of an invocation/object-creation (C# wraps each in an `argument` node). */
function csArgs(node: TsNode): TsNode[] {
  const a = node.childForFieldName("arguments");
  if (!a) return [];
  return a.namedChildren.map((x) => (x.type === "argument" ? x.namedChild(0) : x)).filter((x): x is TsNode => !!x);
}

/** `{object, name}` of an invocation whose callee is a member access (`Process.Start` → {obj:"Process", name:"Start"}). */
function memberInvoke(node: TsNode): { obj: string | null; name: string } | null {
  if (node.type !== "invocation_expression") return null;
  const fn = node.childForFieldName("function");
  if (!fn) return null;
  if (fn.type === "member_access_expression") {
    const o = fn.childForFieldName("expression");
    const n = fn.childForFieldName("name");
    return n ? { obj: o ? o.text : null, name: n.text } : null;
  }
  if (fn.type === "identifier") return { obj: null, name: fn.text };
  return null;
}

/** The unqualified type name of a `new T(...)` creation (`System.IO.FileStream` → `FileStream`). */
function newTypeLeaf(node: TsNode): string | null {
  const type = node.childForFieldName("type");
  return type ? (type.text.split(".").pop() || type.text) : null;
}

function isInterpolating(node: TsNode): boolean {
  return node.type === "interpolated_string_expression" && node.descendantsOfType("interpolation").length > 0;
}

function interpolatedExprs(node: TsNode): TsNode[] {
  return node.descendantsOfType("interpolation").flatMap((i) => i.namedChildren.filter((c) => !INTERP_NON_EXPR.has(c.type)));
}

function isFormatCall(node: TsNode): boolean {
  const c = memberInvoke(node);
  return !!c && c.name === "Format" && (c.obj === "string" || c.obj === "String");
}

function staticText(node: TsNode): string {
  const n = unwrap(node, csharpProfile);
  if (n.type === "string_literal" || n.type === "verbatim_string_literal" || n.type === "raw_string_literal") return n.text;
  if (n.type === "interpolated_string_expression") return n.descendantsOfType("string_content").map((c) => c.text).join(" ");
  if (n.type === "binary_expression") return n.namedChildren.map(staticText).join(" ");
  if (n.type === "invocation_expression" && isFormatCall(n)) {
    const f = csArgs(n)[0];
    return f ? staticText(f) : "";
  }
  return "";
}

export const csharpProfile: LanguageProfile = {
  lang: "csharp",
  parenthesizedType: "parenthesized_expression",
  identifierType: "identifier",
  assignmentType: ["assignment_expression", "variable_declarator"],
  staticLiteralTypes: new Set(["integer_literal", "real_literal", "boolean_literal", "null_literal", "character_literal"]),
  stringTypes: new Set(STRING_TYPES),
  concatTypes: new Set(["binary_expression"]),
  isInterpolating,
  interpolatedExprs,
  staticText,
  enclosingFnTypes: new Set(["method_declaration", "constructor_declaration", "local_function_statement"]),
  fnNameField: "name",
  callDescendantType: "invocation_expression",
  recurseNestedConcat: true,
  // `string.Format("… {0} …", a, b)` — the format args (after arg0) are the injected values.
  resolveDynamicExtra(n, root) {
    if (n.type === "invocation_expression" && isFormatCall(n)) {
      return csArgs(n).slice(1).filter((a) => !isStaticConst(a, root, csharpProfile));
    }
    return null;
  },
};

// --- shared helpers ----------------------------------------------------------

function emitFinding(
  node: TsNode, ctx: RuleContext, emit: EmitFn,
  opts: { sanitized: boolean; message: string; sanitizedNote: string }
): void {
  coreEmitFinding(node, ctx, emit, csharpProfile, opts);
}

/** A value that builds a string from a dynamic part (interpolation / concat / `string.Format`), following
 *  intra-file def-use. A bare opaque identifier (origin unknown) is NOT dynamic. */
function buildsDynamicString(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, csharpProfile);
  if (n.type === "string_literal" || n.type === "verbatim_string_literal" || n.type === "raw_string_literal") return false;
  if (n.type === "interpolated_string_expression") return isInterpolating(n) && dynamicParts(n, root, csharpProfile).length > 0;
  if (n.type === "binary_expression") return dynamicParts(n, root, csharpProfile).length > 0;
  if (n.type === "invocation_expression" && isFormatCall(n)) return dynamicParts(n, root, csharpProfile).length > 0;
  if (n.type === "identifier") {
    const init = declInit(n.text, root, csharpProfile);
    return init ? buildsDynamicString(init, root, depth + 1) : false;
  }
  return false;
}

function isDynamicValue(node: TsNode, root: TsNode): boolean {
  return !isStaticConst(node, root, csharpProfile);
}

function taintedByRequest(node: TsNode, root: TsNode): boolean {
  return coreTaintedByRequest(node, root, csharpProfile, CS_REQUEST_SOURCE);
}

/** The receiver expression of a member-access invocation, resolved through a local variable to a
 *  `new X(...)` if possible — used to identify `BinaryFormatter` deserialization. */
function receiverNewType(node: TsNode, root: TsNode, depth = 0): string | null {
  if (depth > 4) return null;
  const fn = node.childForFieldName("function");
  if (!fn || fn.type !== "member_access_expression") return null;
  const recv = fn.childForFieldName("expression");
  if (!recv) return null;
  const r = unwrap(recv, csharpProfile);
  if (r.type === "object_creation_expression") return newTypeLeaf(r);
  if (r.type === "identifier") {
    const init = declInit(r.text, root, csharpProfile);
    if (init) {
      const u = unwrap(init, csharpProfile);
      if (u.type === "object_creation_expression") return newTypeLeaf(u);
    }
  }
  return null;
}

// SSRF — HttpClient / WebClient / WebRequest fetches and URL construction whose URL is request-tainted.
const SSRF_METHODS = new Set([
  "GetAsync", "GetStringAsync", "GetByteArrayAsync", "GetStreamAsync", "PostAsync", "PutAsync", "DeleteAsync",
  "PatchAsync", "DownloadString", "DownloadData", "DownloadFile", "OpenRead", "DownloadStringAsync", "DownloadDataAsync",
]);
const SSRF_NEW_TYPES = new Map<string, number>([["Uri", 0], ["HttpRequestMessage", 1]]);

/** The URL argument of an SSRF sink, or null. */
function ssrfUrlArg(node: TsNode): TsNode | null {
  if (node.type === "object_creation_expression") {
    const leaf = newTypeLeaf(node);
    const idx = leaf ? SSRF_NEW_TYPES.get(leaf) : undefined;
    return idx === undefined ? null : (csArgs(node)[idx] ?? null);
  }
  if (node.type === "invocation_expression") {
    const c = memberInvoke(node);
    if (!c) return null;
    if (SSRF_METHODS.has(c.name)) return csArgs(node)[0] ?? null;
    if (c.name === "Create" && c.obj === "WebRequest") return csArgs(node)[0] ?? null;
  }
  return null;
}

// XXE (.NET) — modern parsers are safe by default, so we flag only the explicit opt-ins to external-entity
// resolution: a legacy `new XmlTextReader(...)`, an explicit `DtdProcessing.Parse` (without a null resolver),
// or assigning a real `XmlResolver`. Suppressed when the file shows the hardening (`DtdProcessing.Prohibit` /
// `ProhibitDtd = true` / `XmlResolver = null`). Advisory.
const CS_XXE_HARDENED = /DtdProcessing\.Prohibit|ProhibitDtd\s*=\s*true|XmlResolver\s*=\s*null/;
const CS_XXE_RESOLVER_NULL = /XmlResolver\s*=\s*null/;

const XXE_MESSAGE =
  "An XML parser is configured to resolve external entities — a legacy `new XmlTextReader(...)`, " +
  "`DtdProcessing = DtdProcessing.Parse` without a null `XmlResolver`, or an explicit `XmlResolver = new " +
  "XmlUrlResolver()`. If it parses attacker-controlled XML, an attacker can read local files or perform SSRF " +
  "via an external entity (XXE). Set `DtdProcessing = DtdProcessing.Prohibit` (the modern default) and " +
  "`XmlResolver = null`.";

const SSRF_MESSAGE =
  "An outbound HTTP request is made to a request-controlled URL (`HttpClient.GetAsync`, `WebClient.DownloadString`, " +
  "`WebRequest.Create`, `new Uri(...)`) built from `Request.Query`/`Request.Form`/…. An attacker can point it at " +
  "internal services or the cloud metadata endpoint (`169.254.169.254`) — server-side request forgery. Validate the " +
  "URL against an allowlist of permitted hosts (not a denylist), and re-check the host after any redirects.";

// --- messages ----------------------------------------------------------------

const SQL_MESSAGE =
  "A SQL query is assembled with string interpolation (`$\"…{x}…\"`), concatenation, or `string.Format` " +
  "rather than a parameterized command. If any value is user-controlled, an attacker can read, modify, or " +
  "delete arbitrary data. Use parameters — `cmd.CommandText = \"… WHERE id = @id\"; cmd.Parameters.AddWithValue(\"@id\", id);` " +
  "(or EF Core `FromSqlInterpolated`) — and never build SQL from request data.";
const SQL_SANITIZED =
  "Every dynamic part here is wrapped in a recognized escaper — likely safe, but escaping is weaker than a " +
  "parameter; verify it covers every value. Down-tiered from a blocking finding to review.";

const CMD_MESSAGE =
  "An OS command is built from a dynamic value (interpolation / concatenation / `string.Format`) and passed " +
  "to `Process.Start`/`ProcessStartInfo`. If any part is user-controlled, an attacker can run arbitrary " +
  "commands. Pass a fixed executable with arguments validated against an allowlist; never build a command " +
  "line or arguments string from request data, and avoid `UseShellExecute = true` with dynamic input.";

const DESER_MESSAGE =
  "Untrusted data is deserialized with an unsafe .NET formatter (`BinaryFormatter`/`SoapFormatter`/" +
  "`NetDataContractSerializer`/`LosFormatter`). Deserializing attacker-controlled bytes enables gadget-chain " +
  "RCE. `BinaryFormatter` is obsolete and unsafe — use `System.Text.Json`/`DataContractJsonSerializer` with a " +
  "known type, and never deserialize untrusted input with these formatters.";

const PT_MESSAGE =
  "A filesystem path is built from request data (`Request.Query`/`Request.Form`/…) and passed to a file sink " +
  "(`File.ReadAllText`/`new FileStream`/…) without containment. An attacker can read or write arbitrary files " +
  "via `..\\..\\` traversal. Reduce the path with `Path.GetFileName`, or combine it under a fixed base " +
  "directory and verify the resolved path stays within; never open a request path directly.";
const PT_SANITIZED =
  "The request value here is reduced with `Path.GetFileName`, which strips directory traversal — likely safe, " +
  "but confirm it actually contains the path. Down-tiered from a blocking finding to review.";

const XSS_MESSAGE =
  "A dynamic value is written to the HTML response un-encoded (`@Html.Raw`, `Response.Write`, `new HtmlString`), " +
  "bypassing Razor's auto-encoding. If any part is user-controlled, an attacker can inject arbitrary " +
  "HTML/JavaScript (XSS). Render the value normally (Razor `@value` encodes), or encode it explicitly with " +
  "`HttpUtility.HtmlEncode` before marking it raw.";
const XSS_SANITIZED =
  "The value here is wrapped in a recognized HTML encoder (e.g. `HttpUtility.HtmlEncode`) — likely safe, but " +
  "verify it covers every dynamic part and the right context. Down-tiered from a blocking finding to review.";

// --- rules -------------------------------------------------------------------

export const CSHARP_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["csharp"],
    message: SQL_MESSAGE,
    sinkQuery: "[(object_creation_expression) (invocation_expression) (assignment_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      let target: TsNode | undefined;
      let keywordGate = false;
      if (node.type === "object_creation_expression") {
        const leaf = newTypeLeaf(node);
        if (leaf && SQL_NEW_TYPES.has(leaf)) target = csArgs(node)[0]; // fragment
      } else if (node.type === "assignment_expression") {
        const left = node.childForFieldName("left");
        if (left && left.type === "member_access_expression" && left.childForFieldName("name")?.text === "CommandText") {
          target = node.childForFieldName("right") || undefined; // fragment
        }
      } else if (node.type === "invocation_expression") {
        const c = memberInvoke(node);
        if (c && SQL_FRAGMENT_METHODS.has(c.name)) target = csArgs(node)[0]; // fragment
        else if (c && SQL_KEYWORD_METHODS.has(c.name)) { target = csArgs(node)[0]; keywordGate = true; }
      }
      if (!target || !buildsDynamicString(target, root)) return;
      let src = target;
      if (unwrap(src, csharpProfile).type === "identifier") src = declInit(unwrap(src, csharpProfile).text, root, csharpProfile) || src;
      if (keywordGate && !looksLikeSql(unwrap(src, csharpProfile), csharpProfile)) return;
      const dyn = dynamicParts(src, root, csharpProfile);
      const sanitized = dyn.length > 0 && dyn.every((d) => {
        const u = unwrap(d, csharpProfile);
        return u.type === "invocation_expression" && /(?:^|\.)(?:Escape|QuoteIdentifier)$/.test(memberInvoke(u)?.name || "");
      });
      emitFinding(node, ctx, emit, { sanitized, message: SQL_MESSAGE, sanitizedNote: SQL_SANITIZED });
    },
  },
  {
    id: "command-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "OS command injection sink",
    languages: ["csharp"],
    message: CMD_MESSAGE,
    sinkQuery: "[(invocation_expression) (assignment_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      let args: TsNode[] | null = null;
      if (node.type === "invocation_expression") {
        const c = memberInvoke(node);
        if (c && c.name === "Start" && (c.obj === "Process" || c.obj === null)) args = csArgs(node);
      } else if (node.type === "assignment_expression") {
        // `psi.Arguments = "…" + x` / `psi.FileName = x`
        const left = node.childForFieldName("left");
        const name = left?.type === "member_access_expression" ? left.childForFieldName("name")?.text : null;
        if (name === "Arguments" || name === "FileName") { const r = node.childForFieldName("right"); if (r) args = [r]; }
      }
      if (!args) return;
      if (!args.some((a) => buildsDynamicString(a, root) || taintedByRequest(a, root))) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: CMD_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "unsafe-deserialization",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "Unsafe deserialization sink",
    languages: ["csharp"],
    message: DESER_MESSAGE,
    sinkQuery: "(invocation_expression) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = memberInvoke(node);
      if (!c || c.name !== "Deserialize") return;
      const root = ctx.tsTree!.rootNode;
      const type = receiverNewType(node, root);
      if (!type || !UNSAFE_FORMATTERS.has(type)) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: DESER_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "path-traversal",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Path traversal sink",
    languages: ["csharp"],
    message: PT_MESSAGE,
    sinkQuery: "[(invocation_expression) (object_creation_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      let args: TsNode[] | null = null;
      if (node.type === "invocation_expression") {
        const c = memberInvoke(node);
        if (c && PT_FILE_METHODS.has(c.name)) args = csArgs(node);
      } else if (node.type === "object_creation_expression") {
        const leaf = newTypeLeaf(node);
        if (leaf && PT_NEW_TYPES.has(leaf)) args = csArgs(node);
      }
      if (!args) return;
      const tainted = args.find((a) => taintedByRequest(a, root));
      if (!tainted) return;
      const sanitized = requestSanitized(tainted, root, csharpProfile, CS_REQUEST_SOURCE, PT_SANITIZERS);
      emitFinding(node, ctx, emit, { sanitized, message: PT_MESSAGE, sanitizedNote: PT_SANITIZED });
    },
  },
  {
    id: "ssrf",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "SSRF sink",
    languages: ["csharp"],
    message: SSRF_MESSAGE,
    sinkQuery: "[(invocation_expression) (object_creation_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const url = ssrfUrlArg(node);
      if (!url) return;
      const root = ctx.tsTree!.rootNode;
      if (!taintedByRequest(url, root)) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: SSRF_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "xss-sink",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "XSS sink",
    languages: ["csharp"],
    message: XSS_MESSAGE,
    sinkQuery: "[(invocation_expression) (object_creation_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      let value: TsNode | undefined;
      if (node.type === "invocation_expression") {
        const c = memberInvoke(node);
        // `Html.Raw(x)` / `Response.Write(x)`. Plain `Write` is broad — require the Html/Response receiver.
        if (c && XSS_METHODS.has(c.name) && (c.obj === "Html" || c.obj === "Response" || c.name === "Raw")) value = csArgs(node)[0];
      } else if (node.type === "object_creation_expression") {
        const leaf = newTypeLeaf(node);
        if (leaf && XSS_NEW_TYPES.has(leaf)) value = csArgs(node)[0];
      }
      if (!value || !isDynamicValue(value, root)) return; // a static HTML literal is safe
      const sanitized = valueSanitized(value, root, csharpProfile, (n) => {
        const u = unwrap(n, csharpProfile);
        return u.type === "invocation_expression" && XSS_SANITIZERS.test(memberInvoke(u)?.name || "");
      });
      emitFinding(node, ctx, emit, { sanitized, message: XSS_MESSAGE, sanitizedNote: XSS_SANITIZED });
    },
  },
  {
    id: "xxe",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "XML external entity (XXE) sink",
    languages: ["csharp"],
    message: XXE_MESSAGE,
    sinkQuery: "[(object_creation_expression) (assignment_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const file = ctx.tsTree!.rootNode.text;
      let trigger = false;
      if (node.type === "object_creation_expression") {
        // `new XmlTextReader(...)` — unsafe by default on legacy frameworks. Suppress if the file hardens it.
        if (newTypeLeaf(node) === "XmlTextReader" && !CS_XXE_HARDENED.test(file)) trigger = true;
      } else if (node.type === "assignment_expression") {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        const name = left?.type === "member_access_expression" ? left.childForFieldName("name")?.text : null;
        // `… .DtdProcessing = DtdProcessing.Parse` enables DTDs — vulnerable unless a null resolver is also set.
        if (name === "DtdProcessing" && right && /Parse/.test(right.text) && !CS_XXE_RESOLVER_NULL.test(file)) trigger = true;
        // `… .XmlResolver = new XmlUrlResolver()` — explicitly opting back into external resolution.
        // `XmlSecureResolver` is the *hardened* resolver (access-restricted), so it is deliberately excluded.
        else if (name === "XmlResolver" && right && unwrap(right, csharpProfile).type === "object_creation_expression") {
          if (newTypeLeaf(unwrap(right, csharpProfile)) === "XmlUrlResolver") trigger = true;
        }
      }
      if (!trigger) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: XXE_MESSAGE, sanitizedNote: "" });
    },
  },
];
