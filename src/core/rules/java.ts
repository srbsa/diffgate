// Java AST-precision rules (tree-sitter). Same precision tier and safety posture as the other languages.
// Java specifics:
//   • Java has NO string interpolation — a dynamic query/command is built by `+` concatenation or
//     `String.format`/`MessageFormat.format`. A `string_literal` is always static.
//   • A parameterized statement is a static SQL string with `?` placeholders and values bound via
//     `setString`/etc — `prepareStatement("… WHERE id = ?")` is safe because the query is a static literal.
//   • Native deserialization (`ObjectInputStream.readObject`) is the canonical Java RCE sink, flagged on
//     presence (every Java SAST does) — the gadget risk doesn't depend on a locally-visible dynamic value.
//
// Coverage: sql-injection · command-injection · unsafe-deserialization · path-traversal · ssrf · xxe ·
// permissive-cors.
// Honest gaps (future): StringBuilder-built SQL, SpEL/OGNL expression injection, template-engine XSS.

import type { TsAstRule, TsNode, RuleContext, EmitFn } from "../types.js";
import {
  type LanguageProfile,
  unwrap, declInit, isStaticConst, dynamicParts, looksLikeSql,
  taintedByRequest as coreTaintedByRequest, requestSanitized, emitFinding as coreEmitFinding,
} from "./tsast-core.js";

// SQL sinks that GUARANTEE query context (no SQL-keyword gate needed — covers HQL/JPQL `from User …`
// which has no SELECT keyword, and `prepareStatement("…"+x)` which is the anti-pattern).
const SQL_FRAGMENT_SINKS = new Set([
  "executeQuery", "executeUpdate", "executeLargeUpdate",
  "prepareStatement", "prepareCall",
  "createQuery", "createNativeQuery", "createSQLQuery",
]);
// SQL sinks whose names are generic (collide with ExecutorService.execute, Map.update, …) — require a
// SQL keyword in the static text to fire.
const SQL_KEYWORD_SINKS = new Set([
  "execute", "update", "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet",
  "batchUpdate", "addBatch",
]);
// Recognized SQL escapers/quoters (down-tier, never suppress).
const SQL_SANITIZERS = /(?:^|\.)(?:escapeSql|escape|quoteIdentifier)$/;

// Command-execution sinks. `Runtime.exec`, `ProcessBuilder` construction, and `ProcessBuilder.command`.
const CMD_METHODS = new Set(["exec", "command"]);

// Native deserialization sinks (method names). Flagged on presence — the canonical Java RCE gadget.
const DESER_METHODS = new Set(["readObject", "readUnshared"]);
// XStream / object-mapper style: `xstream.fromXML(data)`, `decoder.readObject()` already covered above.
const DESER_DYNAMIC_METHODS = new Set(["fromXML"]);

// Filesystem sinks: object_creation types and method names that open a path argument (arg0).
const PT_NEW_TYPES = new Set(["File", "FileInputStream", "FileReader", "FileOutputStream", "FileWriter", "RandomAccessFile"]);
const PT_METHODS = new Set(["get", "readAllBytes", "readAllLines", "newInputStream", "newOutputStream", "newBufferedReader", "lines", "readString"]);
// Untrusted HTTP request data (servlet / Spring MVC accessors).
const JAVA_REQUEST_SOURCE = /\.getParameter\s*\(|\.getParameterValues\s*\(|\.getHeader\s*\(|\.getQueryString\s*\(|\.getPathInfo\s*\(|\.getCookies\s*\(/;
// `FilenameUtils.getName`/`.getFileName()` strip directory components (down-tier).
const PT_SANITIZERS = /(?:^|\.)(?:getName|getFileName)$/;

// --- Java vocabulary ---------------------------------------------------------

/** The simple (unqualified) name of a `new T(...)` type — `java.io.File` → `File`. */
function newTypeLeaf(node: TsNode): string | null {
  const type = node.childForFieldName("type");
  return type ? (type.text.split(".").pop() || type.text) : null;
}

function invokeParts(node: TsNode): { object: TsNode | null; name: string; args: TsNode[] } | null {
  if (node.type !== "method_invocation") return null;
  const name = node.childForFieldName("name");
  if (!name) return null;
  const argsNode = node.childForFieldName("arguments");
  return {
    object: node.childForFieldName("object"),
    name: name.text,
    args: argsNode ? argsNode.namedChildren : [],
  };
}

/** `String.format(...)` / `MessageFormat.format(...)` — builds a string from a format + args. */
function isFormatCall(node: TsNode): boolean {
  const c = invokeParts(node);
  if (!c || c.name !== "format") return false;
  const obj = c.object ? c.object.text : "";
  return obj === "String" || obj === "MessageFormat" || obj.endsWith(".MessageFormat");
}

function staticText(node: TsNode): string {
  const n = unwrap(node, javaProfile);
  if (n.type === "string_literal") return n.text;
  if (n.type === "binary_expression") return n.namedChildren.map(staticText).join(" ");
  if (n.type === "method_invocation" && isFormatCall(n)) {
    const f = invokeParts(n)!.args[0];
    return f ? staticText(f) : "";
  }
  return "";
}

export const javaProfile: LanguageProfile = {
  lang: "java",
  parenthesizedType: "parenthesized_expression",
  identifierType: "identifier",
  assignmentType: ["assignment_expression", "variable_declarator"],
  staticLiteralTypes: new Set([
    "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
    "decimal_floating_point_literal", "hex_floating_point_literal", "true", "false", "null_literal", "character_literal",
  ]),
  stringTypes: new Set(["string_literal"]),
  concatTypes: new Set(["binary_expression"]),
  isInterpolating: () => false, // Java strings never interpolate
  interpolatedExprs: () => [],
  staticText,
  enclosingFnTypes: new Set(["method_declaration", "constructor_declaration"]),
  fnNameField: "name",
  callDescendantType: "method_invocation",
  calleeField: "name", // Java's call callee is the `name` field, not `function`
  recurseNestedConcat: true,
  // `String.format("… %s …", a, b)` — the format args (after arg0) are the injected values.
  resolveDynamicExtra(n, root) {
    if (n.type === "method_invocation" && isFormatCall(n)) {
      return invokeParts(n)!.args.slice(1).filter((a) => !isStaticConst(a, root, javaProfile));
    }
    return null;
  },
  // A bare `CONSTANT` / `Foo.BAR` reference and `field_access` to a constant are not attacker input.
  resolveStaticExtra(n) {
    if (n.type === "field_access") return null; // unknown — fall through (not assumed static)
    return null;
  },
};

// --- shared helpers ----------------------------------------------------------

function emitFinding(
  node: TsNode, ctx: RuleContext, emit: EmitFn,
  opts: { sanitized: boolean; message: string; sanitizedNote: string }
): void {
  coreEmitFinding(node, ctx, emit, javaProfile, opts);
}

/** A value that builds a string from a dynamic part (concatenation or `String.format`), following
 *  intra-file def-use. A bare method-parameter identifier we can't see the origin of is NOT dynamic
 *  (prefer a miss over flagging a possibly-constant value passed in). */
function buildsDynamicString(node: TsNode, root: TsNode, depth = 0): boolean {
  if (depth > 6) return false;
  const n = unwrap(node, javaProfile);
  if (n.type === "string_literal") return false;
  if (n.type === "binary_expression") return dynamicParts(n, root, javaProfile).length > 0;
  if (n.type === "method_invocation" && isFormatCall(n)) return dynamicParts(n, root, javaProfile).length > 0;
  if (n.type === "identifier") {
    const init = declInit(n.text, root, javaProfile);
    return init ? buildsDynamicString(init, root, depth + 1) : false;
  }
  return false;
}

function callNameMatches(node: TsNode, re: RegExp): boolean {
  const n = unwrap(node, javaProfile);
  const c = invokeParts(n);
  if (!c) return false;
  const full = c.object ? `${c.object.text}.${c.name}` : c.name;
  return re.test(full) || re.test(c.name);
}

function taintedByRequest(node: TsNode, root: TsNode): boolean {
  return coreTaintedByRequest(node, root, javaProfile, JAVA_REQUEST_SOURCE);
}

// SSRF — URL/URI construction and HTTP-client fetches whose URL is request-tainted (arg0).
const SSRF_NEW_TYPES = new Set(["URL", "URI", "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpHead", "HttpUriRequest"]);
const SSRF_METHODS = new Set(["getForObject", "getForEntity", "postForObject", "postForEntity", "getForList", "exchange"]);

/** The URL argument of an SSRF sink, or null. */
function ssrfUrlArg(node: TsNode): TsNode | null {
  if (node.type === "object_creation_expression") {
    const leaf = newTypeLeaf(node);
    if (leaf && SSRF_NEW_TYPES.has(leaf)) { const a = node.childForFieldName("arguments"); return a ? a.namedChildren[0] ?? null : null; }
    return null;
  }
  if (node.type === "method_invocation") {
    const c = invokeParts(node);
    if (!c) return null;
    if (SSRF_METHODS.has(c.name)) return c.args[0] ?? null;
    if (c.name === "newBuilder" && c.object?.text === "HttpRequest") return c.args[0] ?? null;
  }
  return null;
}

// XXE — an XML parser created without disabling DOCTYPE/external entities. Triggers on factory/reader
// creation; suppressed when the file shows any recognized hardening (so a parser secured elsewhere in the
// same file is not re-flagged). Advisory: parsing trusted XML is common, and hardening can be cross-file.
const XXE_FACTORY_OBJECTS = new Set(["DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory", "TransformerFactory", "SchemaFactory"]);
const XXE_FACTORY_METHODS = new Set(["newInstance", "newDefaultInstance", "newNSInstance"]);
const XXE_NEW_TYPES = new Set(["SAXReader", "SAXBuilder"]); // dom4j / JDOM
// Any of these tokens anywhere in the file = the parser is being hardened → suppress (OWASP XXE cheat sheet).
const XXE_HARDENED = /disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities|external-parameter-entities|load-external-dtd|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_STYLESHEET|ACCESS_EXTERNAL_SCHEMA|SUPPORT_DTD|isSupportingExternalEntities|setExpandEntityReferences\s*\(\s*false/;

/** True when `node` creates an XML parser factory/reader that defaults to resolving external entities. */
function isXxeSink(node: TsNode): boolean {
  if (node.type === "method_invocation") {
    const c = invokeParts(node);
    if (!c) return false;
    if (c.name === "createXMLReader" && c.object?.text.split(".").pop() === "XMLReaderFactory") return true;
    return XXE_FACTORY_METHODS.has(c.name) && !!c.object && XXE_FACTORY_OBJECTS.has(c.object.text.split(".").pop() || "");
  }
  if (node.type === "object_creation_expression") {
    const leaf = newTypeLeaf(node);
    return !!leaf && XXE_NEW_TYPES.has(leaf);
  }
  return false;
}

// --- permissive CORS -----------------------------------------------------------
// Wildcard / defaulted / reflected `Access-Control-Allow-Origin` (Spring MVC + servlet):
//   • `@CrossOrigin` with no origin restriction — the bare annotation (and one that sets only e.g.
//     `maxAge`) defaults to allowing ALL origins — or an explicit `origins = "*"` / `"*"` value.
//   • `.allowedOrigins("*")` / `.addAllowedOrigin("*")` / `.setAllowedOrigins(List.of("*"))` (and the
//     `…OriginPattern(s)` variants) on a CORS registry/configuration.
//   • raw header write: `response.setHeader("Access-Control-Allow-Origin", "*")`, or the request's own
//     Origin reflected back (`request.getHeader("Origin")`).
const CORS_HEADER_RE = /access-control-allow-origin/i;
const CORS_STAR_RE = /"\s*\*\s*"/;
const CORS_ORIGIN_METHODS = new Set([
  "allowedOrigins", "allowedOriginPatterns", "addAllowedOrigin", "addAllowedOriginPattern",
  "setAllowedOrigins", "setAllowedOriginPatterns",
]);
const CORS_HEADER_SETTERS = new Set(["setHeader", "addHeader"]);
// Annotation keys that restrict the origin set — if any is present, permissiveness needs an explicit `*`.
const CORS_ANNOTATION_ORIGIN_KEYS = /\b(?:value|origins|originPatterns)\s*=/;

/** The unqualified leaf of an annotation's name (`org.springframework.….CrossOrigin` → `CrossOrigin`). */
function annotationLeaf(node: TsNode): string | null {
  const name = node.childForFieldName("name");
  return name ? (name.text.split(".").pop() || name.text) : null;
}

/** True when an annotation/marker_annotation/method_invocation configures a permissive CORS policy. */
function isCorsPermissive(node: TsNode, root: TsNode): boolean {
  if (node.type === "marker_annotation") return annotationLeaf(node) === "CrossOrigin"; // bare = all origins
  if (node.type === "annotation") {
    if (annotationLeaf(node) !== "CrossOrigin") return false;
    const args = node.childForFieldName("arguments");
    if (!args) return true;
    if (CORS_STAR_RE.test(args.text)) return true; // explicit `*`
    // implicit-value form `@CrossOrigin("https://x")` restricts origins; a key form restricts too.
    const restricts = CORS_ANNOTATION_ORIGIN_KEYS.test(args.text) ||
      args.namedChildren.some((a) => a.type === "string_literal");
    return !restricts; // only maxAge/methods/… set → origins default to ALL
  }
  if (node.type !== "method_invocation") return false;
  const c = invokeParts(node);
  if (!c) return false;
  if (CORS_ORIGIN_METHODS.has(c.name)) return c.args.some((a) => CORS_STAR_RE.test(a.text));
  if (CORS_HEADER_SETTERS.has(c.name) && c.args.length >= 2 && CORS_HEADER_RE.test(c.args[0].text)) {
    return CORS_STAR_RE.test(c.args[1].text) || taintedByRequest(c.args[1], root); // wildcard or reflected
  }
  return false;
}

const CORS_MESSAGE =
  "CORS is configured to allow any origin — a bare `@CrossOrigin` (its default allows ALL origins), an " +
  "explicit `\"*\"` origin, or the request's own Origin reflected back into " +
  "`Access-Control-Allow-Origin`. If cookies or tokens are used, arbitrary websites can make credentialed " +
  "cross-origin requests to this API. Set an explicit allowlist of trusted origins " +
  "(`@CrossOrigin(origins = \"https://app.example.com\")` / `.allowedOrigins(...)`); never send `*` (or a " +
  "reflected origin) alongside credentials.";

const XXE_MESSAGE =
  "An XML parser is created (`DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`TransformerFactory`/" +
  "dom4j `SAXReader`) without disabling DOCTYPE declarations and external entities. If it parses attacker-controlled " +
  "XML, an attacker can read local files, perform SSRF, or exhaust resources (billion-laughs) via an external entity " +
  "(XXE). Disable DTDs — `dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)` — set " +
  "`setXIncludeAware(false)` and `setExpandEntityReferences(false)`, or enable `XMLConstants.FEATURE_SECURE_PROCESSING`.";

const SSRF_MESSAGE =
  "An outbound HTTP request is made to a request-controlled URL (`new URL(...)`, `RestTemplate.getForObject`, " +
  "Apache `HttpGet`, …) built from `request.getParameter`/`getHeader`/…. An attacker can point it at internal " +
  "services or the cloud metadata endpoint (`169.254.169.254`) — server-side request forgery. Validate the URL " +
  "against an allowlist of permitted hosts (not a denylist), and re-check the host after any redirects.";

// --- messages ----------------------------------------------------------------

const SQL_MESSAGE =
  "A SQL/HQL query is assembled with string concatenation or `String.format` rather than a parameterized " +
  "statement. If any concatenated value is user-controlled, an attacker can read, modify, or delete arbitrary " +
  "data. Use a `PreparedStatement` with `?` placeholders (or named JPA parameters) and bind the values — " +
  "`ps = conn.prepareStatement(\"… WHERE id = ?\"); ps.setString(1, id);` — never build SQL from request data.";
const SQL_SANITIZED =
  "Every dynamic part here is wrapped in a recognized escaper — likely safe, but escaping is weaker than a " +
  "bound parameter; verify it covers every value and context. Down-tiered from a blocking finding to review.";

const CMD_MESSAGE =
  "An OS command is built from a dynamic value (concatenation / `String.format`) and passed to " +
  "`Runtime.exec`/`ProcessBuilder`. If any part is user-controlled, an attacker can run arbitrary commands. " +
  "Pass a fixed program with arguments as separate array elements, validate against an allowlist, and never " +
  "build a command line from request data.";

const DESER_MESSAGE =
  "Untrusted data is deserialized with Java native serialization (`ObjectInputStream.readObject`) or an unsafe " +
  "mapper (`XStream.fromXML`). Deserializing attacker-controlled bytes enables gadget-chain RCE. Avoid Java " +
  "serialization for untrusted input — use a data format (JSON) with a strict type allowlist, or set an " +
  "`ObjectInputFilter` (`readObject` is unsafe by default).";

const PT_MESSAGE =
  "A filesystem path is built from request data (`request.getParameter`/`getHeader`/…) and passed to a file " +
  "sink (`new File`/`Files.readAllBytes`/`Paths.get`/…) without containment. An attacker can read or write " +
  "arbitrary files via `../../etc/passwd`. Reduce the path with `FilenameUtils.getName`, or resolve it under a " +
  "fixed base directory and verify it stays within; never open a request path directly.";
const PT_SANITIZED =
  "The request value here is reduced with `FilenameUtils.getName`/`getFileName`, which strips directory " +
  "traversal — likely safe, but confirm it actually contains the path. Down-tiered from a blocking finding to review.";

// --- rules -------------------------------------------------------------------

export const JAVA_RULES: TsAstRule[] = [
  {
    id: "sql-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["java"],
    message: SQL_MESSAGE,
    sinkQuery: "(method_invocation) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = invokeParts(node);
      if (!c) return;
      const fragment = SQL_FRAGMENT_SINKS.has(c.name);
      const keyworded = SQL_KEYWORD_SINKS.has(c.name);
      if (!fragment && !keyworded) return;
      const root = ctx.tsTree!.rootNode;
      const arg0 = c.args[0];
      if (!arg0 || !buildsDynamicString(arg0, root)) return;
      // Resolve a cross-line query variable to its definition BEFORE the keyword gate, so
      // `String q = "SELECT …" + id; stmt.execute(q)` is seen as SQL (the bare identifier has no text).
      let src = arg0;
      if (unwrap(src, javaProfile).type === "identifier") src = declInit(unwrap(src, javaProfile).text, root, javaProfile) || src;
      // Generic-named sinks (execute/update/query) require a SQL keyword so ExecutorService.execute etc.
      // aren't mistaken for queries; the SQL-distinctive fragment sinks skip the gate.
      if (keyworded && !fragment && !looksLikeSql(unwrap(src, javaProfile), javaProfile)) return;
      const dyn = dynamicParts(src, root, javaProfile);
      const sanitized = dyn.length > 0 && dyn.every((d) => callNameMatches(d, SQL_SANITIZERS));
      emitFinding(node, ctx, emit, { sanitized, message: SQL_MESSAGE, sanitizedNote: SQL_SANITIZED });
    },
  },
  {
    id: "command-injection",
    type: "tsast",
    tier: "orange",
    blocking: true,
    title: "OS command injection sink",
    languages: ["java"],
    message: CMD_MESSAGE,
    sinkQuery: "[(method_invocation) (object_creation_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      let args: TsNode[] | null = null;
      if (node.type === "method_invocation") {
        const c = invokeParts(node);
        if (c && CMD_METHODS.has(c.name)) args = c.args;
      } else if (node.type === "object_creation_expression") {
        if (newTypeLeaf(node) === "ProcessBuilder") {
          const a = node.childForFieldName("arguments");
          args = a ? a.namedChildren : [];
        }
      }
      if (!args) return;
      // A dynamically-built command string (concat / String.format) or a directly request-tainted argument
      // is the clear signal. A bare opaque argument (could be a constant/config) is NOT flagged — that
      // avoids the gosec-style false block on configured binaries.
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
    languages: ["java"],
    message: DESER_MESSAGE,
    sinkQuery: "(method_invocation) @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const c = invokeParts(node);
      if (!c) return;
      // `obj.readObject()` / `readUnshared()` on a receiver = the canonical native-deser sink. A bare
      // `readObject()` with no receiver is a Serializable override's own declaration call — skip it.
      if (DESER_METHODS.has(c.name)) {
        if (!c.object) return;
        emitFinding(node, ctx, emit, { sanitized: false, message: DESER_MESSAGE, sanitizedNote: "" });
        return;
      }
      // `xstream.fromXML(data)` — flag a dynamic (non-constant) argument.
      if (DESER_DYNAMIC_METHODS.has(c.name)) {
        const arg0 = c.args[0];
        if (!arg0) return;
        const root = ctx.tsTree!.rootNode;
        if (isStaticConst(arg0, root, javaProfile)) return;
        emitFinding(node, ctx, emit, { sanitized: false, message: DESER_MESSAGE, sanitizedNote: "" });
      }
    },
  },
  {
    id: "ssrf",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "SSRF sink",
    languages: ["java"],
    message: SSRF_MESSAGE,
    sinkQuery: "[(method_invocation) (object_creation_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
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
    languages: ["java"],
    message: PT_MESSAGE,
    sinkQuery: "[(method_invocation) (object_creation_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      const root = ctx.tsTree!.rootNode;
      let args: TsNode[] | null = null;
      if (node.type === "method_invocation") {
        const c = invokeParts(node);
        // `Paths.get`/`Files.readAllBytes`/… — the path is arg0.
        if (c && PT_METHODS.has(c.name)) args = c.args;
      } else if (node.type === "object_creation_expression") {
        const leaf = newTypeLeaf(node);
        if (leaf && PT_NEW_TYPES.has(leaf)) {
          const a = node.childForFieldName("arguments");
          args = a ? a.namedChildren : [];
        }
      }
      if (!args) return;
      const tainted = args.find((a) => taintedByRequest(a, root));
      if (!tainted) return;
      const sanitized = requestSanitized(tainted, root, javaProfile, JAVA_REQUEST_SOURCE, PT_SANITIZERS);
      emitFinding(node, ctx, emit, { sanitized, message: PT_MESSAGE, sanitizedNote: PT_SANITIZED });
    },
  },
  {
    id: "xxe",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "XML external entity (XXE) sink",
    languages: ["java"],
    message: XXE_MESSAGE,
    sinkQuery: "[(method_invocation) (object_creation_expression)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (!isXxeSink(node)) return;
      if (XXE_HARDENED.test(ctx.tsTree!.rootNode.text)) return; // hardened in-file → not a finding
      emitFinding(node, ctx, emit, { sanitized: false, message: XXE_MESSAGE, sanitizedNote: "" });
    },
  },
  {
    id: "permissive-cors",
    type: "tsast",
    tier: "orange",
    blocking: false,
    title: "Permissive CORS policy",
    languages: ["java"],
    message: CORS_MESSAGE,
    sinkQuery: "[(method_invocation) (annotation) (marker_annotation)] @sink",
    visit(node: TsNode, ctx: RuleContext, emit: EmitFn) {
      if (!isCorsPermissive(node, ctx.tsTree!.rootNode)) return;
      emitFinding(node, ctx, emit, { sanitized: false, message: CORS_MESSAGE, sanitizedNote: "" });
    },
  },
];
