import { memberName, walk } from "../parsers/javascript.js";
import type { Rule, AstNode, EmitFn, RuleContext, DeprecatedEntry, Config } from "../types.js";

const JS = ["javascript", "typescript"];

// --- AST rule helper functions for JS/TS ------------------------------------

function findDeclarationInit(idName: string, rootAst: AstNode): AstNode | null {
  let found: AstNode | null = null;
  walk(rootAst, (n) => {
    const node = n as any;
    if (node.type === "VariableDeclarator" && node.id && node.id.type === "Identifier" && node.id.name === idName) {
      found = node.init as AstNode;
    } else if (node.type === "AssignmentExpression" && node.left && node.left.type === "Identifier" && node.left.name === idName) {
      found = node.right as AstNode;
    }
  });
  return found;
}

function isStaticLiteral(n: AstNode | null | undefined, ctx: RuleContext): boolean {
  if (!n) return false;
  const node = n as any;
  if (
    node.type === "StringLiteral" ||
    node.type === "NumericLiteral" ||
    node.type === "BooleanLiteral" ||
    node.type === "NullLiteral" ||
    (node.type === "Literal" && typeof node.value !== "undefined")
  ) {
    return true;
  }
  if (node.type === "TemplateLiteral") {
    return (node.expressions || []).length === 0;
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return isStaticLiteral(node.left, ctx) && isStaticLiteral(node.right, ctx);
  }
  if (node.type === "Identifier" && ctx.ast) {
    const decl = findDeclarationInit(node.name, ctx.ast);
    if (decl) return isStaticLiteral(decl, ctx);
  }
  return false;
}

function isDynamicString(node: AstNode | null | undefined, ctx: RuleContext): boolean {
  if (!node) return false;
  return !isStaticLiteral(node, ctx);
}

function isRequestData(node: AstNode): boolean {
  const name = memberName(node);
  if (name && /\b(req|request|ctx|context)\.(query|body|params|headers)\b/i.test(name)) {
    return true;
  }
  return false;
}

function containsRequestData(n: AstNode | null | undefined, ctx: RuleContext): boolean {
  if (!n) return false;
  const node = n as any;
  if (isRequestData(node)) return true;
  if (node.type === "TemplateLiteral") {
    return (node.expressions || []).some((expr: any) => containsRequestData(expr, ctx));
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return containsRequestData(node.left, ctx) || containsRequestData(node.right, ctx);
  }
  if (node.type === "Identifier" && ctx.ast) {
    const decl = findDeclarationInit(node.name, ctx.ast);
    if (decl) return containsRequestData(decl, ctx);
  }
  return false;
}

function getStaticText(n: AstNode): string {
  const node = n as any;
  if (node.type === "TemplateLiteral") {
    return (node.quasis || []).map((q: any) => q.value.raw).join(" ");
  }
  if (node.type === "StringLiteral" || node.type === "Literal") {
    return String(node.value || "");
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    return getStaticText(node.left) + " " + getStaticText(node.right);
  }
  return "";
}

function isSqlQuery(text: string): boolean {
  return /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b/i.test(text);
}

export const BUILTIN_RULES: Rule[] = [
  // ---------------------------------------------------------------- secrets
  {
    id: "hardcoded-secret",
    type: "pattern",
    tier: "orange",
    blocking: true,
    title: "Hardcoded secret",
    languages: ["*"],
    message: "This looks like a committed credential. Move it to an environment variable or secret manager and rotate the key.",
    patterns: [
      /\bAKIA[0-9A-Z]{16}\b/,
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
      /\bghp_[A-Za-z0-9]{36}\b/,
      /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
      /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
      /\bAIza[0-9A-Za-z_\-]{35}\b/,
      /\bsk_live_[0-9a-zA-Z]{16,}\b/,
      /(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["'][^"'\s]{8,}["']/i,
    ],
  },

  // ----------------------------------------------------- database / schema
  {
    id: "db-schema-destructive",
    type: "pattern",
    tier: "orange",
    blocking: true,
    title: "Destructive schema / data change",
    languages: ["*"],
    message: "Destructive migration. This can drop data or break backward compatibility — run it against a snapshot and confirm a rollback path.",
    patterns: [
      /\bDROP\s+(?:TABLE|COLUMN|DATABASE|INDEX|SCHEMA)\b/i,
      /\bTRUNCATE\s+(?:TABLE\s+)?\w/i,
      /\bDELETE\s+FROM\b(?![\s\S]*\bWHERE\b)/i,
    ],
  },
  {
    id: "db-schema-change",
    type: "pattern",
    tier: "orange",
    title: "Database schema change",
    languages: ["*"],
    message: "Schema migration. Confirm it is additive/backward-compatible and that dependent services are deployed in the right order.",
    patterns: [
      /\b(?:ALTER|CREATE)\s+TABLE\b/i,
      /\bADD\s+COLUMN\b/i,
      /\bRENAME\s+(?:TABLE|COLUMN|TO)\b/i,
    ],
  },
  {
    id: "raw-query",
    type: "pattern",
    tier: "yellow",
    title: "Raw database query",
    languages: ["*"],
    message: "Raw query. Make sure inputs are parameterized (no string concatenation) to avoid SQL injection.",
    patterns: [
      /\b(?:db|knex|prisma|sequelize|pool|client|conn|cursor|session)\.(?:query|raw|execute|exec)\s*\(/i,
      /\bINSERT\s+INTO\b/i,
      /\bUPDATE\b[^\n]*\bSET\b/i,
    ],
  },

  // -------------------------------------------------- auth / crypto / risk
  {
    id: "auth-crypto",
    type: "pattern",
    tier: "orange",
    title: "Authentication / cryptography logic",
    languages: ["*"],
    message: "Security-sensitive code. A subtle change here can silently weaken auth — get a second reviewer and add/keep tests.",
    patterns: [
      /\b(?:passport|jsonwebtoken|bcrypt|argon2|scrypt|oauth2?)\b/i,
      /\bjwt\.(?:sign|verify|decode)\b/i,
      /\bcrypto\.(?:createHash|createHmac|createCipheriv|pbkdf2|randomBytes)\b/,
      /\b(?:sign|verify)Token\b/,
      /\b(?:hash|compare)Password\b/i,
      /\b(?:authenticate|authorize|checkPermission|requireAuth|isAdmin)\b/,
    ],
  },
  {
    id: "dangerous-exec",
    type: "pattern",
    tier: "orange",
    title: "Dynamic execution / shell-out",
    languages: ["*"],
    message: "Dynamic code execution or shell-out. Audit for command/code injection — never pass unsanitized input here.",
    patterns: [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
      /\bchild_process\b/,
      /\.exec(?:Sync|File|FileSync)?\s*\(/,
      /\bspawn(?:Sync)?\s*\(/,
      /\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|pickle\.loads|yaml\.load|__import__)\s*\(/,
    ],
  },
  {
    id: "leftover-debugger",
    type: "pattern",
    tier: "yellow",
    title: "Leftover debugger statement",
    languages: JS,
    message: "A `debugger` statement will pause execution in dev tools — remove before merging.",
    patterns: [/\bdebugger\s*;?/],
  },

  // ---------------------------------------------------------- network i/o
  {
    id: "network-call",
    type: "pattern",
    tier: "yellow",
    title: "Outbound network call",
    languages: ["*"],
    message: "External call. Confirm the host, a sane timeout, retry/backoff, and error handling for failures.",
    patterns: [
      /\b(?:fetch|axios|got|superagent|XMLHttpRequest)\s*\(/,
      /\brequests\.(?:get|post|put|delete|patch)\s*\(/,
      /\bhttp\.(?:get|post|request)\s*\(/,
      /\burllib\.request\b/,
    ],
  },

  // ------------------------------------------------------------ low-noise
  {
    id: "debug-logging",
    type: "pattern",
    tier: "green",
    title: "Debug logging",
    languages: ["*"],
    message: "Local logging — safe, but remove temporary debug output before shipping.",
    patterns: [/\bconsole\.(?:log|debug|info|warn|error)\s*\(/, /\bSystem\.out\.print/, /\bfmt\.Print/],
  },
  {
    id: "todo-marker",
    type: "pattern",
    tier: "green",
    title: "TODO / FIXME marker",
    languages: ["*"],
    enabledByDefault: true,
    message: "Tracked work marker — fine to merge, but make sure it's captured somewhere.",
    patterns: [/\b(?:TODO|FIXME|HACK|XXX)\b/],
  },

  // ----------------------------------------------------- AST rules (JS/TS)
  {
    id: "public-api-change",
    type: "ast",
    tier: "orange",
    title: "Public API surface change",
    languages: JS,
    message: "This changes an exported symbol. Importers across the codebase (and possibly other repos) depend on it — check call sites.",
    visit(node: AstNode, _parent: AstNode | null, _ctx: RuleContext, emit: EmitFn) {
      if (
        node.type === "ExportNamedDeclaration" ||
        node.type === "ExportDefaultDeclaration" ||
        node.type === "ExportAllDeclaration"
      ) {
        emit(node as Parameters<EmitFn>[0]);
        return;
      }
      if (node.type === "AssignmentExpression") {
        const left = memberName(node.left as AstNode);
        if (left && (left === "module.exports" || left.startsWith("exports."))) {
          emit(node as Parameters<EmitFn>[0]);
        }
      }
    },
  },

  // ------------------------------------------------ injection / web security
  {
    id: "sql-injection",
    type: "pattern",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: ["*"],
    skipIfAst: true,
    message:
      "A SQL query is assembled via string interpolation or concatenation. " +
      "An attacker who controls any input variable can read, modify, or delete arbitrary data. " +
      "Use parameterized queries (e.g. `db.query(sql, [params])`) and never build SQL from request data.",
    patterns: [
      /\b(?:db|pool|conn|client|knex|sequelize|cursor|session)\.(?:query|raw|execute|exec)\s*\(\s*`[^`]*\$\{/i,
      /\b(?:db|pool|conn|client|knex|sequelize|cursor|session)\.(?:query|raw|execute|exec)\s*\(\s*["'][^"']*["']\s*\+/i,
      /`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^`]*\$\{(?:req|request|ctx|context)\./i,
      /["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+\s*(?:req|request|ctx)\./i,
    ],
  },
  {
    id: "sql-injection",
    type: "ast",
    tier: "orange",
    blocking: true,
    title: "SQL injection sink",
    languages: JS,
    message:
      "A SQL query is assembled via string interpolation or concatenation. " +
      "An attacker who controls any input variable can read, modify, or delete arbitrary data. " +
      "Use parameterized queries (e.g. `db.query(sql, [params])`) and never build SQL from request data.",
    visit(node: AstNode, _parent: AstNode | null, ctx: RuleContext, emit: EmitFn) {
      if (node.type === "TemplateLiteral" || (node.type === "BinaryExpression" && node.operator === "+")) {
        const text = getStaticText(node);
        if (isSqlQuery(text)) {
          if (isDynamicString(node, ctx)) {
            emit({
              loc: node.loc,
              code: (ctx.lines[node.loc!.start.line - 1] || "").trim(),
            });
          }
        }
      } else if (node.type === "CallExpression") {
        const name = memberName(node.callee as AstNode);
        if (name && /\b(query|execute|exec|raw|\$queryRaw)\b/i.test(name)) {
          const arg = (node as any).arguments?.[0] as AstNode | undefined;
          if (arg && isRequestData(arg)) {
            emit({
              loc: node.loc,
              code: (ctx.lines[node.loc!.start.line - 1] || "").trim(),
              message: "Dynamic request data passed directly as SQL query.",
            });
          }
        }
      }
    },
  },
  {
    id: "permissive-cors",
    type: "pattern",
    tier: "orange",
    blocking: false,
    title: "Permissive CORS policy",
    languages: ["*"],
    message:
      "CORS is configured to allow any origin (`*`). If authentication cookies or tokens are used, " +
      "arbitrary websites can make credentialed cross-origin requests to this API. " +
      "Set `origin` to an explicit allowlist of trusted domains.",
    patterns: [
      /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*['"`]\*['"`]/i,
      /\borigin\s*:\s*['"`]\*['"`]/,
      /['"]Access-Control-Allow-Origin['"]\s*[,)]\s*['"`]\*['"`]/,
      /\.setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"`]\*['"`]\)/,
    ],
  },
  {
    id: "xss-sink",
    type: "ast",
    tier: "orange",
    blocking: false,
    title: "XSS sink",
    languages: JS,
    message:
      "Writing to `innerHTML`, `outerHTML`, or `document.write()` injects raw HTML into the DOM. " +
      "If the value contains user-controlled data, an attacker can inject arbitrary JavaScript. " +
      "Use `textContent` for plain text, or sanitize with DOMPurify before setting innerHTML.",
    visit(node: AstNode, _parent: AstNode | null, ctx: RuleContext, emit: EmitFn) {
      if (node.type === "AssignmentExpression" && node.operator === "=") {
        const left = memberName(node.left as AstNode);
        if (left && (left.endsWith(".innerHTML") || left.endsWith(".outerHTML"))) {
          if (isDynamicString(node.right as AstNode, ctx)) {
            emit({
              loc: node.loc,
              code: (ctx.lines[node.loc!.start.line - 1] || "").trim(),
            });
          }
        }
      } else if (node.type === "CallExpression") {
        const name = memberName(node.callee as AstNode);
        if (name && (
          name === "document.write" || name === "document.writeln" ||
          name.endsWith(".insertAdjacentHTML")
        )) {
          const arg = (node as any).arguments?.[0] as AstNode | undefined;
          if (arg && isDynamicString(arg, ctx)) {
            emit({
              loc: node.loc,
              code: (ctx.lines[node.loc!.start.line - 1] || "").trim(),
            });
          }
        }
      }
    },
  },
  {
    id: "path-traversal",
    type: "pattern",
    tier: "orange",
    blocking: false,
    title: "Path traversal sink",
    languages: ["*"],
    skipIfAst: true,
    message:
      "A file path is constructed from request-controlled data (`req.params`, `req.query`, `req.body`). " +
      "Without canonicalization and a root-prefix check, an attacker can read arbitrary files via `../../etc/passwd`. " +
      "Use `path.resolve()`, then assert the result starts with your allowed base directory before opening the file.",
    patterns: [
      /\bpath\.(?:join|resolve|normalize)\s*\([^)]*(?:req|request|ctx)\.(?:params|query|body)\b/i,
      /\bfs\.(?:readFile|readFileSync|createReadStream|open|openSync)\s*\([^)]*(?:req|request|ctx)\.(?:params|query|body)\b/i,
      /(?:__dirname|process\.cwd\(\))\s*,\s*(?:req|request|ctx)\.(?:params|query|body)\b/i,
    ],
  },
  {
    id: "path-traversal",
    type: "ast",
    tier: "orange",
    blocking: false,
    title: "Path traversal sink",
    languages: JS,
    message:
      "A file path is constructed from request-controlled data (`req.params`, `req.query`, `req.body`). " +
      "Without canonicalization and a root-prefix check, an attacker can read arbitrary files via `../../etc/passwd`. " +
      "Use `path.resolve()`, then assert the result starts with your allowed base directory before opening the file.",
    visit(node: AstNode, _parent: AstNode | null, ctx: RuleContext, emit: EmitFn) {
      if (node.type === "CallExpression") {
        const name = memberName(node.callee as AstNode);
        if (name && (
          /\b(fs|fs\/promises)\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|open|openSync|rm|rmSync|unlink|unlinkSync)\b/.test(name) ||
          /\bpath\.(join|resolve|normalize)\b/.test(name)
        )) {
          const hasInput = ((node as any).arguments || []).some((arg: any) => containsRequestData(arg, ctx));
          if (hasInput) {
            emit({
              loc: node.loc,
              code: (ctx.lines[node.loc!.start.line - 1] || "").trim(),
            });
          }
        }
      }
    },
  },
  {
    id: "nosql-injection",
    type: "pattern",
    tier: "orange",
    blocking: false,
    title: "NoSQL injection sink",
    languages: ["*"],
    message:
      "MongoDB `$where`, `db.eval()`, or passing a raw request object as a query filter enables server-side JS execution " +
      "or operator injection. An attacker can bypass authentication by sending `{ password: { $gt: '' } }`. " +
      "Use typed query operators (`$eq`, `$in`, etc.) and never pass `req.body` directly as a filter.",
    patterns: [
      /\$where\s*:/,
      /\bdb\.eval\s*\(/i,
      /\.mapReduce\s*\(\s*(?!['"]function)/i,
      /\.find(?:One)?\s*\(\s*(?:req|request|ctx)\.(?:body|query|params)\s*[,)]/i,
    ],
  },
  {
    id: "prototype-pollution",
    type: "pattern",
    tier: "orange",
    blocking: false,
    title: "Prototype pollution sink",
    languages: JS,
    message:
      "Merging request data into an existing object with `Object.assign`, `_.merge`, or spread can let an attacker " +
      "set `__proto__` or `constructor` properties, corrupting the prototype chain for all objects in the process. " +
      "Validate/whitelist incoming keys, or always spread into a fresh `{}` rather than an existing object.",
    patterns: [
      /\bObject\.assign\s*\(\s*(?!\s*\{[^}]*\})[^,)]+,\s*(?:req|request|ctx)\.(?:body|query|params)\b/i,
      /\b(?:_\.merge|lodash\.merge)\s*\([^,)]+,\s*(?:req|request|ctx)\.(?:body|query|params)\b/i,
      /\b(?:this\.\w+|[a-zA-Z_$][\w$]*(?:\[.*?\]|\.\w+)+)\s*=\s*\{\s*\.\.\.(?:req|request|ctx)\.(?:body|query|params)\b/i,
    ],
  },
];

// ---------------------------------------------------------------------------
// Config-derived rules
// ---------------------------------------------------------------------------

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function deprecatedRules(config: Partial<Config>): Rule[] {
  const entries = Array.isArray((config as Record<string, unknown>)?.["deprecated"])
    ? ((config as Record<string, unknown>)["deprecated"] as DeprecatedEntry[])
    : [];
  if (entries.length === 0) return [];

  const byName = new Map<string, DeprecatedEntry>();
  for (const e of entries) {
    if (!e || !e.pattern) continue;
    const name = e.pattern.replace(/\(.*$/, "").trim();
    byName.set(name, e);
  }
  if (byName.size === 0) return [];

  const describe = (e: DeprecatedEntry): string => {
    const bits = [`Deprecated — use \`${e.replacedBy}\` instead.`];
    if (e.author) bits.push(`Owner: ${e.author}.`);
    if (e.pr) bits.push(`See ${e.pr}.`);
    return bits.join(" ");
  };

  const astRule: Rule = {
    id: "deprecated-api",
    type: "ast",
    tier: "yellow",
    title: "Deprecated API",
    languages: JS,
    visit(node: AstNode, parent: AstNode | null, _ctx: RuleContext, emit: EmitFn) {
      if (node.type === "CallExpression") {
        const callee = node.callee as AstNode | undefined;
        const name = (callee ? memberName(callee) : null) || ((callee as AstNode & { name?: string })?.name ?? null);
        const meta = name && byName.get(name);
        if (meta) {
          const newCallee = String(meta.replacedBy).replace(/\(.*$/, "").trim();
          const calleeLoc = (node.callee as AstNode).loc;
          emit({
            loc: node.loc,
            message: describe(meta),
            tier: meta.tier,
            fix:
              newCallee && newCallee !== name && calleeLoc
                ? {
                    title: `Replace with ${newCallee}`,
                    startLine: calleeLoc.start.line,
                    startColumn: calleeLoc.start.column,
                    endLine: calleeLoc.end.line,
                    endColumn: calleeLoc.end.column,
                    newText: newCallee,
                  }
                : null,
          });
        }
        return;
      }
      if (node.type === "MemberExpression" && !(parent && parent.type === "CallExpression" && parent.callee === node)) {
        const name = memberName(node);
        const meta = name && byName.get(name);
        if (meta) emit({ loc: node.loc, message: describe(meta), tier: meta.tier });
      }
    },
  };

  const patterns = [...byName.keys()].map((n) => new RegExp(`\\b${escapeRegExp(n)}\\s*\\(`));
  const patternRule: Rule = {
    id: "deprecated-api",
    type: "pattern",
    tier: "yellow",
    title: "Deprecated API",
    languages: ["*"],
    skipIfAst: true,
    patterns,
    message(matchText: string) {
      for (const [name, meta] of byName) {
        if (matchText.includes(name)) return describe(meta);
      }
      return "Deprecated API.";
    },
  };

  return [astRule, patternRule];
}

export function customPatternRules(config: Partial<Config>): Rule[] {
  const list = config?.customPatterns ?? [];
  return list
    .map((c, i) => {
      if (!c.pattern && !c.patterns) return null;
      const raw = c.patterns || (c.pattern ? [c.pattern] : []);
      const patterns = raw
        .map((p) => {
          try {
            return p instanceof RegExp ? p : new RegExp(p, c.flags || "i");
          } catch {
            return new RegExp(escapeRegExp(String(p)), "i");
          }
        })
        .filter(Boolean) as RegExp[];
      if (patterns.length === 0) return null;
      return {
        id: c.id || `custom-${i + 1}`,
        type: "pattern" as const,
        tier: (c.tier || "yellow") as Rule["tier"],
        blocking: !!c.blocking,
        title: c.title || "Custom rule",
        languages: c.languages || ["*"],
        message: c.message || "Matched a project-defined DiffGate pattern.",
        patterns,
      } as Rule;
    })
    .filter((r): r is Rule => r !== null);
}

export function legacyOrangeRules(config: Partial<Config>): Rule[] {
  const list = Array.isArray(config.orangePatterns) ? config.orangePatterns : [];
  if (list.length === 0) return [];
  const patterns = list.map((p) => {
    try {
      return new RegExp(p, "i");
    } catch {
      return new RegExp(escapeRegExp(p), "i");
    }
  });
  return [
    {
      id: "configured-high-impact",
      type: "pattern",
      tier: "orange",
      title: "Configured high-impact pattern",
      languages: ["*"],
      patterns,
      message: "Matched a high-impact pattern from your .diffgate.json config.",
    },
  ];
}

export const RULE_PACKS: Record<string, string[]> = {
  "web-security": [
    "hardcoded-secret",
    "permissive-cors",
    "sql-injection",
    "nosql-injection",
    "path-traversal",
    "prototype-pollution",
    "xss-sink",
  ],
  "compatibility": [
    "public-api-change",
    "signature-drift",
  ],
  "hygiene": [
    "leftover-debugger",
    "debug-logging",
    "todo-marker",
  ],
};
