import { TsTree, TsNode, AstNode } from '../types.js';
import { walk, memberName } from '../parsers/javascript.js';

export interface DetectedEntryPoint {
  /** Qualified name of the handler function (e.g. "UserController.create"). */
  qualName: string;
  /** Kind of entry point. */
  kind: "http_handler" | "event_handler";
  /** HTTP route when detectable (e.g. "GET /users"). */
  route?: string;
  /** File path. */
  file: string;
  /** 1-based line number. */
  line: number;
  /** Line span of the handler's own body, for DSL-style routes with no separate named function
   *  (Sinatra/Ktor/Laravel/minimal-API closures, Go inline handlers) — a sink whose line falls in
   *  this range is reachable even though nothing calls a function literally named `qualName`. */
  bodyRange?: { startLine: number; endLine: number };
}

const CLASS_TYPES = [
  'class_definition', 'class_declaration', 'interface_declaration',
  'object_declaration', 'class', 'record_declaration'
];

function enclosingClassName(node: TsNode): string | null {
  let curr: TsNode | null = node.parent;
  while (curr) {
    if (CLASS_TYPES.includes(curr.type)) {
      const nameNode = curr.childForFieldName('name');
      if (nameNode) return nameNode.text;
      
      for (let i = 0; i < curr.namedChildCount; i++) {
        const child = curr.namedChild(i);
        if (child && child.type.includes('identifier')) {
          return child.text;
        }
      }
    }
    curr = curr.parent;
  }
  return null;
}

function stringLiteralValue(node: TsNode | null | undefined): string | null {
  if (!node) return null;
  const text = node.text;
  if (!text) return null;
  if (/^['"`]/.test(text) && /['"`]$/.test(text) && text.length >= 2) {
    return text.substring(1, text.length - 1);
  }
  return text;
}

function detectPython(tree: TsTree, file: string): DetectedEntryPoint[] {
  const root = (tree as any).rootNode || tree;
  const results: DetectedEntryPoint[] = [];
  const decorated = root.descendantsOfType('decorated_definition');
  
  for (const def of decorated) {
    const decorators = def.descendantsOfType('decorator');
    let funcDef: TsNode | null = null;
    
    for (let i = 0; i < def.namedChildCount; i++) {
      const child = def.namedChild(i);
      if (child && child.type === 'function_definition') {
        funcDef = child;
        break;
      }
    }
    if (!funcDef) continue;
    
    let isEntry = false;
    let route: string | undefined;
    
    for (const dec of decorators) {
      const text = dec.text.toLowerCase();
      if (text.includes('route') || text.includes('get') || text.includes('post') || 
          text.includes('put') || text.includes('delete') || text.includes('patch') ||
          text.includes('api_view') || text.includes('websocket')) {
        isEntry = true;
        const strings = dec.descendantsOfType('string');
        if (strings.length > 0) {
          route = stringLiteralValue(strings[0]) || undefined;
        }
        break;
      }
    }
    
    if (isEntry) {
      const nameNode = funcDef.childForFieldName('name');
      const funcName = nameNode ? nameNode.text : 'unknown';
      const className = enclosingClassName(def);
      const qualName = className ? `${className}.${funcName}` : funcName;
      
      results.push({
        qualName,
        kind: 'http_handler',
        route,
        file,
        line: funcDef.startPosition.row + 1
      });
    }
  }
  return results;
}

function detectGo(tree: TsTree, file: string): DetectedEntryPoint[] {
  const root = (tree as any).rootNode || tree;
  const results: DetectedEntryPoint[] = [];
  
  const calls = root.descendantsOfType('call_expression');
  for (const call of calls) {
    const funcNode = call.childForFieldName('function');
    if (funcNode && funcNode.type === 'selector_expression') {
      const fieldNode = funcNode.childForFieldName('field');
      if (fieldNode && /^(HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Any|Group)$/.test(fieldNode.text)) {
        const args = call.childForFieldName('arguments');
        if (args && args.namedChildCount >= 2) {
          const routeNode = args.namedChild(0);
          const handlerNode = args.namedChild(args.namedChildCount - 1);
          
          if (routeNode && handlerNode) {
            const route = stringLiteralValue(routeNode) || undefined;
            let qualName = 'anonymous_handler';
            const isNamed = handlerNode.type === 'identifier' || handlerNode.type === 'selector_expression';
            if (isNamed) qualName = handlerNode.text;

            results.push({
              qualName,
              kind: 'http_handler',
              route,
              file,
              line: call.startPosition.row + 1,
              // An inline func literal has no separate definition for the call graph to name —
              // fall back to the registration call's own span as the handler body.
              ...(isNamed ? {} : { bodyRange: { startLine: call.startPosition.row + 1, endLine: call.endPosition.row + 1 } })
            });
          }
        }
      }
    }
  }
  
  const funcDefs = root.descendantsOfType('function_declaration');
  for (const fn of funcDefs) {
    const params = fn.childForFieldName('parameters');
    if (params && params.text.includes('http.ResponseWriter') && params.text.includes('*http.Request')) {
      const nameNode = fn.childForFieldName('name');
      const qualName = nameNode ? nameNode.text : 'unknown';
      
      results.push({
        qualName,
        kind: 'http_handler',
        file,
        line: fn.startPosition.row + 1
      });
    }
  }
  
  const unique = new Map<string, DetectedEntryPoint>();
  for (const r of results) {
    unique.set(`${r.qualName}-${r.line}`, r);
  }
  return Array.from(unique.values());
}

function detectJava(tree: TsTree, file: string): DetectedEntryPoint[] {
  const root = (tree as any).rootNode || tree;
  const results: DetectedEntryPoint[] = [];
  
  const methods = root.descendantsOfType('method_declaration');
  for (const method of methods) {
    const modifiers = method.childForFieldName('modifiers');
    if (!modifiers) continue;
    
    let isEntry = false;
    let route: string | undefined;
    let kind: "http_handler" | "event_handler" = 'http_handler';
    
    const annotations = [...modifiers.descendantsOfType('annotation'), ...modifiers.descendantsOfType('marker_annotation')];
    
    for (const ann of annotations) {
      const nameNode = ann.childForFieldName('name');
      const name = nameNode ? nameNode.text : ann.text.replace(/^@/, '').split('(')[0];
      
      if (/^(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|Path)$/.test(name)) {
        isEntry = true;
        const strings = ann.descendantsOfType('string_literal');
        if (strings.length > 0) route = stringLiteralValue(strings[0]) || undefined;
      } else if (/^(MessageMapping|EventHandler)$/.test(name)) {
        isEntry = true;
        kind = 'event_handler';
      }
    }
    
    if (isEntry) {
      const nameNode = method.childForFieldName('name');
      const funcName = nameNode ? nameNode.text : 'unknown';
      const className = enclosingClassName(method);
      const qualName = className ? `${className}.${funcName}` : funcName;
      
      results.push({
        qualName,
        kind,
        route,
        file,
        line: method.startPosition.row + 1
      });
    }
  }
  return results;
}

function detectKotlin(tree: TsTree, file: string): DetectedEntryPoint[] {
  const root = (tree as any).rootNode || tree;
  const results: DetectedEntryPoint[] = [];
  
  const funcs = root.descendantsOfType('function_declaration');
  for (const fn of funcs) {
    const modifiers = fn.childForFieldName('modifiers');
    let isEntry = false;
    let route: string | undefined;
    let kind: "http_handler" | "event_handler" = 'http_handler';
    
    if (modifiers) {
      const annotations = modifiers.descendantsOfType('annotation');
      for (const ann of annotations) {
        const text = ann.text;
        if (text.includes('Mapping') || text.includes('Path')) {
          isEntry = true;
          const strings = ann.descendantsOfType('string_literal');
          if (strings.length > 0) route = stringLiteralValue(strings[0]) || undefined;
        } else if (text.includes('EventHandler') || text.includes('MessageMapping')) {
          isEntry = true;
          kind = 'event_handler';
        }
      }
    }
    
    if (isEntry) {
      let funcName = 'unknown';
      for (let i = 0; i < fn.namedChildCount; i++) {
        const child = fn.namedChild(i);
        if (child && (child.type === 'simple_identifier' || child.type === 'identifier')) {
          funcName = child.text;
          break;
        }
      }
      
      const className = enclosingClassName(fn);
      const qualName = className ? `${className}.${funcName}` : funcName;
      
      results.push({
        qualName,
        kind,
        route,
        file,
        line: fn.startPosition.row + 1
      });
    }
  }
  
  const calls = root.descendantsOfType('call_expression');
  for (const call of calls) {
    const nav = call.text;
    if (nav.startsWith('get(') || nav.startsWith('post(') || nav.startsWith('put(') || 
        nav.startsWith('delete(') || nav.startsWith('patch(') || nav.startsWith('route(')) {
      
      const hasLambda = call.descendantsOfType('lambda_literal').length > 0 || call.descendantsOfType('annotated_lambda').length > 0;
      if (hasLambda) {
        const strings = call.descendantsOfType('string_literal');
        const route = strings.length > 0 ? stringLiteralValue(strings[0]) || undefined : undefined;

        results.push({
          qualName: 'ktor_handler',
          kind: 'http_handler',
          route,
          file,
          line: call.startPosition.row + 1,
          bodyRange: { startLine: call.startPosition.row + 1, endLine: call.endPosition.row + 1 }
        });
      }
    }
  }
  return results;
}

function detectRuby(tree: TsTree, file: string): DetectedEntryPoint[] {
  const root = (tree as any).rootNode || tree;
  const results: DetectedEntryPoint[] = [];
  
  const calls = [...root.descendantsOfType('call'), ...root.descendantsOfType('command')];
  for (const call of calls) {
    const methodNode = call.childForFieldName('method') || call.namedChild(0);
    if (methodNode && /^(get|post|put|delete|patch)$/.test(methodNode.text)) {
      const strings = call.descendantsOfType('string');
      const route = strings.length > 0 ? stringLiteralValue(strings[0]) || undefined : undefined;
      results.push({
        qualName: `sinatra_${methodNode.text}`,
        kind: 'http_handler',
        route,
        file,
        line: call.startPosition.row + 1,
        bodyRange: { startLine: call.startPosition.row + 1, endLine: call.endPosition.row + 1 }
      });
    }
  }
  
  if (file.endsWith('_controller.rb')) {
    const methods = root.descendantsOfType('method');
    for (const m of methods) {
      const nameNode = m.childForFieldName('name') || m.namedChild(0);
      const funcName = nameNode ? nameNode.text : 'unknown';
      const className = enclosingClassName(m);
      const qualName = className ? `${className}#${funcName}` : funcName;
      
      results.push({
        qualName,
        kind: 'http_handler',
        file,
        line: m.startPosition.row + 1
      });
    }
  }
  
  return results;
}

function detectPHP(tree: TsTree, file: string): DetectedEntryPoint[] {
  const root = (tree as any).rootNode || tree;
  const results: DetectedEntryPoint[] = [];
  
  const calls = root.descendantsOfType('scoped_call_expression');
  for (const call of calls) {
    const scope = call.childForFieldName('scope');
    const name = call.childForFieldName('name');
    if (scope && scope.text === 'Route' && name && /^(get|post|put|delete|patch|any|match)$/.test(name.text)) {
      const args = call.childForFieldName('arguments');
      const strings = args ? args.descendantsOfType('string') : [];
      const route = strings.length > 0 ? stringLiteralValue(strings[0]) || undefined : undefined;

      results.push({
        qualName: 'laravel_route',
        kind: 'http_handler',
        route,
        file,
        line: call.startPosition.row + 1,
        bodyRange: { startLine: call.startPosition.row + 1, endLine: call.endPosition.row + 1 }
      });
    }
  }
  
  const methods = root.descendantsOfType('method_declaration');
  for (const m of methods) {
    const attrs = m.descendantsOfType('attribute');
    let isEntry = false;
    let route: string | undefined;
    
    for (const attr of attrs) {
      const nameNode = attr.childForFieldName('name');
      if (nameNode && /^(Route|Get|Post|Put|Delete)$/.test(nameNode.text)) {
        isEntry = true;
        const strings = attr.descendantsOfType('string');
        if (strings.length > 0) route = stringLiteralValue(strings[0]) || undefined;
      }
    }
    
    if (isEntry) {
      const nameNode = m.childForFieldName('name');
      const funcName = nameNode ? nameNode.text : 'unknown';
      const className = enclosingClassName(m);
      const qualName = className ? `${className}::${funcName}` : funcName;
      
      results.push({
        qualName,
        kind: 'http_handler',
        route,
        file,
        line: m.startPosition.row + 1
      });
    }
  }
  
  return results;
}

function detectCSharp(tree: TsTree, file: string): DetectedEntryPoint[] {
  const root = (tree as any).rootNode || tree;
  const results: DetectedEntryPoint[] = [];
  
  const methods = root.descendantsOfType('method_declaration');
  for (const m of methods) {
    const attrs = m.descendantsOfType('attribute');
    let isEntry = false;
    let route: string | undefined;
    
    for (const attr of attrs) {
      const nameNode = attr.childForFieldName('name');
      if (nameNode && /^(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)$/.test(nameNode.text)) {
        isEntry = true;
        const strings = attr.descendantsOfType('string_literal');
        if (strings.length > 0) route = stringLiteralValue(strings[0]) || undefined;
      }
    }
    
    if (isEntry) {
      const nameNode = m.childForFieldName('name');
      const funcName = nameNode ? nameNode.text : 'unknown';
      const className = enclosingClassName(m);
      const qualName = className ? `${className}.${funcName}` : funcName;
      
      results.push({
        qualName,
        kind: 'http_handler',
        route,
        file,
        line: m.startPosition.row + 1
      });
    }
  }
  
  const invocations = root.descendantsOfType('invocation_expression');
  for (const inv of invocations) {
    const funcNode = inv.childForFieldName('function') || inv.namedChild(0);
    if (funcNode && /Map(Get|Post|Put|Delete)/.test(funcNode.text)) {
      const args = inv.childForFieldName('arguments');
      const strings = args ? args.descendantsOfType('string_literal') : [];
      const route = strings.length > 0 ? stringLiteralValue(strings[0]) || undefined : undefined;
      
      results.push({
        qualName: 'minimal_api_handler',
        kind: 'http_handler',
        route,
        file,
        line: inv.startPosition.row + 1,
        bodyRange: { startLine: inv.startPosition.row + 1, endLine: inv.endPosition.row + 1 }
      });
    }
  }
  
  return results;
}

/** JS/TS has no tree-sitter grammar in this build — its entry points come off the Babel AST via
 *  `detectJsEntryPoints` below, called from buildCallGraph's JS branch. */
function detectJsTs(_tree: TsTree, _file: string): DetectedEntryPoint[] {
  return [];
}

const HTTP_VERBS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "all"]);
/** Router-ish receivers for `x.get("/p", handler)`. Guards against `map.get(k)` / `cache.delete(k)`
 *  being read as routes — those take no function argument either, but the name check is cheaper. */
const ROUTER_RECEIVERS = /^(app|router|server|api|fastify|express|http|https|_router)$/i;
/** Next.js app-router segment handlers and similar named-export HTTP entry points. */
const EXPORTED_HTTP_NAMES = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "handler", "middleware"]);
const EVENT_REGISTRARS = new Set(["addEventListener", "on", "once", "subscribe", "addListener"]);
/** `.on(...)` is far too broad to treat as untrusted input on its own — `process.on("exit", …)` or
 *  `db.on("error", …)` are not request paths, and escalating a sink inside them would be a false
 *  block. Only events that actually carry data from outside the process count. */
const UNTRUSTED_EVENTS = new Set([
  "message", "connection", "connect", "request", "data", "upgrade", "push", "fetch", "notification", "submit"
]);

const FN_NODES = new Set(["FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration"]);

function jsLine(node: AstNode | null | undefined, which: "start" | "end"): number {
  const loc = (node as unknown as { loc?: { start: { line: number }; end: { line: number } } } | undefined)?.loc;
  return loc ? loc[which].line : 0;
}

function jsBodyRange(fn: AstNode): { startLine: number; endLine: number } | undefined {
  const start = jsLine(fn, "start");
  const end = jsLine(fn, "end");
  return start && end ? { startLine: start, endLine: end } : undefined;
}

function stringArg(node: AstNode | undefined): string | null {
  if (!node) return null;
  if (node.type === "StringLiteral") return (node as unknown as { value?: string }).value ?? null;
  return null;
}

/**
 * Entry points in a JS/TS Babel AST: Express/Fastify/Koa-style route registrations, Next.js and
 * serverless handler exports, and event-listener registrations. Inline handlers (the common case —
 * `app.get("/u/:id", async (req, res) => …)`) get a `bodyRange` so a sink inside the closure counts
 * as reachable without any named function to match on.
 */
export function detectJsEntryPoints(ast: AstNode, file: string): DetectedEntryPoint[] {
  const results: DetectedEntryPoint[] = [];
  const seen = new Set<string>();

  const push = (ep: DetectedEntryPoint) => {
    const key = `${ep.qualName}:${ep.line}:${ep.bodyRange?.startLine ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    results.push(ep);
  };

  /** Register the handler argument(s) of a route/listener call. */
  const pushHandlers = (
    args: AstNode[], qualName: string, kind: DetectedEntryPoint["kind"], route: string | undefined, line: number
  ) => {
    let found = false;
    for (const arg of args) {
      if (!arg || typeof arg.type !== "string") continue;
      if (FN_NODES.has(arg.type)) {
        // Inline closure — the body span is what reachability matches against.
        push({ qualName, kind, route, file, line, bodyRange: jsBodyRange(arg) });
        found = true;
      } else if (arg.type === "Identifier") {
        // Named handler passed by reference: the call graph resolves it by name.
        push({ qualName: (arg as unknown as { name: string }).name, kind, route, file, line });
        found = true;
      } else if (arg.type === "MemberExpression") {
        const bare = memberName(arg)?.split(".").pop();
        if (bare) { push({ qualName: bare, kind, route, file, line }); found = true; }
      }
    }
    return found;
  };

  walk(ast, (node, parent) => {
    // 1. Route registration: app.get("/path", handler) / router.post(...) / app.use(mw)
    if (node.type === "CallExpression") {
      const callee = node.callee as AstNode | undefined;
      const args = ((node as unknown as { arguments?: AstNode[] }).arguments || []) as AstNode[];
      const line = jsLine(node, "start");

      if (callee && callee.type === "MemberExpression" && !callee.computed) {
        const full = memberName(callee) || "";
        const prop = full.split(".").pop() || "";
        const receiver = full.split(".")[0] || "";
        const isRouterish = ROUTER_RECEIVERS.test(receiver) || /router$/i.test(receiver) || /^\$?(app|route)/i.test(receiver);

        if (HTTP_VERBS.has(prop.toLowerCase()) && isRouterish) {
          const route = stringArg(args[0]);
          pushHandlers(args, `${full}@${line}`, "http_handler",
            route ? `${prop.toUpperCase()} ${route}` : prop.toUpperCase(), line);
        } else if ((prop === "use" || prop === "route" || prop === "register") && isRouterish) {
          pushHandlers(args, `${full}@${line}`, "http_handler", stringArg(args[0]) || undefined, line);
        } else if (EVENT_REGISTRARS.has(prop)) {
          const evt = stringArg(args[0]);
          // DOM listeners are user input by definition; everything else must name a known
          // outside-the-process event.
          const untrusted = prop === "addEventListener" ? !!evt : !!evt && UNTRUSTED_EVENTS.has(evt.toLowerCase());
          if (untrusted) pushHandlers(args, `${full}@${line}`, "event_handler", evt!, line);
        }
      }
      return;
    }

    // 2. Handler exports: `export default function handler(req, res)`, `export async function GET()`,
    //    `export const handler = …`, `exports.handler = …`, `module.exports.handler = …`.
    if (node.type === "ExportDefaultDeclaration" || node.type === "ExportNamedDeclaration") {
      const decl = (node as unknown as { declaration?: AstNode }).declaration;
      if (!decl) return;
      if (FN_NODES.has(decl.type)) {
        const name = (decl as unknown as { id?: { name?: string } }).id?.name;
        const isDefault = node.type === "ExportDefaultDeclaration";
        if (!isDefault && !(name && EXPORTED_HTTP_NAMES.has(name))) return;
        if (isDefault && !isHandlerFile(file) && !(name && EXPORTED_HTTP_NAMES.has(name))) return;
        push({
          qualName: name || `default@${jsLine(decl, "start")}`,
          kind: "http_handler", route: name, file, line: jsLine(decl, "start"), bodyRange: jsBodyRange(decl)
        });
      } else if (decl.type === "VariableDeclaration") {
        for (const d of ((decl as unknown as { declarations?: AstNode[] }).declarations || [])) {
          const id = (d as unknown as { id?: { name?: string } }).id?.name;
          const init = (d as unknown as { init?: AstNode }).init;
          if (!id || !init || !EXPORTED_HTTP_NAMES.has(id) || !FN_NODES.has(init.type)) continue;
          push({ qualName: id, kind: "http_handler", route: id, file, line: jsLine(init, "start"), bodyRange: jsBodyRange(init) });
        }
      }
      return;
    }

    if (node.type === "AssignmentExpression") {
      const left = (node as unknown as { left?: AstNode }).left;
      const right = (node as unknown as { right?: AstNode }).right;
      if (!left || !right || !FN_NODES.has(right.type)) return;
      const full = memberName(left);
      if (!full || !/^(exports|module\.exports)\.\w+$/.test(full)) return;
      const bare = full.split(".").pop()!;
      if (!EXPORTED_HTTP_NAMES.has(bare)) return;
      push({ qualName: bare, kind: "http_handler", route: bare, file, line: jsLine(right, "start"), bodyRange: jsBodyRange(right) });
      return;
    }

    void parent;
  });

  return results;
}

/** Convention-based HTTP entry files: Next.js pages/app routes, serverless function dirs. */
function isHandlerFile(file: string): boolean {
  const p = file.replace(/\\/g, "/");
  return /\/pages\/api\//.test(p) || /\/app\/.*\/route\.(t|j)sx?$/.test(p) ||
    /\/api\//.test(p) || /\/functions\//.test(p) || /\/handlers?\//.test(p);
}

const DETECTORS: Record<string, (tree: TsTree, file: string) => DetectedEntryPoint[]> = {
  python: detectPython,
  go: detectGo,
  java: detectJava,
  kotlin: detectKotlin,
  ruby: detectRuby,
  php: detectPHP,
  csharp: detectCSharp,
  'c#': detectCSharp,
  javascript: detectJsTs,
  typescript: detectJsTs,
  javascriptreact: detectJsTs,
  typescriptreact: detectJsTs
};

/**
 * Detect framework entry points (HTTP/event handlers) in a tree-sitter AST.
 * Returns qualified names of functions that serve as entry points.
 * 
 * @param tree - The parsed Tree-Sitter AST
 * @param file - The file path being processed
 * @param language - The language of the file
 * @returns Array of detected entry points
 */
export function detectEntryPoints(
  tree: TsTree,
  file: string,
  language: string
): DetectedEntryPoint[] {
  const detector = DETECTORS[language.toLowerCase()];
  if (!detector) return [];
  try {
    return detector(tree, file);
  } catch (e) {
    return [];
  }
}
