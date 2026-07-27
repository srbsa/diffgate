import fs from "fs";
import path from "path";
import { TsTree, TsNode, AstNode, Config } from "../types.js";
import { parseTs, treeSitterReady } from "../parsers/treesitter.js";
import { detectLanguage, AST_LANGUAGES } from "../parsers/index.js";
import { parseJs } from "../parsers/javascript.js";
import { extractJs } from "./callgraph-js.js";
import { isIgnored, IGNORE_DIR_NAMES } from "../config.js";
import { isGitIgnoredPath } from "../git.js";

export interface FnDef {
  name: string;
  qualName: string;
  file: string;
  startLine: number;
  endLine: number;
  language: string;
}

export interface CallSite {
  calleeName: string;
  callerQualName: string;
  file: string;
  line: number;
}

export interface CallGraph {
  /** All function definitions, keyed by bare name (may have multiple defs for overloads). */
  functions: Map<string, FnDef[]>;
  /** Class/interface declarations, keyed by bare name. Deliberately separate from `functions`:
   *  a class spans its whole body, so folding it in would let `resolveEnclosingFunction` return the
   *  class instead of the method a line actually sits in. Used only to detect same-name collisions
   *  when answering `impact()` for a type symbol. */
  types: Map<string, FnDef[]>;
  /** Call sites keyed by callee bare name → list of call sites that call it. */
  callers: Map<string, CallSite[]>;
  /** Qualified function names that are framework entry points (detected by entry-points.ts). */
  entryPointNames: Set<string>;
  /** True when the walk hit its file or time budget and stopped early. A partial graph may be
   *  missing callers and entry points, so "no path found" is unknown, not proven-unreachable. */
  partial: boolean;
}

interface CallGraphProfile {
  fnTypes: Set<string>;
  fnNameField: string;
  callType: string;
  extraCallTypes?: string[];
  calleeExtractor?: (node: TsNode) => string | null;
}

const CALL_GRAPH_PROFILES: Record<string, CallGraphProfile> = {
  python: {
    fnTypes: new Set(["function_definition"]),
    fnNameField: "name",
    callType: "call",
    calleeExtractor: (node: TsNode) => {
      const funcNode = node.childForFieldName("function");
      if (!funcNode) return null;
      if (funcNode.type === "attribute") {
        const id = funcNode.descendantsOfType("identifier").pop();
        return id ? id.text : null;
      }
      return funcNode.text;
    }
  },
  go: {
    fnTypes: new Set(["function_declaration", "method_declaration"]),
    fnNameField: "name",
    callType: "call_expression",
    calleeExtractor: (node: TsNode) => {
      const funcNode = node.childForFieldName("function");
      if (!funcNode) return null;
      if (funcNode.type === "selector_expression") {
        const id = funcNode.descendantsOfType("field_identifier").pop();
        return id ? id.text : null;
      }
      return funcNode.text;
    }
  },
  java: {
    fnTypes: new Set(["method_declaration", "constructor_declaration"]),
    fnNameField: "name",
    callType: "method_invocation",
    calleeExtractor: (node: TsNode) => {
      const nameNode = node.childForFieldName("name");
      return nameNode ? nameNode.text : null;
    }
  },
  kotlin: {
    fnTypes: new Set(["function_declaration"]),
    fnNameField: "name",
    callType: "call_expression",
    calleeExtractor: (node: TsNode) => {
      const nav = node.parent?.type === "navigation_expression" ? node.parent : null;
      if (nav) {
        const id = nav.descendantsOfType("simple_identifier").pop();
        if (id) return id.text;
      }
      const child = node.namedChild(0);
      return child ? child.text : null;
    }
  },
  ruby: {
    fnTypes: new Set(["method", "singleton_method"]),
    fnNameField: "name",
    callType: "call",
    calleeExtractor: (node: TsNode) => {
      const methodNode = node.childForFieldName("method");
      return methodNode ? methodNode.text : null;
    }
  },
  php: {
    fnTypes: new Set(["function_definition", "method_declaration"]),
    fnNameField: "name",
    callType: "function_call_expression",
    extraCallTypes: ["member_call_expression", "scoped_call_expression"],
    calleeExtractor: (node: TsNode) => {
      if (node.type === "function_call_expression") {
        const funcNode = node.childForFieldName("function");
        return funcNode ? funcNode.text : null;
      }
      const nameNode = node.childForFieldName("name");
      return nameNode ? nameNode.text : null;
    }
  },
  csharp: {
    fnTypes: new Set(["method_declaration", "constructor_declaration", "local_function_statement"]),
    fnNameField: "name",
    callType: "invocation_expression",
    calleeExtractor: (node: TsNode) => {
      const funcNode = node.childForFieldName("function");
      if (!funcNode) return null;
      if (funcNode.type === "member_access_expression") {
        const id = funcNode.childForFieldName("name");
        return id ? id.text : null;
      }
      return funcNode.text;
    }
  }
};

/**
 * Class/interface/enum declaration node types per language, verified against each grammar's
 * `src/node-types.json` rather than guessed — a typo here fails silently as an empty index.
 *
 * Indexed for EVERY covered language, not just the ones whose instantiation syntax resolves to a
 * call site. The two questions are separate: "how many callers does this symbol have" is only
 * answerable where construction produces a named call (see `SingleCallerAbstractionTsAst`), but
 * "does more than one declaration share this bare name" is answerable everywhere — and it is the
 * question that keeps `impact()` from silently answering about a Java `OrderProcessor` with a
 * Python `OrderProcessor`'s call sites.
 */
const TYPE_DECL_TYPES: Record<string, Set<string>> = {
  python: new Set(["class_definition"]),
  java: new Set(["class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "annotation_type_declaration"]),
  csharp: new Set(["class_declaration", "interface_declaration", "struct_declaration", "record_declaration", "enum_declaration"]),
  kotlin: new Set(["class_declaration", "object_declaration"]),
  ruby: new Set(["class", "module"]),
  php: new Set(["class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"]),
  go: new Set(["type_spec"])
};

/** True when this build's call graph can see definitions/call sites for `lang` at all — either via
 *  a tree-sitter profile or the JS/TS Babel path. False means "no data", not "no callers": callers
 *  must return null (unknown) rather than an empty/zero result for these. */
export function isCallGraphLanguage(lang: string): boolean {
  // Babel path — bundled with the engine, always available.
  if (AST_LANGUAGES.has(lang)) return true;
  if (!(lang in CALL_GRAPH_PROFILES)) return false;
  // Having a profile is not the same as having a grammar. `buildCallGraph` skips every file whose
  // grammar failed to load (see the `treeSitterReady` guard in walkDir), so without this check a
  // host that never initialised tree-sitter — the VS Code extension path, or any caller that
  // forgot `initTreeSitter` — would report "no callers" for a language it never parsed a line of,
  // turning a total absence of data into an authoritative zero.
  return treeSitterReady(lang);
}

/** Extracts a qualified name for a function depending on its context. */
function getQualName(node: TsNode, baseName: string, language: string): string {
  let parent = node.parent;
  
  // Special case for Go method declarations which attach the receiver directly
  if (language === "go" && node.type === "method_declaration") {
    const receiver = node.childForFieldName("receiver");
    if (receiver) {
      const id = receiver.descendantsOfType("type_identifier").pop();
      if (id) {
        return `${id.text}.${baseName}`;
      }
    }
  }

  while (parent) {
    let contextName: string | null = null;
    if (language === "python" && parent.type === "class_definition") {
      contextName = parent.childForFieldName("name")?.text || null;
    } else if (["java", "csharp", "kotlin", "php"].includes(language) && parent.type === "class_declaration") {
      contextName = parent.childForFieldName("name")?.text || null;
    } else if (language === "go" && parent.type === "type_declaration") {
      const spec = parent.namedChild(0);
      if (spec && spec.type === "type_spec") {
        const nameNode = spec.childForFieldName("name");
        if (nameNode) contextName = nameNode.text;
      }
    } else if (language === "ruby" && (parent.type === "class" || parent.type === "module")) {
      contextName = parent.childForFieldName("name")?.text || null;
    }

    if (contextName) {
      return `${contextName}.${baseName}`;
    }
    parent = parent.parent;
  }
  return baseName;
}

/** Walk a tree-sitter tree to extract function definitions. */
function extractFunctions(tree: TsTree, file: string, language: string, profile: CallGraphProfile): FnDef[] {
  const fns: FnDef[] = [];
  const walk = (node: TsNode) => {
    if (profile.fnTypes.has(node.type)) {
      const nameNode = node.childForFieldName(profile.fnNameField);
      if (nameNode) {
        const name = nameNode.text;
        const qualName = getQualName(node, name, language);
        fns.push({
          name,
          qualName,
          file,
          startLine: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          language
        });
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) walk(child);
    }
  };
  if (tree.rootNode) walk(tree.rootNode);
  return fns;
}

/** Walk a tree-sitter tree to extract class/interface declarations (see `TYPE_DECL_TYPES`). */
function extractTypeDecls(tree: TsTree, file: string, language: string): FnDef[] {
  const wanted = TYPE_DECL_TYPES[language];
  if (!wanted) return [];
  const types: FnDef[] = [];
  const walk = (node: TsNode) => {
    if (wanted.has(node.type)) {
      const nameNode = node.childForFieldName("name");
      if (nameNode) {
        types.push({
          name: nameNode.text,
          qualName: nameNode.text,
          file,
          startLine: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          language
        });
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) walk(child);
    }
  };
  if (tree.rootNode) walk(tree.rootNode);
  return types;
}

/** Finds the qualified name of the closest enclosing function for a node. */
function getEnclosingFunction(node: TsNode, language: string, profile: CallGraphProfile): string {
  let parent = node.parent;
  while (parent) {
    if (profile.fnTypes.has(parent.type)) {
      const nameNode = parent.childForFieldName(profile.fnNameField);
      if (nameNode) {
        return getQualName(parent, nameNode.text, language);
      }
    }
    parent = parent.parent;
  }
  return "<top-level>";
}

/** Walk a tree-sitter tree to extract call sites with their enclosing function. */
function extractCallSites(tree: TsTree, file: string, language: string, profile: CallGraphProfile): CallSite[] {
  const sites: CallSite[] = [];
  const callTypes = new Set([profile.callType, ...(profile.extraCallTypes || [])]);
  
  const walk = (node: TsNode) => {
    if (callTypes.has(node.type)) {
      const extractor = profile.calleeExtractor || (() => null);
      const calleeName = extractor(node);
      if (calleeName) {
        const callerQualName = getEnclosingFunction(node, language, profile);
        sites.push({
          calleeName,
          callerQualName,
          file,
          line: node.startPosition.row + 1
        });
      }
    }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i);
      if (child) walk(child);
    }
  };
  if (tree.rootNode) walk(tree.rootNode);
  return sites;
}

/**
 * Build the CallGraph by parsing all source files in the given directory.
 */
export function buildCallGraph(cwd: string, opts?: {
  maxFileSize?: number;
  /** Stop after this many parsed files (graph is then `partial`). Default 3000. */
  maxFiles?: number;
  /** Stop after this much wall time (graph is then `partial`). Default 8000ms. */
  budgetMs?: number;
  entryPointDetector?: (source: { tree: TsTree } | { ast: AstNode }, file: string, lang: string) => string[];
  /** Full config (only `.ignore` is read) — respected the same way the diff/editor/MCP walks are. */
  config?: Partial<Config>;
}): CallGraph {
  const graph: CallGraph = {
    functions: new Map(),
    types: new Map(),
    callers: new Map(),
    entryPointNames: new Set(),
    partial: false
  };

  const maxFileSize = opts?.maxFileSize || 100 * 1024;
  const maxFiles = opts?.maxFiles ?? 3000;
  const budgetMs = opts?.budgetMs ?? 8000;
  const startedAt = Date.now();
  let parsed = 0;
  const ignoreConfig = (opts?.config || {}) as Config;

  function addFns(fns: FnDef[]) {
    for (const fn of fns) {
      const existing = graph.functions.get(fn.name) || [];
      existing.push(fn);
      graph.functions.set(fn.name, existing);
    }
  }

  function addTypes(types: FnDef[]) {
    for (const t of types) {
      const existing = graph.types.get(t.name) || [];
      existing.push(t);
      graph.types.set(t.name, existing);
    }
  }

  function addSites(sites: CallSite[]) {
    for (const site of sites) {
      const existing = graph.callers.get(site.calleeName) || [];
      existing.push(site);
      graph.callers.set(site.calleeName, existing);
    }
  }

  function walkDir(dir: string) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (graph.partial) return;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIR_NAMES.has(entry.name)) {
          walkDir(fullPath);
        }
      } else if (entry.isFile()) {
        try {
          if (isIgnored(fullPath, ignoreConfig, cwd) || isGitIgnoredPath(cwd, fullPath)) continue;

          const stats = fs.statSync(fullPath);
          if (stats.size > maxFileSize) continue;

          const lang = detectLanguage(fullPath);
          if (!lang) continue;
          if (!AST_LANGUAGES.has(lang) && !CALL_GRAPH_PROFILES[lang]) continue;

          // Budget guard: a huge monorepo must not turn the gate into a minute-long parse. Checked
          // only for files we're actually about to parse, so it measures work, not directory size.
          if (parsed >= maxFiles || Date.now() - startedAt > budgetMs) {
            graph.partial = true;
            return;
          }
          parsed++;

          if (AST_LANGUAGES.has(lang)) {
            // JS/TS isn't tree-sitter-parsed in this build — reuse the Babel AST instead.
            const content = fs.readFileSync(fullPath, "utf-8");
            const ast = parseJs(content, lang);
            const { fns, sites, types } = extractJs(ast, fullPath);
            addFns(fns);
            addTypes(types);
            addSites(sites);
            if (opts?.entryPointDetector) {
              for (const ep of opts.entryPointDetector({ ast }, fullPath, lang)) {
                graph.entryPointNames.add(ep);
              }
            }
            continue;
          }

          if (!treeSitterReady(lang)) continue;
          const profile = CALL_GRAPH_PROFILES[lang];

          const content = fs.readFileSync(fullPath, "utf-8");
          const tree = parseTs(content, lang);
          if (!tree) continue;

          if (opts?.entryPointDetector) {
            const eps = opts.entryPointDetector({ tree }, fullPath, lang);
            for (const ep of eps) {
              graph.entryPointNames.add(ep);
            }
          }

          addFns(extractFunctions(tree, fullPath, lang, profile));
          addTypes(extractTypeDecls(tree, fullPath, lang));
          addSites(extractCallSites(tree, fullPath, lang, profile));
        } catch {
          // Skip unreadable or unparseable files
        }
      }
    }
  }

  walkDir(cwd);
  return graph;
}

/** Resolve the enclosing function for a given file and 1-based line number. */
export function resolveEnclosingFunction(graph: CallGraph, file: string, line: number): FnDef | null {
  let bestFit: FnDef | null = null;
  for (const fns of graph.functions.values()) {
    for (const fn of fns) {
      if (fn.file === file && line >= fn.startLine && line <= fn.endLine) {
        // Return the narrowest fit in case of nested functions
        if (!bestFit || (fn.startLine >= bestFit.startLine && fn.endLine <= bestFit.endLine)) {
          bestFit = fn;
        }
      }
    }
  }
  return bestFit;
}

/** Get all callers of a function by its bare name. */
export function getCallers(graph: CallGraph, name: string): CallSite[] {
  return graph.callers.get(name) || [];
}

/** Test seam for resetting any global state if necessary in the future. */
export function _resetCallGraph(): void {
  // Test seam
}
