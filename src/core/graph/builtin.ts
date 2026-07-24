import type {
  GraphProvider, ImpactQuery, PrContextQuery, ReachabilityQuery
} from "./index.js";
import type {
  GraphConfig, ImpactInfo, PrContextInfo, ReachabilityVerdict, ReachabilityEntryPoint, ImpactRef,
  EditContext, SecurityVerdict, Config
} from "../types.js";
import { buildCallGraph, resolveEnclosingFunction, getCallers, isCallGraphLanguage, CallGraph } from "./callgraph.js";
import { detectEntryPoints, DetectedEntryPoint } from "./entry-points.js";
import { detectLanguage } from "../parsers/index.js";

/**
 * Built-in GraphProvider backed by an in-process Tree-Sitter call graph.
 */
// The full-repo walk + parse is the expensive part (seconds on a large repo) and is identical
// across queries for the same cwd regardless of per-query config (escalateThreshold, etc.) — cache
// it briefly so a long-lived host (the MCP server) doesn't redo it on every tool call. A fresh
// `BuiltinGraphProvider` is still constructed per call (cheap), so config is always current; only
// the built graph itself is shared.
const GRAPH_CACHE_TTL_MS = 30_000;
const graphCache = new Map<string, { graph: CallGraph; entryPoints: DetectedEntryPoint[]; builtAt: number }>();

export class BuiltinGraphProvider implements GraphProvider {
  public readonly id = "builtin";
  private cwd: string;
  private config: GraphConfig;
  private fullConfig: Partial<Config>;
  private graph: CallGraph | null = null;
  private detectedEntryPoints: DetectedEntryPoint[] = [];

  constructor(cwd: string, config: GraphConfig, fullConfig: Partial<Config> = {}) {
    this.cwd = cwd;
    this.config = config;
    this.fullConfig = fullConfig;
  }

  private ensureGraph(): CallGraph {
    if (this.graph) return this.graph;

    const cached = graphCache.get(this.cwd);
    if (cached && Date.now() - cached.builtAt < GRAPH_CACHE_TTL_MS) {
      this.graph = cached.graph;
      this.detectedEntryPoints = cached.entryPoints;
      return this.graph;
    }

    const entryPointsList: DetectedEntryPoint[] = [];

    this.graph = buildCallGraph(this.cwd, {
      config: this.fullConfig,
      entryPointDetector: (tree, file, lang) => {
        const eps = detectEntryPoints(tree, file, lang);
        entryPointsList.push(...eps);
        return eps.map((e) => e.qualName);
      }
    });

    this.detectedEntryPoints = entryPointsList;
    graphCache.set(this.cwd, { graph: this.graph, entryPoints: entryPointsList, builtAt: Date.now() });
    return this.graph;
  }

  impact(query: ImpactQuery): ImpactInfo | null {
    const lang = detectLanguage(query.file);
    if (!isCallGraphLanguage(lang)) return null; // no coverage for this language — unknown, not zero

    const graph = this.ensureGraph();
    const callers = getCallers(graph, query.symbol);
    const related = this.relatedTests(query) || [];
    const defs = graph.functions.get(query.symbol) || [];

    const callerRefs: ImpactRef[] = callers.map((c) => ({
      file: c.file,
      line: c.line,
      symbol: c.callerQualName
    }));

    return {
      source: "codegraph",
      symbol: query.symbol,
      callerCount: callers.length,
      callers: callerRefs,
      reachable: null,
      reviewers: [],
      testGaps: related.length === 0 ? [{ symbol: query.symbol }] : [],
      truncated: false,
      // Bare-name matching only: >1 definition sharing this name means the caller list above may
      // belong to any of them, not necessarily the one at query.file:query.line.
      ambiguous: defs.length > 1
    };
  }

  prContext(query: PrContextQuery): PrContextInfo | null {
    const graph = this.ensureGraph();
    const bySymbol: Record<string, ImpactInfo> = {};

    for (const [name, fnDefs] of graph.functions.entries()) {
      const callers = getCallers(graph, name);
      if (callers.length > 0) {
        bySymbol[name] = {
          source: "codegraph",
          symbol: name,
          callerCount: callers.length,
          callers: callers.map((c) => ({
            file: c.file,
            line: c.line,
            symbol: c.callerQualName
          })),
          reachable: null,
          reviewers: [],
          testGaps: [],
          truncated: false,
          ambiguous: fnDefs.length > 1
        };
      }
    }

    return {
      source: "codegraph",
      bySymbol,
      staleDocs: []
    };
  }

  relatedTests(query: ImpactQuery): ImpactRef[] | null {
    const graph = this.ensureGraph();
    const callers = getCallers(graph, query.symbol);
    const testCallers = callers.filter((c) =>
      /\b(test|tests|spec)\b/i.test(c.file) || /_test\.|\.test\.|\.spec\./i.test(c.file)
    );

    return testCallers.map((c) => ({
      file: c.file,
      line: c.line,
      symbol: c.callerQualName
    }));
  }

  editContext(query: ImpactQuery): EditContext | null {
    const impact = this.impact(query);
    if (!impact) return null;

    return {
      source: "codegraph",
      callers: impact.callers,
      tests: this.relatedTests(query) || [],
      history: []
    };
  }

  security(query: ImpactQuery): SecurityVerdict | null {
    return null; // Pro taint analysis is not provided by the built-in tree-sitter provider
  }

  reachability(query: ReachabilityQuery): ReachabilityVerdict | null {
    const graph = this.ensureGraph();
    const maxDepth = query.maxDepth ?? this.config.reachabilityMaxDepth ?? 6;

    const untrustedKinds = new Set(query.untrustedKinds || ["http_handler", "event_handler"]);
    const validEntryPoints = this.detectedEntryPoints.filter((e) => untrustedKinds.has(e.kind));

    if (validEntryPoints.length === 0) {
      return {
        source: "codegraph",
        reachable: false,
        entryPoints: [],
        depth: 0
      };
    }

    const entryPointNames = new Set(validEntryPoints.map((e) => e.qualName));
    const entryPointMap = new Map<string, DetectedEntryPoint>();
    for (const ep of validEntryPoints) {
      entryPointMap.set(ep.qualName, ep);
    }
    // DSL-style handlers (Sinatra/Ktor/Laravel/minimal-API routes, Go inline handlers) have no
    // separate named function — their synthetic qualName (e.g. "sinatra_get") never appears as a
    // real caller name, so name-matching alone can't find them. `bodyRange` is the handler's own
    // line span; a sink (or a call site on the path to one) inside it is reachable regardless of
    // whether any enclosing function has a matching name.
    const rangedEntryPoints = validEntryPoints.filter((e) => e.bodyRange);
    const withinRange = (file: string, line: number, ep: DetectedEntryPoint): boolean =>
      !!ep.bodyRange && ep.file === file && line >= ep.bodyRange.startLine && line <= ep.bodyRange.endLine;

    const directHit = rangedEntryPoints.find((ep) => withinRange(query.file, query.line, ep));
    if (directHit) {
      const epRef: ReachabilityEntryPoint = {
        name: directHit.qualName, kind: directHit.kind, route: directHit.route, file: directHit.file
      };
      return {
        source: "codegraph",
        reachable: true,
        entryPoints: [epRef],
        depth: 0,
        path: [{ symbol: directHit.qualName, file: query.file, line: query.line }]
      };
    }

    // 1. Resolve enclosing function of the target line
    const enclosing = resolveEnclosingFunction(graph, query.file, query.line);
    if (!enclosing) {
      // Not directly inside a detected handler body, and no wrapping function either -> unknown.
      return null;
    }

    // 2. BFS backwards through caller chain
    const visited = new Set<string>();
    let currentQueue: string[] = [enclosing.qualName, enclosing.name];
    let depth = 0;
    const pathRefs: ImpactRef[] = [{ symbol: enclosing.qualName, file: query.file, line: query.line }];

    let foundEntryPoint: DetectedEntryPoint | null = null;

    while (currentQueue.length > 0 && depth <= maxDepth) {
      const nextQueue: string[] = [];

      for (const fnName of currentQueue) {
        if (visited.has(fnName)) continue;
        visited.add(fnName);

        if (entryPointNames.has(fnName)) {
          foundEntryPoint = entryPointMap.get(fnName)!;
          break;
        }

        // Find call sites calling `fnName`
        const callers = getCallers(graph, fnName);
        for (const c of callers) {
          // A call site sitting inside a DSL handler body reaches that handler even though the
          // call's enclosing scope has no name matching the (synthetic) entry-point qualName.
          const rangeHit = rangedEntryPoints.find((ep) => withinRange(c.file, c.line, ep));
          if (rangeHit) {
            foundEntryPoint = rangeHit;
            pathRefs.push({ symbol: rangeHit.qualName, file: c.file, line: c.line });
            break;
          }

          if (!visited.has(c.callerQualName)) {
            nextQueue.push(c.callerQualName);
            pathRefs.push({ symbol: c.callerQualName, file: c.file, line: c.line });
            // Also push bare name if qualified
            const bare = c.callerQualName.split(/[.#]|::/).pop();
            if (bare && bare !== c.callerQualName && !visited.has(bare)) {
              nextQueue.push(bare);
            }
          }
        }
        if (foundEntryPoint) break;
      }

      if (foundEntryPoint) break;
      currentQueue = nextQueue;
      depth++;
    }

    if (foundEntryPoint) {
      const epRef: ReachabilityEntryPoint = {
        name: foundEntryPoint.qualName,
        kind: foundEntryPoint.kind,
        route: foundEntryPoint.route,
        file: foundEntryPoint.file
      };
      return {
        source: "codegraph",
        reachable: true,
        entryPoints: [epRef],
        depth,
        path: pathRefs
      };
    }

    return {
      source: "codegraph",
      reachable: false,
      entryPoints: [],
      depth
    };
  }

  reindex(): boolean {
    this.graph = null;
    graphCache.delete(this.cwd);
    this.ensureGraph();
    return true;
  }
}

export function makeBuiltinProvider(cwd: string, config: GraphConfig, fullConfig?: Partial<Config>): GraphProvider {
  return new BuiltinGraphProvider(cwd, config, fullConfig);
}
