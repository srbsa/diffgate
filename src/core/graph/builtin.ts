import type {
  GraphProvider, ImpactQuery, ReachabilityQuery
} from "./index.js";
import type {
  GraphConfig, ImpactInfo, ReachabilityVerdict, ReachabilityEntryPoint, ImpactRef,
  EditContext, SecurityVerdict, Config
} from "../types.js";
import { buildCallGraph, resolveEnclosingFunction, getCallers, isCallGraphLanguage, CallGraph } from "./callgraph.js";
import { detectEntryPoints, detectJsEntryPoints, DetectedEntryPoint } from "./entry-points.js";
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

/** Walk budgets. Not config keys — a host embedding the engine (or a test) can tighten them; the
 *  defaults are the point where a gate run stops being interactive on a very large repo. */
export interface BuildBudget { maxFiles?: number; budgetMs?: number }

export class BuiltinGraphProvider implements GraphProvider {
  public readonly id = "builtin";
  private cwd: string;
  private config: GraphConfig;
  private fullConfig: Partial<Config>;
  private budget: BuildBudget;
  private graph: CallGraph | null = null;
  private detectedEntryPoints: DetectedEntryPoint[] = [];

  constructor(cwd: string, config: GraphConfig, fullConfig: Partial<Config> = {}, budget: BuildBudget = {}) {
    this.cwd = cwd;
    this.config = config;
    this.fullConfig = fullConfig;
    this.budget = budget;
  }

  private ensureGraph(): CallGraph {
    if (this.graph) return this.graph;

    // The cache is keyed by cwd alone, so a custom budget (different coverage) neither reads nor
    // writes it.
    const cacheable = this.budget.maxFiles === undefined && this.budget.budgetMs === undefined;
    const cached = cacheable ? graphCache.get(this.cwd) : undefined;
    if (cached && Date.now() - cached.builtAt < GRAPH_CACHE_TTL_MS) {
      this.graph = cached.graph;
      this.detectedEntryPoints = cached.entryPoints;
      return this.graph;
    }

    const entryPointsList: DetectedEntryPoint[] = [];

    this.graph = buildCallGraph(this.cwd, {
      config: this.fullConfig,
      maxFiles: this.budget.maxFiles,
      budgetMs: this.budget.budgetMs,
      entryPointDetector: (source, file, lang) => {
        const eps = "tree" in source
          ? detectEntryPoints(source.tree, file, lang)
          : detectJsEntryPoints(source.ast, file);
        entryPointsList.push(...eps);
        return eps.map((e) => e.qualName);
      }
    });

    this.detectedEntryPoints = entryPointsList;
    // Drop entries that have aged out rather than letting the map grow per-cwd forever (a
    // long-lived MCP server can be pointed at many repos over a session).
    for (const [key, entry] of graphCache) {
      if (Date.now() - entry.builtAt >= GRAPH_CACHE_TTL_MS) graphCache.delete(key);
    }
    if (cacheable) graphCache.set(this.cwd, { graph: this.graph, entryPoints: entryPointsList, builtAt: Date.now() });
    return this.graph;
  }

  impact(query: ImpactQuery): ImpactInfo | null {
    const lang = detectLanguage(query.file);
    if (!isCallGraphLanguage(lang)) return null; // no coverage for this language — unknown, not zero

    const graph = this.ensureGraph();
    const callers = getCallers(graph, query.symbol);
    // A truncated walk can't distinguish "no callers" from "didn't get that far".
    if (callers.length === 0 && graph.partial) return null;
    const related = this.relatedTests(query) || [];
    // Type declarations count toward ambiguity too — `single-caller-abstraction` asks about classes
    // and interfaces, and two same-named classes in different files share one bare-name bucket of
    // call sites exactly the way two same-named functions do.
    const defs = [...(graph.functions.get(query.symbol) || []), ...(graph.types.get(query.symbol) || [])];

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
      // A partial walk stopped before it ran out of repo, so every count it produces is a floor,
      // not a total. The `callers.length === 0` guard above only catches the case where the walk
      // found nothing at all; a walk that found one caller and then hit its budget was reported as
      // an exact "1" — which is precisely the value `single-caller-abstraction` treats as proof.
      // Consumers render this as "N+" and drop conclusions that depend on the count being complete.
      truncated: graph.partial,
      // Bare-name matching only: >1 definition sharing this name means the caller list above may
      // belong to any of them, not necessarily the one at query.file:query.line.
      ambiguous: defs.length > 1
    };
  }

  // No prContext: a whole-repo bySymbol dump carries nothing `impact()` doesn't (no reviewers, no
  // stale docs, no complexity here), costs a full-repo map, and is matched by bare name — so a
  // same-named symbol in an uncovered language could answer for a finding `impact()` would have
  // correctly reported as unknown. attachImpact falls back to the per-finding path, which shares
  // the same cached graph.

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
    // Outside the languages this graph parses, silence is absence of evidence — never report
    // "unreachable" for a file we never read.
    if (!isCallGraphLanguage(detectLanguage(query.file))) return null;

    const graph = this.ensureGraph();
    const maxDepth = query.maxDepth ?? this.config.reachabilityMaxDepth ?? 6;

    const untrustedKinds = new Set(query.untrustedKinds || ["http_handler", "event_handler"]);
    const validEntryPoints = this.detectedEntryPoints.filter((e) => untrustedKinds.has(e.kind));

    // Same rule for a truncated walk: the handler that reaches this sink may be in a file the
    // budget cut off, so a negative verdict is unknown, not proven.
    if (graph.partial && validEntryPoints.length === 0) return null;

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

    if (graph.partial) return null; // negative result off a truncated graph proves nothing

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

export function makeBuiltinProvider(
  cwd: string, config: GraphConfig, fullConfig?: Partial<Config>, budget?: BuildBudget
): GraphProvider {
  return new BuiltinGraphProvider(cwd, config, fullConfig, budget);
}
