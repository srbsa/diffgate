// Tree-sitter engine: AST precision for languages @babel can't parse (Python first).
//
// Why this exists: JS/TS get deep, sanitizer-aware AST rules via @babel; every other language was
// limited to comment-aware regex. Tree-sitter (via the WASM build `web-tree-sitter`) gives those
// languages a real AST too — the same precision tier: clear static-constant interpolation, recognize
// parameterized queries, target real sinks instead of any line mentioning SQL.
//
// Design constraints this module honors:
//   • The hot path (`analyze`) is SYNCHRONOUS. WASM init is not. So init runs ONCE, ahead of time
//     (`initTreeSitter`, awaited at the CLI/MCP entry points), populating a parser cache that
//     `parseTs` reads synchronously. If init hasn't run or a grammar failed to load, `parseTs`
//     returns null and the caller falls back to regex — graceful degradation, never a hard failure.
//   • No native compilation, no vendored binaries: the runtime and grammar WASM ship inside the
//     `web-tree-sitter` / `tree-sitter-python` npm packages and are resolved from node_modules at
//     runtime (both are marked external in the bundled CLI, like @babel/parser).

import { createRequire } from "module";
import path from "path";
import type { TsTree } from "../types.js";

// Resolved lazily, not at module load: the VS Code extension bundles this to CJS where
// `import.meta.url` is undefined, so a top-level `createRequire(import.meta.url)` would throw on
// import. Deferring it keeps the module safe to load anywhere; it's only invoked inside init (Node).
let _resolve: ((id: string) => string) | null = null;
function nodeResolve(): ((id: string) => string) | null {
  if (_resolve) return _resolve;
  try {
    const url = (import.meta as { url?: string } | undefined)?.url;
    if (url) { _resolve = createRequire(url).resolve; return _resolve; }
  } catch {
    /* import.meta unavailable (CJS bundle) */
  }
  return null;
}

/** Language name (from detectLanguage) → npm package shipping a matching-ABI grammar WASM. */
const GRAMMAR_PACKAGES: Record<string, string> = {
  python: "tree-sitter-python",
  php: "tree-sitter-php",
};

/** Languages this build can parse with tree-sitter, regardless of whether init has run yet. */
export function treeSitterLanguages(): string[] {
  return Object.keys(GRAMMAR_PACKAGES);
}

// `undefined` = not initialized; a Promise = in flight / done. Parsers keyed by language name.
let initPromise: Promise<void> | null = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const parserCache = new Map<string, any>();

/** Absolute path to a file at the root of an installed npm package. We resolve the package's main
 *  entry then walk up to its `node_modules/<pkg>` root — `require.resolve('<pkg>/package.json')`
 *  fails when the package's `exports` map doesn't expose package.json (web-tree-sitter does this). */
function packageFile(pkg: string, file: string): string | null {
  const resolve = nodeResolve();
  if (!resolve) return null;
  const main = resolve(pkg);
  const marker = `${path.sep}node_modules${path.sep}${pkg.split("/").join(path.sep)}`;
  const idx = main.lastIndexOf(marker);
  const root = idx !== -1 ? main.slice(0, idx + marker.length) : path.dirname(main);
  return path.join(root, file);
}

/**
 * Load the tree-sitter runtime and the configured grammars once. Idempotent — repeated calls share
 * one in-flight promise. Best-effort: any failure (missing dep, ABI mismatch) leaves the affected
 * language uncached, so it falls back to regex. Never throws.
 */
export async function initTreeSitter(langs: string[] = treeSitterLanguages()): Promise<void> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const mod: any = await import("web-tree-sitter");
      const Parser = mod.Parser ?? mod.default?.Parser ?? mod.default;
      const Language = mod.Language ?? mod.default?.Language;
      if (!Parser || !Language) return;
      const runtimeWasm = packageFile("web-tree-sitter", "web-tree-sitter.wasm");
      if (!runtimeWasm) return; // can't resolve node_modules (e.g. CJS bundle) → degrade to regex
      await Parser.init({ locateFile: () => runtimeWasm });
      for (const lang of langs) {
        const pkg = GRAMMAR_PACKAGES[lang];
        if (!pkg) continue;
        try {
          const wasm = packageFile(pkg, `${pkg}.wasm`);
          if (!wasm) continue;
          const language = await Language.load(wasm);
          const parser = new Parser();
          parser.setLanguage(language);
          parserCache.set(lang, parser);
        } catch {
          /* this grammar is unavailable — language degrades to regex */
        }
      }
    } catch {
      /* web-tree-sitter not installed / failed to init — all languages degrade to regex */
    }
  })();
  return initPromise;
}

/** Whether a tree-sitter parser for `language` is loaded and ready (init has completed). */
export function treeSitterReady(language: string): boolean {
  return parserCache.has(language);
}

/**
 * Parse `content` for `language` into a tree-sitter tree, or null when no parser is loaded (init
 * not run, or grammar unavailable). Synchronous — the async cost is paid once in `initTreeSitter`.
 */
export function parseTs(content: string, language: string): TsTree | null {
  const parser = parserCache.get(language);
  if (!parser) return null;
  try {
    return (parser.parse(content) as TsTree | null) ?? null;
  } catch {
    return null;
  }
}

// --- test seam -------------------------------------------------------------

/** Reset cached state so a test can re-exercise init. Not used in production. */
export function _resetTreeSitter(): void {
  initPromise = null;
  parserCache.clear();
}
