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
import type { TsTree, TsQuery } from "../types.js";

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

/** Language name (from detectLanguage) → npm package shipping a matching-ABI grammar WASM, plus the
 *  wasm filename when it differs from `<pkg>.wasm` (tree-sitter-c-sharp ships `tree-sitter-c_sharp.wasm`). */
const GRAMMAR_PACKAGES: Record<string, { pkg: string; wasm?: string }> = {
  python: { pkg: "tree-sitter-python" },
  php: { pkg: "tree-sitter-php" },
  go: { pkg: "tree-sitter-go" },
  ruby: { pkg: "tree-sitter-ruby" },
  java: { pkg: "tree-sitter-java" },
  csharp: { pkg: "tree-sitter-c-sharp", wasm: "tree-sitter-c_sharp.wasm" },
  kotlin: { pkg: "@tree-sitter-grammars/tree-sitter-kotlin", wasm: "tree-sitter-kotlin.wasm" },
};

/** Languages this build can parse with tree-sitter, regardless of whether init has run yet. */
export function treeSitterLanguages(): string[] {
  return Object.keys(GRAMMAR_PACKAGES);
}

// `null` = not initialized; a Promise = in flight / done. The web-tree-sitter runtime is loaded
// once; grammars are loaded per language and memoized individually, so a later call naming a
// language the first call did not ask for still loads it.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let runtimePromise: Promise<{ Parser: any; Language: any } | null> | null = null;
/** Per-language grammar load, memoized (including failures — a broken grammar isn't retried). */
const grammarPromises = new Map<string, Promise<void>>();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const parserCache = new Map<string, any>();
// The loaded grammar `Language` per language (needed to compile queries), and the web-tree-sitter
// `Query` constructor captured at init. Both populated alongside `parserCache`.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const languageCache = new Map<string, any>();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let QueryCtor: any = null;
// Compiled-query cache keyed by `lang source` — queries are reused across files. `null` caches a
// compile failure so we don't retry a broken query on every file.
const queryCache = new Map<string, TsQuery | null>();

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
  if (!runtimePromise) {
    runtimePromise = (async () => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const mod: any = await import("web-tree-sitter");
        const Parser = mod.Parser ?? mod.default?.Parser ?? mod.default;
        const Language = mod.Language ?? mod.default?.Language;
        QueryCtor = mod.Query ?? mod.default?.Query ?? null;
        if (!Parser || !Language) return null;
        const runtimeWasm = packageFile("web-tree-sitter", "web-tree-sitter.wasm");
        if (!runtimeWasm) return null; // can't resolve node_modules (e.g. CJS bundle) → regex
        await Parser.init({ locateFile: () => runtimeWasm });
        return { Parser, Language };
      } catch {
        return null; // web-tree-sitter missing / failed to init — every language degrades to regex
      }
    })();
  }
  const rt = await runtimePromise;
  if (!rt) return;

  // Load each requested grammar independently rather than gating the whole call on one shared
  // promise. The previous shape returned the first call's promise verbatim, so the FIRST language
  // list won permanently: a host that warmed up with `initTreeSitter(["python"])` and later asked
  // for Ruby got a resolved promise and no Ruby parser, silently and forever. Every downstream
  // coverage check reads `treeSitterReady`, so that turned into "this language has no callers /
  // no findings" rather than an error anyone could see.
  await Promise.all(
    langs.map((lang) => {
      let pending = grammarPromises.get(lang);
      if (!pending) {
        pending = (async () => {
          const entry = GRAMMAR_PACKAGES[lang];
          if (!entry) return;
          try {
            const wasm = packageFile(entry.pkg, entry.wasm ?? `${entry.pkg}.wasm`);
            if (!wasm) return;
            const language = await rt.Language.load(wasm);
            const parser = new rt.Parser();
            parser.setLanguage(language);
            parserCache.set(lang, parser);
            languageCache.set(lang, language);
          } catch {
            /* this grammar is unavailable — language degrades to regex */
          }
        })();
        grammarPromises.set(lang, pending);
      }
      return pending;
    })
  );
}

/** Whether a tree-sitter parser for `language` is loaded and ready (init has completed). */
export function treeSitterReady(language: string): boolean {
  return parserCache.has(language);
}

/**
 * Compile (and memoize) a tree-sitter query `source` for `language`, or null when the grammar/Query
 * runtime is unavailable or the source fails to compile. Caches failures so a broken query isn't
 * recompiled per file. The returned object exposes only `.matches(root)` (our minimal `TsQuery`).
 */
export function compileTsQuery(language: string, source: string): TsQuery | null {
  const key = `${language} ${source}`;
  const cached = queryCache.get(key);
  if (cached !== undefined) return cached;
  let q: TsQuery | null = null;
  const lang = languageCache.get(language);
  if (lang && QueryCtor) {
    try {
      q = new QueryCtor(lang, source) as TsQuery;
    } catch {
      q = null; // invalid query for this grammar — caller falls back to the full walk
    }
  }
  queryCache.set(key, q);
  return q;
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
  runtimePromise = null;
  grammarPromises.clear();
  parserCache.clear();
  languageCache.clear();
  queryCache.clear();
  QueryCtor = null;
}
