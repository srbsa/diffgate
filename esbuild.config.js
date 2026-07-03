import esbuild from "esbuild";
import fs from "fs";
import path from "path";

function findTs(dir) {
  const result = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) result.push(...findTs(p));
    else if (entry.name.endsWith(".ts")) result.push(p);
  }
  return result;
}

// Single source of truth for the version: package.json, injected at build time.
const VERSION = JSON.parse(fs.readFileSync("package.json", "utf-8")).version;
const define = { __DIFFGATE_VERSION__: JSON.stringify(VERSION) };

// Clean dist/
fs.rmSync("dist", { recursive: true, force: true });

// Build 1: Compile all source files individually (preserves module structure for library
// consumers and lets tests import top-level modules like dist/bench.js, dist/github.js).
// dist/cli.js produced here is overwritten by the bundled build below.
await esbuild.build({
  entryPoints: findTs("src"),
  bundle: false,
  platform: "node",
  format: "esm",
  target: "node18",
  outdir: "dist",
  outbase: "src",
  sourcemap: true,
  define,
  logLevel: "info",
});

// Build 2: Compile MCP server individually (depends on dist/core at runtime)
await esbuild.build({
  entryPoints: ["src/mcp.ts"],
  bundle: false,
  platform: "node",
  format: "esm",
  target: "node18",
  outdir: "dist",
  outbase: "src",
  sourcemap: true,
  define,
  logLevel: "info",
});

// Build 3: Bundle CLI into a single executable. `chokidar` is dynamically imported (watch-only) so
// it stays a plain runtime dep, not bundled. web-tree-sitter + native grammars load their own .wasm
// / .node assets from node_modules at runtime, so they must not be inlined either. @babel/parser is
// pure JS with no native/asset loading — it IS bundled (it's needed by every JS/TS analysis, so the
// `mcp` / npx entrypoints must not depend on node_modules being present, e.g. the mcpb bundle).
await esbuild.build({
  entryPoints: ["src/cli.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node18",
  outfile: "dist/cli.js",
  external: ["fsevents", "chokidar", "web-tree-sitter", "tree-sitter-python", "tree-sitter-php", "tree-sitter-go", "tree-sitter-ruby", "tree-sitter-java", "tree-sitter-c-sharp", "@tree-sitter-grammars/tree-sitter-kotlin"],
  banner: { js: "#!/usr/bin/env node" },
  sourcemap: true,
  define,
  logLevel: "info",
});

console.log("esbuild: all builds complete");
