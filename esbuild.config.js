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

// Clean dist/
fs.rmSync("dist", { recursive: true, force: true });

// Build 1: Compile core library files individually (preserves module structure for library consumers)
await esbuild.build({
  entryPoints: findTs("src/core"),
  bundle: false,
  platform: "node",
  format: "esm",
  target: "node18",
  outdir: "dist",
  outbase: "src",
  sourcemap: true,
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
  logLevel: "info",
});

// Build 3: Bundle CLI into a single executable (all deps included, no node_modules needed)
await esbuild.build({
  entryPoints: ["src/cli.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node18",
  outfile: "dist/cli.js",
  external: ["fsevents"],
  banner: { js: "#!/usr/bin/env node" },
  sourcemap: true,
  logLevel: "info",
});

console.log("esbuild: all builds complete");
