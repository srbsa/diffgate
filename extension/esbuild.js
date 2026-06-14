// Bundles the extension + the shared core engine (and @babel/parser) into a
// single CommonJS file VS Code can load. `vscode` is provided by the host.
const esbuild = require("esbuild");

const watch = process.argv.includes("--watch");

const options = {
  entryPoints: ["src/extension.ts"],
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node18",
  outfile: "dist/extension.js",
  external: ["vscode"],
  sourcemap: true,
  logLevel: "info",
};

(async () => {
  if (watch) {
    const ctx = await esbuild.context(options);
    await ctx.watch();
    console.log("esbuild: watching…");
  } else {
    await esbuild.build(options);
    console.log("esbuild: build complete");
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
