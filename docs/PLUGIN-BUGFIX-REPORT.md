# DiffGate VS Code plugin + MCP — bug deep-dive & fix plan

_Date: 2026-06-26 · Scope: `extension/`, `src/core/`, `src/mcp.ts`, `src/cli.ts`_

This documents the four reported plugin issues plus additional defects found while
tracing them, with root cause (`file:line`), severity, and the implemented fix.

The engine's job: a **diff-aware, three-tier (green/yellow/orange) code-review gate**.
Findings are reported **only on changed lines** of the **current git diff**. Every bug
below is a place where that contract leaks — findings that aren't tied to the diff,
repos that aren't enumerated, or files that aren't part of any diff being read anyway.

---

## Bug 1 — `package.json` / manifest findings linger after the change is gone

**Severity: High** (most-reported; breaks the core "diff-aware" promise)

**Symptom.** A yellow _"Dependency manifest change"_ (and the orange _"Database migration
file"_) finding stays in the sidebar / diagnostics / status bar even when `package.json`
has no pending changes — e.g. after committing or reverting, or just by having the file
open.

**Root cause.** `FILE`-type rules bypass the diff gate. In
[`src/core/rules/index.ts`](../src/core/rules/index.ts):

- `pattern` and `ast` rules call `inChange(ctx, line)` →
  `!ctx.changedLines || ctx.changedLines.has(line)`. When `changedLines` is an **empty
  Set** (a tracked file with zero diff), every line fails `.has()`, so they emit nothing.
- `runFile()` never consults `inChange`. It emits via
  `firstChangedLine(ctx)`, which **falls back to line 1 when `changedLines` is empty**.
  So `dependency-manifest` and `migration-file` fire on *any* analysis pass — including
  an open-but-unchanged `package.json`.

The extension's per-document path
([`extension/src/extension.ts:147` `analyzeText`](../extension/src/extension.ts)) computes
`changedLines = computeChangedLines(prev, content)` → empty Set when unchanged → the FILE
rule still fires. The same leak exists in MCP `diffgate_analyze`
([`src/mcp.ts:481`](../src/mcp.ts)) and `reviewChanges`.

**Fix.** `runFile()` returns early when `ctx.changedLines` is a non-null empty Set,
matching `pattern`/`ast` behavior. A genuinely new (untracked) file still has
`changedLines === null` → whole-file scan → FILE rule fires, which is correct.

---

## Bug 2 — Multi-repo workspaces only show one repo

**Severity: High**

**Symptom.** A workspace containing several git repositories shows findings for only one.
Expected: behave like VS Code's Source Control view (one section per repo).

**Root cause (two layers).**

1. **Discovery.** [`refreshWorkspace` `extension/src/extension.ts:503`](../extension/src/extension.ts)
   treats each workspace folder as exactly one repo: `reviewChanges(cwd)` →
   `repoRoot(cwd)`. It never scans for **nested or sibling repos** under a folder. So:
   - A folder that *contains* repos but isn't itself one → `isGitRepo(folder)` false → 0 repos.
   - A folder that *is* a repo and contains nested repos → only the outer repo's `git diff`
     is shown (nested repos are gitlinks/untracked) → "only 1 repo".
   - `watchGitDir` ([`:1471`](../extension/src/extension.ts)) only watches `<folder>/.git`,
     so nested repos' commits/stashes never refresh the view.
2. **Presentation.** The risk tree ([`RiskTreeProvider:416`](../extension/src/extension.ts))
   is a **flat file list** with no repo node, so even correct discovery wouldn't read like SCM.

A secondary correctness bug: `findingsByUri.set(uriStr, { folder: cwd, ... })` stores the
**workspace-folder** path as the config/AI/blame base even for files that live in a nested
repo → wrong `.diffgate.json`, wrong `git blame` root.

**Recommendation (chosen): match VS Code Source Control.** The user's own framing
("similar to source control / forks") is the right target. Implemented as a **bounded**
version of VS Code's `git.autoRepositoryDetection`:

- Discover repos per workspace folder = the folder's own repo root (if any) **plus** a
  bounded scan (depth ≤ 2, skipping `node_modules`/cache dirs) for nested `.git` dirs.
- Dedupe by real repo root; `reviewChanges(root)` each; key findings by their **owning
  repo** so the per-file `folder` base is correct.
- Watch each discovered repo's `.git`.
- Group the risk tree by repo root (collapsible repo node → files → findings), shown only
  when more than one repo is present (single-repo UX is unchanged).

Unbounded full-tree recursion was rejected (perf on large monorepos); depth-2 covers the
real cases (folder-of-services, repo-with-submodules) the way SCM does by default.

---

## Bug 3 — Reads a cache folder (redundant)

**Severity: Medium** (perf / noise; not a correctness gate failure)

**Root cause.** There is **no single ignore policy** — three walkers with three different,
incomplete skip lists, none of which covers framework build/cache output dirs:

| Site | Skip/ignore set | Misses |
|---|---|---|
| [`config.ts:13` `DEFAULT_CONFIG.ignore`](../src/core/config.ts) | `node_modules .git dist build coverage vendor *.min.js` | `.next .nuxt .svelte-kit .turbo .cache out .output .parcel-cache __pycache__ .pytest_cache .mypy_cache .venv target .gradle tmp` |
| [`cli.ts:407` `chokidar.watch`](../src/cli.ts) | dotdirs + `node_modules .git dist` | `build coverage vendor out __pycache__ target` |
| [`agent/tools.ts:51` Deep-Review grep](../src/core/agent/tools.ts) | `node_modules .git dist build coverage` | all caches above |

The git-**diff** path is safe (`git ... --exclude-standard` honors `.gitignore`). The leaks
are the **non-diff** walkers (`diffgate scan`, `diffgate watch`, Deep-Review's fallback
grep) and the extension's **per-document** path
([`extension.ts:188`](../extension/src/extension.ts)), which consult only `config.ignore`,
never `.gitignore`. Opening or restoring a file under `out/`, `build/`, `__pycache__/`,
etc. gets it analyzed, decorated, and listed.

**Fix.**
- Add `HARD_IGNORE` (VCS/deps/`.diffgate` state) + `DEFAULT_IGNORE` (HARD + build/cache
  output dirs) + `IGNORE_DIR_NAMES` (bare dir names) in `config.ts`. `DEFAULT_CONFIG.ignore`
  now = `DEFAULT_IGNORE`; `isIgnored` **always** applies `HARD_IGNORE` so even a user who
  overrides `ignore` never re-reads deps/`.git`/`.diffgate`.
- Point the CLI watcher (`chokidar.ignored`), CLI scan (`walkFiles` via `isIgnored`), and
  the agent grep walker (`IGNORE_DIR_NAMES`) at the same policy.
- The git-diff path already honors `.gitignore` (`--exclude-standard`); the extension's
  per-document path inherits the expanded default for auto-restored/decorated files.
  Files a user *explicitly* opens are still analyzed (matching VS Code's own behavior).
  `HARD_IGNORE` is conservative (only never-source dirs) so real source in `out/`/`target/`
  isn't hidden when a project overrides `ignore`.

---

## Bug 4 — Other issues surfaced

- **`.diffgate.json` watcher matches `node_modules`.**
  [`extension.ts:1456`](../extension/src/extension.ts) `createFileSystemWatcher("**/.diffgate.json")`
  fires for vendored configs under `node_modules`, triggering a full config-cache clear +
  re-analysis. _Fix: ignore `node_modules`/cache paths in the handler._ **(Low)**
- **`MAX_BYTES` compares UTF-16 length, not bytes.**
  [`extension.ts:184`](../extension/src/extension.ts) `document.getText().length > MAX_BYTES`
  over- or under-counts for non-ASCII. _Fix: use `Buffer.byteLength`._ **(Low)**
- **`jsGrep` re-reads the tree on every Deep-Review grep call** with no `.gitignore`
  awareness (only triggers when `git grep` is unavailable). Folded into the Bug-3 fix. **(Low)**
- **`folderForUri` analyzes files outside any workspace folder** by falling back to
  `path.dirname` ([`extension.ts:69`](../extension/src/extension.ts)) — a file opened via
  "Open Recent" from an unrelated repo gets analyzed against that repo's git. Now bounded by
  the repo-discovery change (findings are keyed to a known repo). **(Low)**

---

## MCP workflow — verified

`src/mcp.ts` is single-repo-per-call by design (the agent passes `cwd`, defaulting to
`process.cwd()`); tools and `diffgate://*` resources resolve against that one repo, which is
correct for an agent that drives one repo at a time. The only defect was the shared **Bug 1**
FILE-rule leak in `diffgate_analyze` ([`:481`](../src/mcp.ts)) — fixed centrally in
`runFile`. No multi-repo work is required for MCP.

---

## Fix summary

| Bug | File(s) | Change |
|---|---|---|
| 1 | `src/core/rules/index.ts` | `runFile` honors empty-diff gate |
| 3 | `src/core/config.ts`, `src/cli.ts`, `src/core/agent/tools.ts`, `extension/src/extension.ts` | shared `BASELINE_IGNORE`; `.gitignore` awareness |
| 2 | `extension/src/extension.ts` | repo discovery, per-repo review/watch, tree grouping by repo |
| 4 | `extension/src/extension.ts` | watcher node_modules filter, byte-length cap |
