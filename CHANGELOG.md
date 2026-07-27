# Changelog

All notable changes to this project will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [0.8.0] — 2026-07-26

### Added

- **`reinvented-helper` — the second half of over-engineering** ([src/core/fingerprint.ts](src/core/fingerprint.ts), [reinvention.ts](src/core/reinvention.ts)). Over-engineering is *wrong-shaped code for the job*, and it runs in two directions. The rules below cover too much structure — abstractions, wrappers, indirection. This one covers the other direction, and it is the one the field data says dominates: too much duplication. GitClear's 2026 corpus finds block duplication up 81% since 2023, refactored ("moved") code down from 21% to 3.8%, and function connectivity down 35% — new code calls less existing code and is increasingly a self-contained reinvention of something the repo already has. A diff-scoped metric cannot see that: the diff is locally fine, and only a comparison against the rest of the repo reveals it.
  - The detector fingerprints each function added in the diff — a SHA-1 over the normalized AST node-type sequence of the body, with identifiers, literals, and type annotations erased, so two functions that do the same thing with different names and constants hash identically. The attach pass indexes every function in the repo by that hash and confirms or drops.
  - A finding survives only when all of: identical non-empty shape hash, identical arity, ≥6 shape nodes **and** ≥4 distinct node types, name-token Jaccard ≥ 0.25, and the match is in a different file that is neither a test file nor part of the same diff (a function moved between two files is a move, not a reinvention). The message names the original: *"⚡ Reinvented helper: `resolveLimits` duplicates `resolveThresholds` at src/core/language-thresholds.ts:143."* (Node-count-only calibrated at ≥5, then ≥8, both wrong: the two populations overlap almost completely on length and separate cleanly on variety — three calls in a row scores 6 nodes / 3 distinct types, the canonical positive control scores 7/5.)
  - The name gate is deliberately the weak one — an identical body over 5+ statements is already strong evidence, the name only corroborates. It was calibrated up from a 0.34 floor that rejected the canonical case: two two-token names sharing one token (`resolveThresholds` → `resolveLimits`) score exactly 1/3.
  - Opt-in (`enabledByDefault: false`) pending broader calibration; `rules: { "structural": true }` or `rules: { "reinvented-helper": true }` turns it on.
  - **Note the inverted error direction.** `single-caller-abstraction` must drop anything an incomplete graph cannot confirm, because a truncated walk can report zero callers for a symbol that has many. Reinvention is the opposite: a truncated walk can only *miss* a duplicate, never invent one, since a match is positive evidence on its own. A partial walk is therefore acceptable and findings still stand.
  - Dogfooded on this repo: it found `recompute` duplicated **six times** across `impact`, `structural-impact`, `reinvention`, `reachability`, `security`, and `recall` — each copy byte-identical. Consolidated into `recomputeResult` in [tiers.ts](src/core/tiers.ts); the rule then went quiet.

- **Structural rules — a `structural` pack targeting over-engineering, not vulnerabilities** ([src/core/rules/structural.ts](src/core/rules/structural.ts), [complexity.ts](src/core/complexity.ts), [language-thresholds.ts](src/core/language-thresholds.ts)). Twelve rules over a shared AST metric engine (cognitive complexity conforming to the SonarSource spec — verified case-by-case against it, including operator-sequence scoring and flat else-if chains — nesting depth, function length, parameter count), computed on the tree the security rules already parsed, matching across both AST backends and all 8 languages. Everything is 🟡 yellow and non-blocking — a mis-tuned threshold can produce a review note, never a blocked gate. `handleAnalyze` (the `diffgate_analyze` MCP tool) runs the same graph-confirmation pass as the CLI/gate path, so `single-caller-abstraction` can't leak an unconfirmed finding through either surface.
  - *Universal metrics*: `cognitive-complexity-spike`, `deep-nesting`, `long-function`, `too-many-parameters`.
  - *Language anti-patterns*: `py-unnecessary-class`, `py-unnecessary-abc`, `go-premature-interface`, `java-single-impl-interface`, `ts-over-generic`. Each is written narrowly so the idiomatic lookalike stays quiet — `@dataclass`, `@property`, any base class, or a second implementor all suppress the Python rules.
  - *Indirection*: `pass-through-wrapper` (single-statement body forwarding its parameters unchanged, **and** the function has a named binding — a declaration, method key, or const/assignment/property target — since the advice is "inline the call site" and an anonymous callback passed straight into another call, e.g. `xs.filter(l => ready(l))`, has none), `diff-churn-ratio` (added lines vs net AST statements).
  - *Graph-backed*: `single-caller-abstraction`, scoped to **Python and JS/TS classes only** (not interfaces, not Java/C#/PHP/Ruby/Kotlin). The rule asks the call graph "how many call sites name this symbol?", which is only answerable where construction syntax produces one — `Foo()`/`new Foo()` are calls named `Foo`; Java/C#/PHP's `new Foo()` and Ruby's `Foo.new` are not, so every class in those languages scored a structural zero regardless of use. Interfaces are never called anywhere, so they're excluded across the board. The detector alone cannot tell a speculative abstraction from a load-bearing one, so it is **opt-in** (`enabledByDefault: false`) and [structural-impact.ts](src/core/structural-impact.ts) drops every finding it cannot positively confirm — no graph, no language coverage, a truncated walk, or a provider error all mean drop. Only `callerCount <= 1` on a *complete* walk survives (a truncated walk's count is a floor, not a total, so it no longer confirms even at `<=1`).
- **`languageOverrides` config section** — per-language complexity thresholds, merged built-in defaults ← language defaults ← `languageOverrides._default` ← `languageOverrides.<lang>`. Defaults follow SonarSource / Clippy / golangci-lint conventions (Python 10/3/25/4, Go 10/3/35/4, Java 15/4/50/5, …).
- **Rule packs can be enabled, not just disabled.** `rules: { "structural": true }` opts a default-off family in wholesale, instead of one override line per rule.
- **Built-in in-process code graph is now the default `graph.provider`** ([src/core/graph/builtin.ts](src/core/graph/builtin.ts), [callgraph.ts](src/core/graph/callgraph.ts), [entry-points.ts](src/core/graph/entry-points.ts)). Cross-file blast radius and reachability escalation work with zero setup — no external binary, no index step. CodeGraph stays available as an opt-in upgrade (`graph.provider: "codegraph"`) for proper symbol resolution, cross-repo consumers, and Pro taint analysis.
- **JS/TS entry-point detection** — Express/Fastify/Koa route registration (`app.get("/x", handler)`, `router.use(...)`), Next.js segment handlers (`export async function GET`), `export default function handler` in route-shaped paths, `exports.handler` serverless entry points, and `addEventListener`/`.on(...)` event handlers. Inline arrow handlers are matched by the closure's own line span, so a sink inside `app.get("/u/:id", async (req, res) => …)` is reachable with no named function to match on. Previously the JS/TS detector was a stub returning nothing — on the flagship language every reachability query answered "no entry points in this repo".

### Changed

- **The graph is built lazily.** `attachImpact` now returns early when no finding can consume impact data, instead of calling `pr_context` first. That call was the one unconditional graph build per run: a diff with no public-surface change paid a full-repo parse for nothing (~2s on this repo, worse on a monorepo). The built-in provider no longer implements `prContext` at all — a whole-repo `bySymbol` dump carried nothing the per-symbol path doesn't, and its bare-name matching could answer for a symbol in a language the graph never parsed.
- **The repo walk is bounded** (3000 parsed files / 8s wall, overridable by an embedding host) so the gate stays interactive on very large repos.

### Fixed

- **Confirmation-required rules leaked unconfirmed candidates from two paths.** `single-caller-abstraction` and `reinvented-helper` both emit optimistically and depend on an attach-pass to confirm or drop them. `reviewCommit` (the `check <commit>` / history-audit path) skipped the graph passes on the reasoning that they are "no-ops without a code graph" — true for genuine graph passes, but these are not: without their pass they print raw detector output. On one real commit in this repo that was 30 unconfirmed *"Possible reinvented helper"* lines out of 80 findings. The history path now drops anything in the new `CONFIRMATION_REQUIRED_RULES` set outright, and `handleAnalyze` (the `diffgate_analyze` MCP tool) gained the `attachReinvention` call it was missing — the agent loop is where an unconfirmed candidate does the most damage, since it sends the model rewriting code that has no duplicate.
- **`rules: { "<id>": true }` was a silent no-op for default-off rules.** `false` disabled a rule but `true` did nothing — only the `{ enabled: true }` object form or a pack opt-in worked. A config that looked like it enabled `single-caller-abstraction` or `reinvented-helper` quietly did not, and the user saw an unexplained absence of findings. The boolean form is now symmetric.
- **Rule `meta` never reached the finding.** `runAst`, `runTsAst`, and `runFile` each enumerate the emit payload field by field and all three omitted `meta`, so every rule that attaches data for a later attach-pass had it silently dropped between emit and finding. This made `reinvented-helper` completely inert end-to-end while its unit tests passed, because those tests hand-construct findings that already carry `meta`.
- **Functions on the first line of a file were dropped by the fingerprint and detector.** Tree-sitter rows are 0-based, so a truthiness guard on `startPosition.row` discards row 0. This is the same defect already fixed once in `complexity.ts`; it is now fixed in `fingerprint.ts` and `structural.ts`, and a repo-wide sweep confirms no other `row`-truthiness guards remain.
- **`reinvented-helper` never fired on new or untracked files.** The detector returned early when `ctx.changedLines` was null, but the engine's own `inChange` treats null as "whole file in scope" — so the rule was silent on exactly its best case, a file an agent just created that reimplements existing code.
- **Rule-pack disabling was silently ignored for any pack outside a hardcoded list.** `getRules` matched `rules: { "<pack>": false }` against the literal names `web-security`, `compatibility`, and `hygiene`, so a newly added pack could not be turned off. Pack handling is now driven by `RULE_PACKS` itself.
- **A per-rule `tier` override could not re-tier a structural finding.** `makeFinding` prefers the emit-site tier over the rule's, and the structural rules were passing `tier`/`blocking` on every emit — overriding the user's own config. Emit-level tier is now reserved for genuine per-finding adjustment.
- **Tree-sitter line numbers were off by one in the complexity engine**, and the `if (!startLine)` guard discarded any function starting on the file's first row.
- **No negative verdict from an incomplete graph.** `impact()` returns unknown instead of `callerCount: 0`, and `reachability()` returns unknown instead of `reachable: false`, when (a) the file's language isn't one the graph parses, or (b) the walk hit its budget and truncated. A truncated or blind walk must never look like proof that nothing calls a symbol or that no handler reaches a sink — that's the input to `reachabilityDeescalate`.
- The provider graph cache no longer grows one entry per `cwd` for the life of an MCP server; aged-out entries are dropped on rebuild.

**Bug-bash round two** (four independent deep-dives — three Opus judge passes plus one mechanical sweep — against the actual bundled tree-sitter grammars):

- **`single-caller-abstraction` scoped down to Python + JS/TS classes; interfaces dropped everywhere.** See the rule description above — Java/C#/PHP/Ruby/Kotlin classes and every language's interfaces previously confirmed on a structural zero regardless of use.
- **A truncated graph walk could still confirm `single-caller-abstraction`.** The provider's own guard only covered `callerCount === 0`; the rule's threshold is `<=1`, so a budget-truncated walk that happened to find exactly one caller reported an exact count and confirmed. `impact()` now reports `truncated: graph.partial` honestly (was hardcoded `false`), and the confirmation pass drops any truncated result outright.
- **Two same-named classes in different files/languages could answer for each other.** The call graph indexed function definitions but never class/interface declarations, so `impact()`'s ambiguity check silently missed every type-symbol collision. A new `graph.types` index (verified per-language against each grammar's real `node-types.json`, plus the Babel path) fixes this and is what let `single-caller-abstraction`'s Python/JS scope decision above be verified rather than assumed.
- **`isCallGraphLanguage` reported coverage for a grammar that never loaded.** It checked "does a profile exist for this language" rather than "did the grammar actually load" — so a host that skipped `initTreeSitter` for a language (the VS Code extension path, a CJS bundle that can't resolve `node_modules`) reported "no callers" for code it never parsed a line of. Now tracks `treeSitterReady`.
- **`initTreeSitter` permanently ignored languages not in its first call.** It cached and returned the first call's promise verbatim, so `initTreeSitter(["python"])` followed later by `initTreeSitter(["ruby"])` never loaded Ruby — silently, for the life of the process. Grammar loads are now memoized per-language rather than gated behind one shared init promise; this was the actual mechanism behind the coverage-guard bug above.
- **JS `https.get(url, callback)` — Node's HTTP client — registered as an untrusted HTTP entry point.** `http`/`https` were in the router-receiver allowlist, so an outbound request's own response callback escalated any sink inside it to blocking. Removed; the `app`-prefix match was also tightened (`appConfig.get(...)`, `appleClient`, `approvals` no longer match a bare `app` prefix).
- **Ruby: any `.get`/`.post`/`.delete` call registered as a Sinatra route, with no guard at all.** `cache.get(k)`, `hash.delete(:k)`, `client.post(body)` all matched. A route now requires no receiver, a string path argument, and a block.
- **Two route registrations on the same source line silently deduped to one.** The entry-point dedupe key was `qualName:line`; `app.get("/a", h); app.get("/b", h)` on one line collapsed to a single entry point. Key now includes column.
- **`ts-over-generic` only measured the first type argument.** `Map<string, Promise<Array<Set<number>>>>` nests three deep in its *second* argument and scored 1, never firing on the common `Map<K, V>` shape. Now descends every type argument and union/intersection member.
- **`reinvented-helper`'s same-file/same-diff exclusion gates compared un-canonicalized paths**, so a `cwd` reached through a symlink (e.g. macOS `/tmp` → `/private/tmp`) could report a function as a duplicate of itself. Paths are now `realpath`-resolved before comparison, and `attachReinvention` takes an optional `changedFiles` set so a single-file caller (the MCP path) can supply the real diff-wide set instead of a set of one.
- **Two functions opening on the same source line could each emit a `reinvented-helper` candidate at the same location.** Matching was keyed on start line only; now matched against the full span.

---

## [0.7.11] — 2026-07-05

### Changed

- **Positioning reframed around the measurement, not feature adjectives.** README hero now leads with the finding — 0% textbook OWASP bugs written from scratch, 13% of *edits* reintroduce a footgun (unguarded merge, bare `cors()`, unchecked path) — instead of "high-signal, low-noise, deterministic," which had converged into generic AI-code-review-tool wallpaper. "Why triage, not a scanner" → "Why a tripwire, not another review bot," with a shift-left framing (runs before any review bot sees the PR). Demo GIF added at the top of the README (hosted via `raw.githubusercontent.com` so it renders on npm too, not just GitHub — relative image paths aren't reliably rewritten by npm's README renderer). Synced one-liners across every published surface: `package.json`, `manifest.json` (`.mcpb`/Smithery), `server.json` (MCP registry), `action.yml` (GitHub Actions Marketplace), `extension/package.json` + `extension/README.md` (VS Code Marketplace/Open VSX), `extension.manifest.json`, `.pre-commit-hooks.yaml`, `MCP.md`, `skills/diffgate/SKILL.md`. `docs/MEASUREMENT.md` and `docs/TEAM.md` cross-link the new companion study below.
- Keywords: added `guardrails` + `ai-generated-code` to `package.json`, `guardrails` to the VS Code extension manifest.

### Added

- **New post: [docs/posts/the-pr-was-reviewed-the-risky-line-wasnt.md](docs/posts/the-pr-was-reviewed-the-risky-line-wasnt.md)** — a field study of 350 merged AI-assisted PRs across public repos: of 109 with flagged AI-attributed changes, 73 got no review, 65 no discussion at all, 41 were reviewed by a bot or the author only, and just 3 drew comment from another human. Counts are reproducible via the newly-published `research/review-state.mjs` (input contract documented in the file header); the discovery scanner and PR dataset that produced the 109-PR candidate list stay unpublished, since re-running the scan surfaces specific third-party PRs by name. Cross-linked with the existing `diffgate marginal` measurement (lab: what agents write; this post: field: what humans catch).
- `glama.json` — ownership-claim file for the Glama MCP directory listing.



### Fixed

- The `.mcpb` desktop-extension bundle (published via Smithery/Claude Desktop) crashed on startup: `dist/cli.js` statically imported `chokidar` (only used by the `watch` command) and `@babel/parser` (core JS/TS parsing) as externals, so they had to be resolved from `node_modules` at runtime — but the `.mcpb` bundle ships `dist/` only, so `mcp` threw `ERR_MODULE_NOT_FOUND` before any tool could run. `chokidar` is now a dynamic import scoped to `watch`; `@babel/parser` is pure JS with no native/asset loading and is now bundled directly into `dist/cli.js`. Verified against a real unpacked `.mcpb` and a fresh Docker build with `node_modules` deleted.
- `manifest.json` (the `.mcpb` bundle's static metadata) had an empty `tools` list and no `homepage`/`icon`/`keywords` — likely why Smithery's capability scan of the bundle showed nothing. Populated all 7 tools plus display/homepage/icon/license/keyword metadata.

### Added

- MCP tool definitions (`src/mcp.ts`) now declare `outputSchema` and `annotations` (`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`) per the MCP spec, and `tools/call` responses now include `structuredContent` alongside the text content block — improves Smithery's Capability Quality score and gives MCP clients typed output.

## [0.7.9] — 2026-07-03

### Added

- Per-rule path scoping: `customPatterns` entries and `rules` overrides accept optional `include`/`exclude` glob lists (same syntax as `ignore`, matched against the repo-relative path). `exclude` wins over `include`; an empty or missing `include` means all files; malformed (non-array) values are ignored at load. Motivated by a Backstage-monorepo evaluation where a custom `no-direct-process-env` pattern fired on the config loader itself — the one file where reading `process.env` is legitimate — and the only escapes were disabling the rule or dismissing findings one at a time. Enforced in the rule runner, so CLI diff, MCP, and the editor live path agree on where a rule runs.

### Fixed

- Docs/prose files (`.md`, `.mdx`, `.markdown`, `.txt`, `.rst`, `.adoc`) no longer run code-shaped pattern rules — a Backstage-monorepo evaluation showed `auth-crypto` flagging the word "oauth2-provider" in changelog prose (`\b` treats the hyphen as a word boundary), and every `languages: ["*"]` pattern rule (`db-schema-*`, `raw-query`, `network-call`, `sql-injection-candidate`, `deprecated-api`, …) had the same exposure. Prose is all-comment, so docs files now run only rules that already opt into raw comment scanning (`scanRaw`): `hardcoded-secret` (a key pasted in a README still leaks) and `todo-marker`. Machine-read `.txt` files (`requirements*.txt`, `constraints*.txt`, `CMakeLists.txt`) keep full coverage. Note: config-defined `customPatterns`/`orangePatterns` also stop matching docs files.
- `public-api-change` no longer flags `module.exports = …` in tooling config files (`.eslintrc.js`/`.cjs`, `*.config.js`/`cjs`/`mjs`/`ts`, rc-style `.prettierrc.js`, `karma.conf.js`, gulpfile/gruntfile) — a config file's export is configuration, not public API surface with importers to break.
- Bench harness: the PHP corpus case ran as `bench.txt` (`php` was missing from the extension map), and the new docs carve-out correctly treats `.txt` as prose — so the case silently became a miss. Restored the real `.php` extension (corpus back to 22/0/0) and tightened the bench recall assertion to exact (`= 1.0`, was `>= 0.8`) so a single missed positive now fails the suite.

## [0.7.8] — 2026-07-03

### Fixed

- `dependency-manifest` no longer fires on version-only bumps, scripts edits, or other metadata churn — it now checks which *lines* of the manifest changed and stays quiet unless a dependency-declaring line is in the diff (release commits were tripping it on every bump; a version bump changes zero packages, so the "review added/updated/removed packages" advisory was unactionable noise). Section-aware per manifest: package.json/composer.json (top-level dep keys — dependencies/devDependencies/peerDependencies/optionalDependencies/overrides/resolutions/pnpm, require/require-dev/replace/conflict/provide — via a string-aware brace scan so braces inside script strings can't corrupt tracking, Allman-style `"key":`-then-brace included), Cargo.toml/pyproject.toml (any `[…dependencies…]` section incl. target-specific and PEP 621 `dependencies = [...]` arrays, plus PEP 518 `[build-system] requires`; `requires-python` stays quiet), go.mod (require/replace/exclude/`tool` directives, inline + block), pom.xml (`<dependencies>`/`<dependencyManagement>`; the project's own `<version>` **and** `<parent>` stay quiet — multi-module reactor releases bump the parent version in every child pom), build.gradle (`dependencies {}` block + bare configuration lines like buildscript `classpath`), requirements.txt/Gemfile (comment/blank-only edits stay quiet). New/untracked manifests still fire whole-file as before; the finding now anchors to the first changed dependency line instead of the first changed line.

### Added

- `build.gradle.kts` is now recognized as a dependency manifest (the Kotlin DSL was missing from the manifest list entirely, so Gradle Kotlin projects never got the advisory).

## [0.7.7] — 2026-07-02

### Fixed

- `action.yml` rejected by the GitHub Actions Marketplace: the name `DiffGate` collided with an existing action/user/org name, and the description exceeded the 125-char cap. Renamed to `DiffGate Review Triage`; shortened the description to match the one already used for the MCP registry listing.

## [0.7.6] — 2026-07-02

### Added

- **Distribution plumbing** — no functional changes to the engine. Adds the pieces needed to be discoverable outside npm/VS Code:
  - `server.json` + `mcpName` in `package.json` for the official MCP Registry; `publish-npm.yml` now syncs the registry listing via `mcp-publisher` (GitHub-OIDC auth) on every tagged release.
  - `Dockerfile` + `publish-docker.yml` — publishes an image to GHCR on tag, satisfying Glama's listing requirements.
  - `.pre-commit-hooks.yaml` for the pre-commit.com hooks registry. Runs the published package via `npx` rather than pre-commit's `language: node` (which would try to build `dist/` — gitignored, CI-built — from source and fails).
  - `action.yml` — composite GitHub Action wrapping `diffgate check`, for the Actions Marketplace.
  - `.claude-plugin/plugin.json` + `.mcp.json` + `skills/diffgate/SKILL.md` — packages DiffGate as a Claude Code plugin with a bundled MCP server and a `/diffgate` skill.

## [0.7.5] — 2026-07-02

### Changed

- README-only republish. 0.7.4's README fix landed in commit [2611797](https://github.com/srbsa/diffgate/commit/2611797) after the 0.7.4 tag/publish had already run, so npm/marketplace pages were serving a stale README. No functional changes.

## [0.7.4] — 2026-07-02

### Added

- **`diffgate check` can now audit git history, per-commit.** New flags on `check`: `--since=<rev|date>` (e.g. `HEAD~20` or `"2 weeks ago"`), `--range=A..B`, `--author=<pat>`, `--ai-authored` (agent commits — Claude/Copilot/Cursor/…, heuristic), a positional `<sha>` for a single commit, and `--limit=<n>` (default 50). Each finding is attributed to the commit that introduced it — a story, not a repo-wide report card. Content is sourced from git objects at each commit (no `checkout`, no working-tree mutation); merge commits are skipped. `--author` matches author name/email **and** `Co-authored-by:` trailers, where most agent attribution lives. History mode is report-only (never runs the test command or blocks) and honors `--json`/`--fail-on`. New `src/core/history.ts`; git helpers `listCommits`/`getCommitChangedFiles`/`getBlobAtRef`/`isCommitish`.
- **`permissive-cors` now covers all 8 AST-precision languages** (was JS/TS + Python + PHP only). New tree-sitter rules for **Go** (`w.Header().Set("Access-Control-Allow-Origin", "*")`, gin-contrib `AllowAllOrigins: true` / `AllowOrigins: []string{"*"}` / `AllowOriginFunc: … { return true }` / `cors.Default()`, rs/cors `AllowedOrigins: {"*"}` / `cors.AllowAll()`), **Ruby** (rack-cors `origins '*'`, `set_header`/`headers[…] =` wildcard), **Java** (bare `@CrossOrigin` — its default allows ALL origins — explicit `"*"` origins, `.allowedOrigins("*")`/`.addAllowedOrigin("*")` and the `…OriginPattern` variants, `setHeader` wildcard), **C#** (`.AllowAnyOrigin()`, `.WithOrigins("*")`, `Response.Headers` wildcard writes), and **Kotlin** (Ktor `anyHost()`, Spring `@CrossOrigin`/`allowedOrigins("*")`, `setHeader`/`.headers.append` wildcard). Every rule also flags the request's own `Origin` **reflected** back — the exploitable combo alongside credentials. All findings are advisory (orange, non-blocking review), matching the existing CORS rules; explicit origin allowlists, origin-checking functions, and unrelated `*` arguments are structurally distinguished and not flagged. Permissive CORS is one of the two classes the marginal-catch experiment showed models actually emit in edit mode — this closes the 5-language coverage gap on it.
- **`hardcoded-secret` knows the AI-era key formats**: Anthropic (`sk-ant-…`), OpenAI project/service-account/admin (`sk-proj-…`/`sk-svcacct-…`/`sk-admin-…`) and legacy (`sk-…T3BlbkFJ…`), Hugging Face (`hf_…`), GitLab (`glpat-…`), and npm (`npm_…`) tokens — AI-written diffs disproportionately embed exactly these, and a bare key inline in a fetch header has no `key = "…"` shape for the generic pattern to catch. Added to both the rule patterns and `classifySecret`'s known-format list (kept in sync), so they always flag blocking with the high-confidence note; prose mentions of a prefix and short lookalikes stay unflagged.

### Fixed

- **Stale rule-file coverage headers**: `go.ts` listed SSRF as a future gap while implementing it (added 0.7.1); `ruby.ts` omitted its `ssrf` rule from the coverage list. Both now state actual coverage, and the honest-gap lists name what's really next (Go `text/template` XSS + the `template.HTML` cast; Ruby path-traversal).

- **Silent-failure sweep (gate path): a gate that doesn't run must not exit 0.** A CI gate whose failure mode is "warning + exit 0 + no scan" is a false pass — worse than a noisy one. Every such path in `check`/`scan`/MCP now fails loudly:
  - `check`/`check --since` in a **non-git directory** exit 2 with the reason on stderr (was: warning on **stdout** + exit 0 — which also broke `--json` parsers).
  - `check --base=<unresolvable ref>` exits 2 (was: `git diff` failed silently → 0 changed files → **pass**; the exact shape of a shallow CI clone that never fetched `origin/main`).
  - `check --range=<typo>` exits 2 (was: `git log` failed silently → "scanned 0" → exit 0).
  - `check <no-such-path-or-sha>` exits 2 with "No such directory or commit" (was: misreported "Not a git repository" at exit 0).
  - `--fail-on=<invalid tier>` exits 2 (was: silently gated at orange — a typo could change what blocks without anyone noticing).
  - **`check --json` / `--sarif` / `--github` now carry the gate exit code** (1 when findings reach `--fail-on`, honoring `--no-fail`; previously always exit 0 — a false pass for any CI step that checked the exit code). `scan` and history mode stay report-only by default and now apply `--fail-on` to their `--json` output too. Note: `--json` mode still skips the `testCommand` gate; the exit reflects findings only.
  - **MCP `diffgate_check_staged` errors on a non-git `cwd`** instead of returning an empty review indistinguishable from a real "clean".
  - **VS Code: a repo whose diff review throws** (e.g. malformed `.diffgate.json`) now raises one warning toast per repo instead of silently dropping out of the sidebar/status bar (which read "clear").
  - `--json` stdout purity: the `--recall`/semgrep-missing warning and `guidelines` progress lines moved to stderr; `scan` warns on stderr when 0 scannable files are found under the target.
  - `scan --sarif` now stamps the real tool version (was `0.0.0`).
  - `test/cli-flags.test.js` was never wired into `npm test` (the regression tests for the space-separated-flag bug didn't run in CI); added, plus regression tests for every path above.

- **`path-traversal` (JS/TS) is now guard-aware**, closing the known "flags guarded code" gap. It recognizes two confinement idioms and down-tiers (orange → yellow, non-blocking review) instead of misreporting them as defects, mirroring the sanitizer-wrapper awareness already in the tsast per-language `path-traversal` rules (Python/PHP/Go/Java/C#/Kotlin): (1) a `path.basename` wrapper around the request-tainted value (traced through local variable aliases), and (2) a `<var>.startsWith(baseDir)` root-prefix containment check anywhere in the file, covering the `path.resolve(base, name)` + `if (!target.startsWith(base))` idiom the rule's own message recommends. Never suppresses — a value built from a mix of sanitized and raw request data, or a guard on an unrelated variable, still blocks.
- **`dangerous-exec` (JS/TS) no longer flags `RegExp.prototype.exec()`.** Found in corpus scanning (theonaai/Heron `src/discovery/diff.ts:340`: `CONTRAST_BOUNDARY.exec(sentence)`). The rule now runs as an AST rule for JS/TS (was a shared regex) and checks the `.exec()` receiver: a regex literal, `new RegExp(...)`, a variable traced back to either, or an ALL_CAPS/`_RE`/`Pattern`/`Regex`-named identifier (weaker fallback) is skipped; everything else — `child_process`, `spawn`/`spawnSync`, `eval`, `new Function`, and custom shell-out wrappers like `ctx.conway.exec(...)` (a true positive in the same corpus) — still fires. Other languages are unaffected (regex rule unchanged there).
- **`diffgate check` flags now accept space-separated values** (`--range A..B`, `--since HEAD~20`, `--limit 50`, `--author ...`), not just `--flag=value`. The space form previously dropped the value as a stray positional and misreported "Not a git repository" at exit 0.

## [0.7.3] — 2026-06-30

### Changed

- **Positioning reframed to triage / "what to review first."** The README, `package.json`, the VS Code extension, and the GitHub listing now lead with *risk triage of AI-written diffs* (high signal · low noise · low latency) rather than "AI code review" — that category is dominated by noisy LLM reviewers, whereas DiffGate's job is the opposite: route attention, stay quiet, 0 false blocks. README headline → "Triage your AI-written diffs — see what to review first"; §"Why a gate, not a scanner" → "Why triage, not a scanner"; extension `displayName` → `DiffGate — Code Review Triage`. MCP.md + smithery.yaml aligned to the triage identity.
- **Discoverability metadata.** Root `package.json` keywords expanded (`code-review-triage`, `code-review-tool`, `claude-code`, `cursor`, `pre-commit-hook`, `secrets-detection`, `sql-injection`); extension keywords re-led with `code review triage` / `ai code review`; 16 GitHub repo topics added (were empty). "ai code review" / "code review" kept as search keywords only — identity is carried by the name/headline.

### Added

- **Cerebras + Gemini providers** — `--provider=cerebras` (base `https://api.cerebras.ai/v1`, env `CEREBRAS_API_KEY`) and `--provider=gemini` (base `https://generativelanguage.googleapis.com/v1beta/openai`, env `GEMINI_API_KEY`) registered in the provider registry. Both use the OpenAI wire. Cerebras free tier: 5 RPM; use `--delay-ms=13000`.

- **`diffgate marginal` new flags**: `--delay-ms=N` inserts an N-millisecond pause between scenario API calls (essential for providers with low RPM free tiers); `--scenarios=id1,id2,...` runs only the named subset (useful for targeted re-runs or cost-controlled frontier checks).

- **4 new `diffgate marginal` scenarios** covering the expanded Deep-AST language surface:
  - `python-sql-search` — Python LIKE search; probes f-string/`%`-concat SQLi in psycopg2.
  - `php-sql-search` — PHP string-concatenation SQLi via PDO (tests AST-precise PHP sql-injection rule).
  - `java-xxe-parse` — Java `DocumentBuilderFactory` without XXE hardening (tests the v0.7.2 XXE rule).
  - `python-ssrf-webhook` — Flask `POST /webhook/test` fetching a user-supplied URL (tests Python SSRF rule).

- **`python-sql-lookup` promoted** from `knownGap` to a scored scenario: Python SQLi is now AST-precise via tree-sitter (v0.7.0), so a catch here is real signal, not an ambiguous gap probe. The corpus is now **21 scenarios, 20 scored, 1 gap** (`nosql-auth-fields` — destructured-field NoSQL injection, still undetected).

### Improved

- **Python SSRF taint sources**: `request.get_json()` added alongside `request.json` so inline Flask JSON-body chains (`requests.get(request.get_json().get('url'))`) are now caught. **Remaining gap**: a two-hop chain through an intermediate variable (`data = request.get_json(); url = data.get('url'); requests.get(url)`) is not traced (dict-method call propagation required). Gap documented in `docs/SCOPE.md`.

### Experiment results (2026-06-29)

`diffgate marginal` run across Cerebras `gpt-oss-120b` (21 scenarios, K=2), `zai-glm-4.7` (8 key scenarios, K=2), and gpt-5.5 (java-xxe-parse only, K=3 independent runs) on the expanded corpus. Key findings:

- **Python/PHP SQLi**: 0% defect rate across all models — parameterized queries are default for capable models; engine correctness confirmed, marginal agent value near zero.
- **Java XXE (real frontier-resistant signal)**: gpt-5.5 produces unhardened `DocumentBuilderFactory` in 2/3 samples (both modes); gpt-oss-120b drops hardening in edit mode (2/2); zai-glm-4.7 fires in both modes. Suppress-on-hardening works correctly.
- **`python-pickle-load` now DEFECT, not advisory**: v0.7 Python AST rules fire `unsafe-deserialization` (blocking) rather than `dangerous-exec` (advisory). Caught 2/2 in both modes by gpt-oss-120b.
- **Python SSRF**: 0% due to two-hop dict chain gap (documented above and in `docs/SCOPE.md`).
- **gpt-oss-120b full corpus**: greenfield 15% [7–29%], edit 20% [10–35%]; edit > greenfield (consistent with all prior models).

Full cross-model table added to `docs/MEASUREMENT.md`.

---

## [0.7.2] — 2026-06-29

_First published release of the 0.7 line. **0.7.0 and 0.7.1 were never published** (committed locally only); their language-parity and SSRF work ships here, plus this release's four additions: Python import-alias resolution, PHP permissive-CORS, cross-language XXE (JVM + .NET), and Kotlin SQL sanitizer parity. **689 tests green.**_

### Added

- **XXE — a new cross-language advisory** ([`xxe`], orange / non-blocking) on the JVM and .NET. Fires on an XML parser created without disabling DOCTYPE/external-entity resolution, and is **suppressed when the file shows recognized hardening** (OWASP XXE cheat-sheet markers) so a parser secured elsewhere in the same file isn't re-flagged:
  - **Java / Kotlin** ([java.ts](src/core/rules/java.ts), [kotlin.ts](src/core/rules/kotlin.ts)): `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`TransformerFactory`/`SchemaFactory` `newInstance()`, `XMLReaderFactory.createXMLReader()`, and dom4j/JDOM `new SAXReader()`/`new SAXBuilder()`. Suppressed by `disallow-doctype-decl`, `FEATURE_SECURE_PROCESSING`, `external-general/parameter-entities`, `load-external-dtd`, `ACCESS_EXTERNAL_DTD/STYLESHEET/SCHEMA`, `SUPPORT_DTD`, `isSupportingExternalEntities`, or `setExpandEntityReferences(false)`.
  - **C#** ([csharp.ts](src/core/rules/csharp.ts)): only the explicit opt-ins to external resolution — legacy `new XmlTextReader(...)`, `DtdProcessing = DtdProcessing.Parse` without a null `XmlResolver`, or `XmlResolver = new XmlUrlResolver()`. The modern safe-by-default APIs (`XmlReader.Create`, `DtdProcessing.Prohibit`, `XmlResolver = null`) and the hardened `XmlSecureResolver` are **not** flagged (bug-bashed false-positive). `xxe` joined the `web-security` pack + SOC-2 control map.

- **PHP `permissive-cors`** ([php.ts](src/core/rules/php.ts), orange / non-blocking) — a wildcard `header("Access-Control-Allow-Origin: *")` or a request-reflected `Origin` (`$_SERVER['HTTP_ORIGIN']`), including framework setters (`$resp->headers->set(...)`, `response()->header(...)`, PSR-7 `->withHeader(...)`). Gated on an `Access-Control-Allow-Origin` argument, so a generic `$cache->set('k','*')`, an allowlisted origin, and a wildcard *subdomain* (`https://*.example.com`) are correctly not flagged. Brings PHP to **eight** AST classes and reuses the existing `permissive-cors` id (already in the pack + compliance map).

### Improved

- **Python import-alias resolution** ([python.ts](src/core/rules/python.ts)) — closes the known 0.7.0 limitation. Module-based sinks (command-injection, unsafe-deserialization, SSRF) now resolve `import subprocess as sp; sp.run(...)`, `from os import system; system(...)`, `from os import system as sh`, and `import pickle as p; p.loads(...)` back to their origin module before sink matching. A per-file alias map (cached on the tree root) only ever maps an alias to the module it was imported from, so recall improves with **no new false positives** — `from json import loads` and `from mycache import get` stay clean.
- **Kotlin SQL sanitizer parity** ([kotlin.ts](src/core/rules/kotlin.ts)) — Kotlin's `sql-injection` now down-tiers a fully-escaped query (`escapeSql`/`escape`/`quoteIdentifier`) to a review note instead of blocking, matching the Java rule on the same JVM vocabulary. (Go's SQL/command rules intentionally have no down-tier — there is no recognized escaper; the safe form is placeholders / argument vectors, already not flagged.)

### Fixed

- **Stray NUL bytes made two source files binary to git** (no line diffs — corrosive for a diff-review engine reviewing its own changes): a NUL in a [treesitter.ts](src/core/parsers/treesitter.ts) comment, and a NUL written as a raw byte (instead of the `"\u0000"` escape) in the [session.ts](src/core/session.ts) finding-fingerprint hash separator. Both are now plain text; the `session.ts` string is byte-identical at runtime, so persisted dismiss/confirm fingerprints are unchanged. A new [test/hygiene.test.js](test/hygiene.test.js) gate fails the suite if any tracked text file ever carries a NUL again.
- **`package-lock.json` version** was stuck at `0.6.1` while `package.json` is `0.7.2` (an `npm ci` mismatch); synced to `0.7.2`.

[`xxe`]: src/core/rules/

## [0.7.1] — unreleased

_Committed locally, never published to npm/marketplace — this work ships in **0.7.2**._

### Added

- **SSRF — a new cross-language advisory class** ([`ssrf`], orange / non-blocking) across **all 8 Deep-AST languages**. Fires only when a request-tainted URL/host reaches an outbound-request sink, so a static or config URL is never flagged:
  - **JS/TS** ([builtin.ts](src/core/rules/builtin.ts)): `fetch`/`axios.*`/`http(s).get`/`got`/`superagent` of `req.query`/`req.params`/`req.body` (incl. template/concat URLs).
  - **Python**: `requests`/`httpx`/`urllib3`/`aiohttp` HTTP methods + `urllib.request.urlopen`.
  - **Go**: `http.Get`/`Post`/`Head`/`PostForm` and `http.NewRequest`/`NewRequestWithContext` (URL arg position aware).
  - **Ruby**: `Net::HTTP`/`URI.open`/`HTTParty`/`RestClient`/`Faraday`/`Excon` (new Rails `params`/`cookies` request source).
  - **PHP**: `curl_init`/`curl_setopt(CURLOPT_URL, …)`/`get_headers`/`fsockopen` (`file_get_contents`/`fopen` stay under path-traversal — no double report).
  - **Java**: `new URL`/`URI`, `RestTemplate.getForObject`/`exchange`/…, Apache `HttpGet`/`HttpPost`, `HttpRequest.newBuilder`.
  - **C#**: `HttpClient.GetAsync`/`GetStringAsync`/…, `WebClient.DownloadString`/…, `WebRequest.Create`, `new Uri`/`HttpRequestMessage`.
  - **Kotlin**: JVM `URL(...)`/`URI(...)` construction and OkHttp `.url(...)`.
  - Qualified by library so a generic `.get`/`.Get` on a dict/cache/collection with request data is **not** flagged (bug-bashed). `ssrf` joined `SECURITY_RULES` + the `web-security` pack, so it's eligible for code-graph reachability escalation like the other injection advisories. +29 tests; full suite 652 green. **Honest gaps:** session/instance-based clients (`requests.Session().get`, `client.Get`), `axios({url})` config form, redirect-following analysis.

[`ssrf`]: src/core/rules/

## [0.7.0] — unreleased

_Committed locally, never published to npm/marketplace — this work ships in **0.7.2**._

_Language parity expansion: every mainstream backend language brought to maximum feasible AST depth. DiffGate now does real tree-sitter AST analysis for **11 languages** (JS/TS via Babel; Python, PHP, Go, Ruby, Java, C#, Kotlin via tree-sitter) — Python reached PHP's 7-class depth, and Go, Ruby, Java, C#, and Kotlin graduated from the regex floor to Deep (AST). Each language is sink-targeted, parameterization/sanitizer-aware, and tuned to never false-block. Shared engine ([tsast-core](src/core/rules/tsast-core.ts)) extended with declarative `sinkQuery` discovery and a `LanguageProfile` that absorbed every grammar's def-use shape (Go `expression_list`, C# positional declarators, Kotlin field-less `property_declaration`) and callee field — so a new language is a profile + name-sets, not a new engine. 623 tests green._

### Added

- **Python AST parity with PHP — three new blocking sink classes** ([src/core/rules/python.ts](src/core/rules/python.ts)), taking Python from 4 to **7 AST-precise classes**:
  - **`command-injection`** — `os.system`/`os.popen`/`subprocess.getoutput`/`getstatusoutput` (always invoke a shell → any dynamic arg blocks) and `subprocess.run`/`call`/`check_call`/`check_output`/`Popen` **only with `shell=True`** and a dynamic arg. The argument-list form (`subprocess.run(["ls", x])`) bypasses the shell and is correctly **not** flagged; every dynamic part wrapped in `shlex.quote` down-tiers to review.
  - **`code-injection`** — `eval`/`exec`/`compile` of a dynamic, non-literal value. A literal (`eval("1 + 1")`) is safe, and attribute calls like pandas `df.eval` / `ast.literal_eval` are **not** flagged (no false positives).
  - **`unsafe-deserialization`** — `pickle`/`marshal`/`dill` `.load`/`.loads` and `yaml.load` of a dynamic value. `yaml.safe_load` / `Loader=SafeLoader` down-tier to review; `FullLoader` (not fully safe) still blocks; a literal payload (test fixture) is not flagged.
  - `dangerous-exec` now defers to these on Python (`skipIfAstLangs` includes `python`) — no double report; recall is preserved via the regex when the grammar isn't loaded. The four AST injection classes (`command-`/`code-injection`, `file-inclusion`, `unsafe-deserialization`) joined `SECURITY_RULES` so they get the same trust-label + reachability treatment as `sql-injection` (also closes a latent gap for PHP).
  - **Known limitation:** module-alias resolution is not implemented — `import pickle as p; p.loads(x)` is a false negative (miss, not a false block). Direct `pickle.loads`/`os.system`/etc. are covered.

- **Go is now a Deep (AST) language** ([src/core/rules/go.ts](src/core/rules/go.ts), `tree-sitter-go`) — three AST-precise classes, exploiting Go's lack of string interpolation (a dynamic query is built only by `+` or `fmt.Sprintf`):
  - **`sql-injection`** (blocking) — `fmt.Sprintf`/concat into `database/sql` / `sqlx` / gorm sinks (`Query`/`Exec`/`Queryx`/`MustExec`/`Raw`/…). A `?`/`$1` placeholder string is static → safe; cross-line `:=`/`var`/`const` query variables are resolved. The generic `Get`/`Select` names are excluded to avoid false-blocking caches (honest FN for sqlx `Get`/`Select`).
  - **`command-injection`** (blocking) — `exec.Command`/`exec.CommandContext`. Go runs no shell, so the argument-vector form `exec.Command("git", "checkout", branch)` is correctly **safe**; blocks only a static shell program (`sh`/`bash`/`cmd`) with a dynamic argument, or a **request-tainted** program name — deliberately narrower than gosec's noisy G204 to preserve zero false blocks.
  - **`path-traversal`** (advisory) — `os.ReadFile`/`os.Open`/`http.ServeFile`/… of request data (`r.FormValue`/`r.URL.Query()`/`mux.Vars`); `filepath.Base` down-tiers.
  - Shared-core change: `declInit` (intra-file def-use) generalized to resolve Go's `expression_list`-wrapped `:=`/`=` and `var`/`const` specs, behind new optional `LanguageProfile` fields (`assignmentType` now accepts a list; `assignmentListType`). No change to Python/PHP behavior.
  - **Honest gaps:** SSRF (`http.Get(taintedURL)`), `text/template`-vs-`html/template` XSS, sqlx `Get`/`Select`.

- **Ruby is now a Deep (AST) language** ([src/core/rules/ruby.ts](src/core/rules/ruby.ts), `tree-sitter-ruby`) — five AST-precise classes built around `#{…}` interpolation (a `string`/`subshell` interpolating a non-constant is dynamic; interpolating only a `Constant` is static):
  - **`sql-injection`** (blocking) — ActiveRecord raw-SQL methods (`where`/`find_by_sql`/`exists?`/`order`/`group`/`joins`/…) and connection methods (`execute`/`exec_query`/…) as fragment sinks, so `"age > #{x}"` blocks. The `?`-placeholder array (`where("age > ?", x)`), the value-bound `where("id = ?", "#{x}")`, and the hash (`where(age: x)`) forms are correctly safe; `connection.quote`/`sanitize_sql` down-tier.
  - **`command-injection`** (blocking) — `system`/`exec`/`spawn`, backticks/`%x{}`, `IO.popen`, `Open3.*`, `Process.spawn`. Only the single-string form invokes a shell, so `system("git", "checkout", x)` is safe; `Shellwords.escape` down-tiers.
  - **`code-injection`** (blocking) — `eval`/`instance_eval`/`class_eval`/`module_eval` of a dynamic value; the block form is not flagged.
  - **`unsafe-deserialization`** (blocking) — `Marshal.load`/`YAML.load`/`Oj.load` of a dynamic value; `YAML.safe_load` is not a sink.
  - **`xss-sink`** (advisory) — `raw(…)`/`.html_safe`/`safe_concat` of a dynamic value; `sanitize`/`h`/`html_escape` down-tier.
  - `dangerous-exec` defers to Ruby. **Honest gaps:** mass-assignment, open-redirect, `render inline:` SSTI, dynamic `send`/`constantize`.

- **Java is now a Deep (AST) language** ([src/core/rules/java.ts](src/core/rules/java.ts), `tree-sitter-java`) — four AST-precise classes (Java has no string interpolation, so dynamic queries/commands are built by `+` or `String.format`):
  - **`sql-injection`** (blocking) — JDBC (`executeQuery`/`executeUpdate`/`prepareStatement`/`prepareCall`), JPA/Hibernate (`createQuery`/`createNativeQuery`/`createSQLQuery`) as fragment sinks (so keyword-less HQL `from User where …` blocks), and JdbcTemplate (`query`/`update`/…) gated on a SQL keyword to avoid false-blocking `ExecutorService.execute`. `?`-placeholder statements are safe; cross-line query variables resolved.
  - **`command-injection`** (blocking) — `Runtime.exec`/`ProcessBuilder` with a concat/`String.format`-built or request-tainted argument; a bare opaque parameter is not flagged (no gosec-style config false-block).
  - **`unsafe-deserialization`** (blocking) — `ObjectInputStream.readObject`/`readUnshared` on a receiver (the canonical native-deser gadget sink; a bare `readObject()` override call is skipped), and `XStream.fromXML` of a dynamic value.
  - **`path-traversal`** (advisory) — `new File`/`FileInputStream`/`Files.readAllBytes`/`Paths.get` of `request.getParameter`/`getHeader`; `FilenameUtils.getName` down-tiers.
  - Shared-core change: `requestSanitized` now honors a per-language `calleeField` (Java's call callee is the `name` field, not `function`) so the path down-tier works; bug bash also fixed fully-qualified `new java.io.File(...)` matching and a keyword-gate ordering FN (`execute(q)` is now resolved before the SQL-keyword check). `dangerous-exec` defers to Java.
  - **Honest gaps:** XXE, `StringBuilder`-built SQL, SpEL/OGNL injection, SSRF.

- **C# is now a Deep (AST) language** ([src/core/rules/csharp.ts](src/core/rules/csharp.ts), `tree-sitter-c-sharp`) — five AST-precise classes, interpolation-aware (`$"…{x}"`, plus concat and `string.Format`):
  - **`sql-injection`** (blocking) — `new SqlCommand(…)`, `cmd.CommandText = …`, Dapper `Query`/`Execute` (SQL-keyword gated), EF Core `FromSqlRaw`/`ExecuteSqlRaw` (fragment sinks). A `@name`-parameterized command and EF `FromSqlInterpolated` (which parameterizes the interpolation) are correctly safe; cross-line query variables and `const`-interpolation are resolved.
  - **`command-injection`** (blocking) — `Process.Start`/`ProcessStartInfo.Arguments`/`FileName` with a concat/interpolation-built or request-tainted value; a bare opaque parameter is not flagged.
  - **`unsafe-deserialization`** (blocking) — `BinaryFormatter`/`SoapFormatter`/`NetDataContractSerializer`/`LosFormatter` `.Deserialize`, resolved through the receiver's `new …()` so a safe serializer is distinguished.
  - **`path-traversal`** (advisory) — `File.*`/`new FileStream`/`StreamReader` of `Request.Query`/`Request.Form`/…; `Path.GetFileName` down-tiers.
  - **`xss-sink`** (advisory) — `@Html.Raw`/`Response.Write`/`new HtmlString` of a dynamic value; `HttpUtility.HtmlEncode` down-tiers.
  - Shared-core change: `boundValue` (def-use) now resolves C#'s `variable_declarator`, which exposes a `name` field but a positional initializer (no `value` field); the grammar registry gained a per-language wasm-filename override (`tree-sitter-c-sharp` ships `tree-sitter-c_sharp.wasm`). **Honest gaps:** Json.NET `TypeNameHandling`, XXE, SSRF, LDAP.

- **Kotlin is now a Deep (AST) language** ([src/core/rules/kotlin.ts](src/core/rules/kotlin.ts), `@tree-sitter-grammars/tree-sitter-kotlin`) — JVM parity with Java plus Kotlin string templates (`"… $x"` simple, `"… ${expr}"` braced; interpolating a non-constant is dynamic, a `const val` is static). Four AST classes:
  - **`sql-injection`** (blocking) — JDBC/JPA fragment sinks + Android `rawQuery`/`execSQL`, JdbcTemplate `query`/`execute`/`update` (SQL-keyword gated). `?`-placeholders and const templates are safe; cross-line `val` query variables resolved.
  - **`command-injection`** (blocking) — `Runtime.exec`/`ProcessBuilder` with a template/concat-built or request-tainted value; a bare opaque parameter is not flagged.
  - **`unsafe-deserialization`** (blocking) — `ObjectInputStream.readObject`/`readUnshared` on a receiver.
  - **`path-traversal`** (advisory) — `File(...)`/`FileInputStream`/`Files.readAllBytes` of `getParameter`/`@RequestParam`/Ktor `call.parameters`; `FilenameUtils.getName` down-tiers.
  - The community Kotlin grammar is field-less on calls/navigation/declarations and splits a simple `$x` template into text fragments, so the rules use positional parsing and a `declNameWrapper` def-use hook (added to the shared profile). **Honest gaps:** XSS, the `File(...).name` property sanitizer, XXE, SSRF.

---

## [0.6.1] — 2026-06-28

_Patch on 0.6.0: false-positive dismissal from the VS Code extension (editor parity with the CLI `feedback` command), plus the read-consistency fix and bug-bash hardening below._

### Added

- **Dismiss / confirm findings from the VS Code extension** ([extension/src/extension.ts](extension/src/extension.ts)) — the editor half of `diffgate feedback`. A false positive can now be suppressed without leaving the editor: **⌘. / Ctrl+. → "Dismiss as noise"**, a **"Dismiss as noise"** link on the hover card, or a **one-click button in the Deep Review inspector** after the agent returns a "likely safe" verdict. **"Confirm as a real risk"** records the opposite verdict (feeding the `diffgate stats` signal-vs-noise ratio). All write the same committed `.diffgate/learnings.json` keyed by a hash of the flagged snippet — so the dismissal is team-shared via git and applies in CI, with **no inline `// disable` comments** polluting source. An optional note can annotate why (skippable). CLI and editor dismissals reflect in each other live via a `.diffgate/learnings.json` file watcher.

  - **Bug fix it closes:** the live-editor analysis path silently ignored `.diffgate/learnings.json` — only the git-diff sidebar path (`reviewChanges`) applied it. A finding dismissed via the CLI therefore vanished from the sidebar but **reappeared in the editor gutter** the moment the file was opened or edited. `analyzeText` now applies the verdicts the same way.
  - Verdicts are cached per folder (analysis runs on every keystroke) and invalidated on a recorded verdict, an external `learnings.json` change, or a config change that could alter `learnings.shared` — so a dismissal takes effect immediately without re-reading disk on every edit.
  - An empty flagged snippet is refused (it would hash to a constant and suppress every empty-line finding of that rule), mirroring the CLI guard.

---

## [0.6.0] — 2026-06-28

_Bundles community-edition reachability, real tree-sitter AST precision for Python and PHP, and the PHP AST expansion to seven sink classes (last released: 0.5.2)._

### Added

- **PHP AST coverage expanded from 1 → 7 sink classes** ([src/core/rules/php.ts](src/core/rules/php.ts)). A deep-dive found PHP had only `sql-injection` at AST precision — every other PHP-infamous footgun (command exec, `unserialize`, `include` LFI, echo-XSS, path traversal) passed clean, because the cross-language regex rules are JS/Python-shaped. PHP now has six new `tsast` rules, each sink-targeted, dynamic-aware, sanitizer-down-tiering, and intra-file def-use resolving — same posture and precision tier as the SQLi rule:
  - **command-injection** (CWE-78, blocking) — `exec`/`shell_exec`/`passthru`/`system`/`proc_open`/`popen`/`pcntl_exec` and backtick `` `…$x` `` with a dynamic argument. `escapeshellarg`/`escapeshellcmd` on every dynamic part down-tier to review; an argument-array form (`proc_open(['ls',$f], …)`, no shell) is **not** flagged; a static command is not flagged; a `$db->exec(…)` *method* call stays SQL, not command-exec.
  - **code-injection** (CWE-95, blocking) — `eval`/`create_function` of a dynamic value, and `assert` only when its argument is string-shaped. `assert($x === 1)` / `assert(is_array($x))` are correctly **not** flagged (the prior naive shape would have).
  - **file-inclusion** (CWE-98, blocking) — `include`/`include_once`/`require`/`require_once` of a dynamic path (LFI/RFI → RCE). `basename()` down-tiers to review; a static include is not flagged.
  - **unsafe-deserialization** (CWE-502, blocking) — `unserialize()` of a dynamic value (object-injection / POP-chain RCE). `['allowed_classes' => false]` down-tiers to review.
  - **xss-sink** (CWE-79, advisory) — `echo`/`print`/`printf` of a request superglobal (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_FILES`/`$_SERVER`/`php://input`), resolved across lines. `htmlspecialchars`/`htmlentities`/`strip_tags`/`(int)` down-tier; echo of a non-request value is **not** flagged (precision over noise).
  - **path-traversal** (CWE-22, advisory) — `fopen`/`file_get_contents`/`file_put_contents`/`readfile`/`unlink`/`copy`/`rename`/`scandir`/`opendir` of request data (`file_get_contents($url)` is also SSRF). `basename`/`realpath` down-tier.

  The blocking classes block on local evidence (no graph required); xss and path-traversal are non-blocking advisories that the community-CodeGraph reachability pass can escalate. The four new ids join the `web-security` rule pack.

  Hardened in a follow-up bug bash: **SQLi** now also catches `sprintf()`-built queries and Laravel raw-fragment builders (`whereRaw`/`orderByRaw`/… — the method name signals SQL context, so a keyword-less fragment like `"age > $x"` is caught, while `whereRaw("age > ?", [$x])` is safe); **file-inclusion** no longer false-blocks the ubiquitous `include(__DIR__ . "/config.php")` / `dirname(__FILE__)` / `CONST . "/x.php"` idioms (magic constants, user constants, and `dirname()` are treated as static); **path-traversal** only inspects the *path* argument, so `file_put_contents($staticPath, $requestData)` (request data as content, not path) is no longer a false positive; **xss-sink** now catches the PHP short-echo `<?= $_GET[...] ?>` template form; and a nowdoc (`<<<'EOT'`) is correctly treated as non-interpolating.

  Honest remaining PHP gaps (documented in [docs/SCOPE.md](docs/SCOPE.md)): type-juggling (`==`), weak crypto, `header()` injection / open redirect, `extract()`/mass-assignment, dedicated `curl` SSRF, XXE.

- **Real AST precision for Python and PHP (tree-sitter)** ([src/core/parsers/treesitter.ts](src/core/parsers/treesitter.ts), [src/core/rules/python.ts](src/core/rules/python.ts), [src/core/rules/php.ts](src/core/rules/php.ts)). JS/TS got deep, sanitizer-aware AST rules via `@babel`; every other language was capped at comment-aware regex. Python and PHP now get a real AST too — via the WASM build of tree-sitter (`web-tree-sitter` + `tree-sitter-python` / `tree-sitter-php`, no native compilation, resolved from node_modules at runtime). The new `sql-injection` rule for Python reaches the **same precision tier as the JS rule**:
  - **sink-targeting** — only a dynamic SQL string that flows *into* a query sink (`.execute`, `.executemany`, `.executescript`, `.exec_driver_sql`, `.raw`, `.mogrify`, SQLAlchemy `text(...)`) is flagged, so an f-string mentioning `SELECT` in a *log line* is not;
  - **static clearing** — an f-string whose every `{…}` resolves to a module/local constant (`f"SELECT … {TABLE}"`) is not user-controlled → not flagged;
  - **parameter-aware** — a placeholder query with params passed separately (`cur.execute("… WHERE id = %s", (uid,))`) is parameterized → not flagged;
  - **sanitizer-aware** — when every dynamic part is wrapped in a recognized quoter (`psycopg2.sql.Identifier`, `quote_ident`, …) the finding is **down-tiered to review**, not blocked; a *mix* of sanitized and raw values stays blocking (one raw value can't be hidden);
  - cross-line query variables are resolved intra-file (`q = f"…{uid}"; cur.execute(q)`).

  **PHP** ([src/core/rules/php.ts](src/core/rules/php.ts)) gets the same rule with PHP-aware precision: single-quoted strings **don't interpolate** (`'… $id'` is literal, not flagged); double-quoted/`{$x}`/heredoc interpolation and `.`-concatenation into a sink (`mysqli_query`, `$pdo->query`/`->exec`/`->prepare`, `$wpdb->get_results`, …) block; a placeholder prepared statement (`->prepare("… = ?")`) is safe while an interpolated one is the flagged anti-pattern; `(int)$id` casts and escapers (`mysqli_real_escape_string`, `$pdo->quote`) down-tier to review; a mix of escaped and raw values stays blocking.

  Python also gets three more AST-precise rules at the same tier ([src/core/rules/python.ts](src/core/rules/python.ts)): **xss-sink** (`mark_safe`/`Markup`/`render_template_string` of a dynamic value — advisory; `escape()`-wrapped values down-tier; a static literal is not flagged), **path-traversal** (`open`/`send_file` of request data via `request.args`/`request.GET`/… — advisory; `secure_filename`/`safe_join`/`basename` wrappers down-tier; a mix of sanitized + raw stays orange; `send_from_directory` is not a sink), and **permissive-cors** (flask-cors `CORS(app)`/`origins='*'`, django-cors-headers `CORS_ALLOW_ALL_ORIGINS = True`, manual `Access-Control-Allow-Origin: *` — an explicit allowlist is not flagged).

  Posture matches JS exactly: **blocking orange on local evidence** (no graph required), never suppress — only down-tier on a recognized sanitizer. The community-CodeGraph reachability/blast-radius pass composes on top unchanged (AST = intra-procedural precision, graph = inter-procedural reachability). A new `tsast` rule type ([src/core/types.ts](src/core/types.ts)) carries this; init (`initTreeSitter`) runs once at the CLI/MCP entry points, the `analyze` hot path stays synchronous, and **when the grammar isn't loaded the language falls back to the cross-language regex candidate** — recall is never lost.

- **CodeGraph value, clarified** ([docs/CODE-GRAPH.md](docs/CODE-GRAPH.md)). Verified live that community CodeGraph indexes Python's call graph (entry points + callers + impact) — its value is **orthogonal** to per-language AST and concentrated in a focused ~7 of its ~40 tools (the rest are agent/IDE features). As AST precision raises local confidence per language, the graph's role shifts from *sole justification to block* → *reachability refinement + the language-agnostic blast-radius/cross-repo/reviewers/test-gap layer*, strongest on web-server code.

- **Community-edition reachability — cross-language injection that earns its block** ([src/core/reachability.ts](src/core/reachability.ts), [src/core/graph/codegraph.ts](src/core/graph/codegraph.ts)). DiffGate's injection detection is AST-deep on JS/TS and best-effort regex elsewhere, and the Pro taint engine that made the graph "precision" is absent from the community CodeGraph build — so on Python/PHP/Ruby the precision story was dark exactly where recall was weakest. New `GraphProvider.reachability()` closes this using only **community** tools (`find_entry_points` + `get_callers`/`traverse_graph`): it walks the deterministic, AST-derived call graph from a sink back toward untrusted entry points (HTTP/event handlers). A new `attachReachability` pass routes injection-class findings through it — **reachable from a handler → escalate to a blocking orange** (entry point named, `trust: "reachable"`); **no path found → advisory** (`trust: "unreachable"`, never auto-cleared unless `graph.reachabilityDeescalate: true`); **can't tell → untouched** (`null` = unknown, never a false "unreachable"). Pro taint verdicts still win when present. Core-only behavior is unchanged — a strict no-op without a graph. Entry-point discovery is memoized once per review; reachability has its own depth bound and timeout budget.

- **`sql-injection-candidate` rule + widened `dangerous-exec`** ([src/core/rules/builtin.ts](src/core/rules/builtin.ts)). A broad, **advisory** (yellow, non-blocking) cross-language injection rule for the idioms the JS-shaped blocking rule misses — Python f-string / `%` / `.format`, PHP `.`-concat & `"…$var…"`, Ruby `#{}` — and `dangerous-exec` now covers Go `exec.Command`/`CommandContext` and Ruby `system`/`%x{}`/`IO.popen`/`Open3`/`Process.spawn`/`Kernel.exec`. These never block on their own (and don't fire on parameterized queries); they escalate to blocking **only** via reachability. `skipIfAst` keeps the candidate off JS/TS, where the precise AST rule already owns this. This is the low-noise contract: recall comes from the rule, the right to block comes from the graph.

- **Config + status surface.** New `graph.reachability` / `reachabilityDeescalate` / `untrustedEntryKinds` / `reachabilityMaxDepth` / `reachabilityTimeoutMs` keys ([docs/CONFIG.md](docs/CONFIG.md)). `diffgate graph status` now shows a reachability line and the index age (reachability is only as good as the index; a stale index can make a reachable sink look unreachable). MCP `diffgate_analyze` findings may carry a `reachability` block and `trust: "reachable"/"unreachable"` ([MCP.md](MCP.md)).

- **Docs.** [docs/SCOPE.md](docs/SCOPE.md) and [docs/CODE-GRAPH.md](docs/CODE-GRAPH.md) gain a "Reachability (community edition)" section; the Pro security graph is reframed as an optional enhancement *on top of* community reachability, not a prerequisite.

### Changed

- `analyze` attaches a tree-sitter tree (`ctx.tsTree`) for grammar-backed languages; a loaded grammar suppresses the broad `skipIfAst` regex candidate for that language so the precise rule isn't doubled. New runtime deps: `web-tree-sitter`, `tree-sitter-python`, `tree-sitter-php` (marked external in the bundled CLI, like `@babel/parser`).

- **`skipIfAstLangs` — per-language regex deferral** ([src/core/types.ts](src/core/types.ts), [src/core/rules/index.ts](src/core/rules/index.ts)). `skipIfAst` skipped a broad pattern rule whenever *any* tree-sitter tree was loaded; the new `skipIfAstLangs` skips only when the tree is for a language that has a precise replacement. `dangerous-exec` now sets `skipIfAstLangs: ["php"]` so it defers to PHP's AST command/code-injection rules (no double-report) while still firing for Python `os.system`/`subprocess`, Go, and Ruby.

### Fixed — validated against a live CodeGraph (the integration was dark)

The graph normalizers had been written against hand-authored JSON shapes that do **not** match the real community CodeGraph (v0.18.6). Driving the engine's real CLI provider against a live `codegraph-server` surfaced that **both** the v0.6.0 reachability path and the older blast-radius path only ever worked against self-authored fakes:

- **Symbol names were `"[object Object]"`** ([src/core/graph/normalize.ts](src/core/graph/normalize.ts)). `find_entry_points`/`get_callers`/`traverse_graph` nest the symbol name under `symbol.name` and the entry kind under `entry_type`; the normalizer read the top level. Because both the entry-point set and the ancestor set collapsed to the same `"[object Object]"` string, they *matched each other* → any non-JS injection finding whose function had any caller falsely escalated to blocking. Now reads the nested envelope (shared `symbolNameOf` digging `symbol.name`).
- **`analyze_impact` read 0 callers** — real callers are under `impacted` with the count under `direct_impacted`/`total_impacted` (keys the normalizer never read), so a 7-caller breaking change read as 0 callers and `attachImpact` **de-escalated it through the gate** (fail-dangerous). Fixed; `normalizePrContext` reworked for the real `function_details` + flat caller-edge-list shape.
- **Bare paths instead of `file://` URIs** ([src/core/graph/codegraph.ts](src/core/graph/codegraph.ts)). CodeGraph's uri+line lookups require a `file://` URI; the provider sent a bare path → "Could not find starting node" → reachability + impact silently dead even after the shape fix. `absUri` now schemes the path.
- **Cold-index fail-safe.** A partially-built index answers `get_callers` with `{callers:[], message:"Could not find starting node"}` — the provider read that as "no callers → unreachable". `reachability()` now returns `null` (unknown) when CodeGraph can neither resolve the enclosing function nor return any caller — never a false "unreachable".
- **Availability detected the wrong layout** — `codeGraphAvailable()` only checked the legacy `~/.codegraph/graph.db`, but CodeGraph ≥ 0.18 stores per-project indexes under `~/.codegraph/projects/<slug>/`, so the graph read as unavailable on real installs. Now recognizes both.

Verified end-to-end against the real binary on a Flask fixture: a Python f-string SQLi reachable from an `@app.route` handler escalates to a blocking orange (with the sink→handler trace), while the identical sink reached only from a CLI command stays advisory.

### Tests

- New `test/reachability.test.js` (22): the `attachReachability` pass with an injected fake graph + the provider's `reachability()` with a canned `GraphRunner` (reachable/unreachable/unknown, `untrustedEntryKinds`, memoization, fail-safe degradation, Pro-wins). `test/graph-shapes.test.js` (9): the normalizers + provider against **real captured CodeGraph JSON** ([test/fixtures/codegraph-real.json](test/fixtures/codegraph-real.json)) — the regression guard the flat fakes could not be. `test/codegraph-e2e.test.js` (`npm run test:e2e`, gated by `DIFFGATE_CODEGRAPH_E2E=1`): drives the real binary on a Flask fixture. `test/scenarios.test.js` promotes the previously-pinned cross-language GAPs to the new covered-by-candidate behavior and the two-step reachability escalation. New `test/python-rules.test.js` and `test/php-rules.test.js` cover the tree-sitter rules — the latter with 53 cases across all seven PHP sink classes (TP / FP / sanitizer-down-tier / cross-line def-use / no-double-report / bug-bash regressions). Full suite **481 green**; the clean-corpus false-block rate is unchanged (0.00) — CI has no graph, so nothing new can block.

---

## [0.5.2] — 2026-06-26

### Fixed

- **`package.json` / manifest findings no longer linger** ([src/core/rules/index.ts](src/core/rules/index.ts)). `FILE`-type rules (`dependency-manifest`, `migration-file`) bypassed the diff gate and emitted on any open file even when it had no pending changes — after committing or reverting `package.json`, the yellow "Dependency manifest change" stayed in the sidebar. Root cause: `runFile` fell back to line 1 instead of suppressing when `changedLines` was an empty Set (tracked-but-unchanged file), unlike `pattern`/`ast` rules which already self-suppress via `inChange`. Fixed with an early-return matching that behavior. A `changedLines: null` (untracked/new file) still fires correctly.

- **Multi-repo workspaces now show all repos** ([extension/src/extension.ts](extension/src/extension.ts)). The extension treated each workspace folder as exactly one repo (`repoRoot(folder)`) and rendered a flat file list, so only the outermost git root was visible. It now discovers every git repo reachable from the open workspace folders — the folder's own root plus nested/sibling repos up to depth 2, matching VS Code Source Control's `git.autoRepositoryDetection` behavior. Each repo is reviewed independently, its `.git` directory is watched for commits/stashes/resets, and the DiffGate Risk sidebar groups findings by repo when more than one is present (single-repo UX is unchanged). Nested-repo files also now use the correct repo root for `.diffgate.json` config, `git diff`, and `git blame`.

- **Redundant cache-folder reads eliminated** ([src/core/config.ts](src/core/config.ts), [src/cli.ts](src/cli.ts), [src/core/agent/tools.ts](src/core/agent/tools.ts)). Three independent walkers (CLI `scan`/`watch`, the Deep-Review agent grep fallback) had three incomplete skip lists — none covered framework build/cache output dirs (`.next`, `out`, `__pycache__`, `target`, `.turbo`, `.cache`, `.svelte-kit`, etc.). Introduced `HARD_IGNORE` (always-on: `node_modules`/`.git`/`.diffgate`) and `DEFAULT_IGNORE` (extends HARD with all common output caches) in `config.ts`. `isIgnored` now always applies `HARD_IGNORE` even when a user overrides `ignore` in `.diffgate.json`, so deps/VCS/state are never re-read. The CLI watcher, CLI scan walker, and agent grep walker share the same policy. The git-diff path already honored `.gitignore` via `--exclude-standard` and was not affected.

- **Miscellaneous plugin fixes** ([extension/src/extension.ts](extension/src/extension.ts)). The `.diffgate.json` file watcher used `**/.diffgate.json` which matches inside `node_modules`, triggering spurious config-cache clears and full re-analysis on every dep install. The handler now skips paths that fail `isIgnored`. The `MAX_BYTES` guard compared VS Code's UTF-16 string length against a byte threshold — now uses `Buffer.byteLength` for correctness on non-ASCII files.

- **OpenAI GPT-5 / o-series models now work without manual config** ([src/core/llm/registry.ts](src/core/llm/registry.ts), [src/core/llm/index.ts](src/core/llm/index.ts)). The chat/completions contract for reasoning models (e.g. `gpt-5.4-nano`, `gpt-5.4-mini`, `o3`) differs from earlier models: `max_tokens` is rejected in favor of `max_completion_tokens`, and any `temperature` other than the default `1` is rejected. DiffGate sent `max_tokens` + `temperature: 0` for every OpenAI-wire call, so a `gpt-5.4-nano` config (the default `apiKeyEnv: "OPENAI_API_KEY"` setup) always 400'd. A new `isOpenAIReasoningModel()` detects these by model name — across `openai`, `openrouter` (namespaced ids like `openai/gpt-5.4-mini`), and any custom OpenAI-compatible router — and auto-applies the correct param mapping: `max_completion_tokens`, an omitted non-default `temperature`, and a larger default completion budget (reasoning tokens are billed against it, so a small cap could return empty content). Explicit `ai.tokenParam` / `ai.temperature` in `.diffgate.json` still override the auto-mapping.

## [0.5.1] — 2026-06-24

### Added

- **MCP prompts** ([src/mcp.ts](src/mcp.ts)). The server now answers `prompts/list` / `prompts/get` with three user-invocable playbooks that encode the autonomy ladder so an agent triages findings consistently instead of over-escalating or looping: `review-workflow` (the pre-surface self-check), `triage-finding` (act on one finding by its tier/trust/rung), and `setup-diffgate` (write a low-noise `.diffgate.json`). Prompt text is tailored to the repo's resolved budget and live layers.
- **MCP resources** ([src/mcp.ts](src/mcp.ts), [src/core/rules/index.ts](src/core/rules/index.ts) `ruleCatalog`). The server answers `resources/list`, `resources/read`, and `resources/templates/list` with read-only context views: `diffgate://capabilities`, `diffgate://rules` (+ the `diffgate://rules/{ruleId}` template), `diffgate://learnings`, and `diffgate://protocol` — so an agent can pre-load the rule catalog, the team's suppressions, and the autonomy protocol without a tool round-trip. `initialize` now advertises `prompts` and `resources` capabilities.
- **Smithery install** ([smithery.yaml](smithery.yaml)). One-click, zero-config install via `npx @smithery/cli install diffgate-review --client claude`.

### Fixed

- **LICENSE** restored to the canonical Apache-2.0 text. The previous file had been reworded — one clause even carried MIT-style "to use, copy, modify, merge, publish, distribute, sublicense" language — which made GitHub classify the repo as `NOASSERTION` ("Other") and was a genuine licensing defect, not just a detection quirk.
- **AI config now works for non-Anthropic providers** ([src/core/config.ts](src/core/config.ts), [src/core/index.ts](src/core/index.ts), [extension/src/extension.ts](extension/src/extension.ts), [src/cli.ts](src/cli.ts)). Two fixes so "Explain with AI" honors an OpenAI-compatible setup: (1) a zero-dep `loadDotenv()` parses a workspace `.env` into `process.env` (never clobbering real env vars), called at extension activation and CLI startup — GUI-launched VS Code doesn't inherit shell exports, so an `OPENAI_API_KEY` in `.env` was previously invisible; (2) `DEFAULT_CONFIG.ai` no longer hardcodes `provider: "anthropic"`, which `resolveProvider` prioritized over inference and used to override a user who set only `apiKeyEnv`/`model` for another provider. Provider is now inferred from `apiKeyEnv`/`model` (still falling back to anthropic).

## [0.5.0] — 2026-06-23

First public release since 0.1.2 — and the debut of the VS Code extension (Marketplace + Open VSX) and the `.mcpb` Desktop Extension. Versions 0.2.0–0.4.2 below were **unreleased internal milestones**; they ship together here. **Versioning policy from 0.5.0 on:** the CLI and the VS Code extension share one version, each release is cut from a matching `v<x.y.z>` git tag (which drives the publish workflows), and we follow [semver](https://semver.org/).

Bundles the adoption-friction pass (trivial install, non-JS/TS precision, test-scope de-escalation) with a hardened agent-counterfactual measurement and agent-trust improvements.

### Added

- **Comment-aware pattern rules** ([src/core/mask.ts](src/core/mask.ts)). Non-JS/TS languages match via regex, so commented-out code (`# os.system(x)`, `// eval(x)`, `-- DROP TABLE`) used to trip security rules. Comment regions are now blanked before matching (columns preserved) across Python, Go, Ruby, Java, C/C++, C#, Rust, SQL, shell, HTML, and more. Strings are left intact (secrets and SQL live in strings), and `hardcoded-secret` / `todo-marker` scan raw text via a new `scanRaw` rule flag (a secret in a comment is still a leak; markers live in comments).
- **Test-context de-escalation** ([src/core/testscope.ts](src/core/testscope.ts), `testScope` config, default `true`). Non-exempt orange findings in test / fixture / mock files down-tier to yellow and stop blocking the gate — test scaffolding (mock SQL, `eval` in a harness, sample payloads) is almost always intentional. Never suppressed (still shown as a review note). Exempt and still blocking: `hardcoded-secret`, `db-schema-destructive`, and the graph-owned public-surface rules (`public-api-change`, `signature-drift`, `deprecated-api`). Opt out per-rule by pinning its tier, or globally with `testScope: false`.
- **Language-aware CodeGraph nudge** ([src/cli.ts](src/cli.ts) `maybeGraphTip`). A non-JS/TS repo now gets a quiet, fade-out tip that CodeGraph adds cross-file caller/taint precision for its language — previously the tip only fired on JS/TS public-surface findings, so the users who benefit most never saw it.
- **`diffgate merge-driver`** ([src/core/learnings.ts](src/core/learnings.ts) `mergeLearningStores`). A git merge driver that auto-resolves parallel `learnings.json` verdicts (set-union by id; newer timestamp wins). `diffgate install-hook` registers it automatically (calls `diffgate` on PATH with a node fallback — no fragile `node_modules` path).
- **Release automation**: `publish-npm.yml`, `publish-ext.yml`, `publish-mcpb.yml` GitHub Actions publish the CLI (npm, with provenance), the VS Code extension (Marketplace + Open VSX), and a `.mcpb` Desktop Extension on a `v*` tag. Extension version is stamped from the tag.
- **One-click MCP**: `claude mcp add diffgate -- diffgate mcp`; `extension.manifest.json` ships a Desktop Extension manifest. `diffgate init --demo` previews findings on the bundled `mock_project` so first-run is never empty.
- **`diffgate marginal` — the agent-counterfactual measurement** ([src/marginal.ts](src/marginal.ts)). Hands a model realistic coding tasks with *no security hint* and runs the gate over its output, to measure the question behind adoption: of the risky code DiffGate catches, how much would an agent ship on its own? Hardened to a defensible number across three axes — **(coverage)** 17 scenarios spanning JS/Python/SQL (injection, secrets, prototype pollution, permissive CORS, Python deserialization/shell-out) plus `knownGap` probes (destructured-field NoSQL, Python f-string SQLi) that track coverage holes without inflating the headline; **(validity)** `--mode=edit`, which has the agent edit a seed file and analyzes only the changed lines (the real before-the-diff case), alongside the original `greenfield` whole-file mode, reported separately; **(confidence)** `--samples=K` with a Wilson 95% CI over pooled trials, plus `--temperature`. Provider-agnostic (hosted or local LM Studio/Ollama); `--out` saves generated code so every verdict is auditable. Scoring stays honest: empty/think-only replies are errors (never "clean"), blast-radius advisories are excluded, and coarse construct-presence rules (`dangerous-exec`/`auth-crypto`/`db-schema-destructive`) form a separate "advisory" bucket. **Result** (qwen3.5-9b, gpt-5.4-nano, gpt-5.4-mini, gpt-5.5; both modes, Wilson CIs): every model avoids textbook OWASP unprompted; the real marginal value is prototype pollution + permissive-CORS defaults — and it is *higher in edit mode* (gpt-5.5 introduced **0** issues writing from scratch but reintroduced both footguns when editing a file).

- **Transparent self-correction protocol** ([src/core/capabilities.ts](src/core/capabilities.ts)). The agent capability manifest (`diffgate_capabilities`) now instructs the agent that when it self-corrects on a finding it must show the human *both* the original and the corrected version (and why) rather than silently rewriting — closing the agent-in-the-middle trust gap so a human can grant more autonomy without losing sight of what changed.

### Changed

- **Positioning: self-check, not a gate; footguns, not OWASP.** README and [docs/ai-agents.md](docs/ai-agents.md) reframe DiffGate from "gates your agent" to "lets your agent self-check before you see the diff, so you can grant it more autonomy," and sharpen the security claim to match the measurement above: agents already avoid textbook vulns, so the value is catching the second-order footguns they drop while editing — surfaced both in the MCP self-check (before code hits disk) and the IDE diff review.

### Fixed

- **MCP stdio transport is now spec-compliant** ([src/mcp.ts](src/mcp.ts)). The server framed messages LSP-style (`Content-Length:` headers); the [MCP spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) mandates newline-delimited JSON. Spec-compliant clients (Cursor, mcp-inspector, the official SDKs) got no response and hung. The reader now auto-detects both framings (older Claude Code builds keep working) and the writer emits newline-delimited JSON. `initialize` also negotiates the protocol version (echoes the client's if supported, else `2025-06-18`) instead of hardcoding `2024-11-05`.
- **`permissive-cors` now catches bare `cors()`** ([src/core/rules/builtin.ts](src/core/rules/builtin.ts)). The `cors` npm package with no `origin` option defaults to `Access-Control-Allow-Origin: *`; the rule previously only matched the explicit `*` / `origin:true` forms, so the most common permissive form slipped through. Surfaced by `diffgate marginal` — both a local 9B and `gpt-5.4-mini` wrote `cors()`. Bench cases added (`cors/default-permissive`, `clean/cors-allowlist`); gate noise stays 0 false-blocks.
- **`prototype-pollution` now flags unguarded recursive deep-merge** ([src/core/rules/builtin.ts](src/core/rules/builtin.ts)). An AST check for a recursive merge that lacks a string-literal `__proto__`/`constructor` guard (a `hasOwnProperty` member-access does *not* count — it still pollutes through `target["__proto__"]`). Non-blocking review note; `Object.create(null)` targets and Maps are an accepted recall gap.
- Extension version synced to the CLI (was stuck at 0.1.5) and given the marketplace metadata it was missing (`icon`, `repository`, `homepage`, `bugs`, `keywords`, `galleryBanner`); added a generated PNG icon. Extension `package` script no longer hardcodes a `0.1.2` filename. Removed stale committed `.vsix` artifacts.
- **gpt-5.x / o-series temperature** ([src/cli.ts](src/cli.ts) `marginal`). These reasoning models reject any non-default `temperature` (only `1` is supported), which 400'd every call at temp 0 / sampling temps. `diffgate marginal` now detects the family and forces `1`; the local model carries the lower-temperature CI anchor.

---

## [0.4.2] — 2026-06-21

Hardening of the agent autonomy ladder (0.4.1): make the budget enforceable where a session actually exists, surface trust in the IDE, and close config/CLI footguns.

### Added

- **Opt-in budget enforcement** ([src/core/session.ts](src/core/session.ts)). DiffGate stays stateless and deterministic by default (a CI/pre-commit gate is a pure function of the diff). But in the two contexts that have a real agent loop, it now counts how many gate checks a finding has survived and escalates when it outlasts `escalateAfterTurns`:
  - **MCP** (one server process == one session): `diffgate_check_staged` adds an `agentBudget` block listing findings that have recurred past the budget — the external "stop re-fixing, escalate to a human" signal an agent can't self-enforce.
  - **CLI**: `diffgate check --agent --session=<id>` (or `$DIFFGATE_AGENT_SESSION`) promotes over-budget findings to the `escalate` rung, surfacing them as `review`. Without a session id, behavior is unchanged and deterministic. `agentVerdict` gains an `escalations` count and a per-finding `overBudget` flag.
  - Session ledger is idle-window scoped (30 min) and per-`sessionId`, so unrelated runs never bleed into each other.
- **Trust in the VS Code hover.** Findings now carry their deterministic trust label (`confirmed` / `cleared` / `unconfirmed`) in the editor, so the same orange finding reads "pattern/AST match" vs "no taint analysis available — verify before acting". Kept quiet for green/yellow deterministic matches to avoid noise.

### Changed

- **`gate.agent.mode` (and `failOn`, `agent.autoFixFloor`, `agent.trustSource`) are now validated at config load** — a typo like `"gated2"` throws a clear error instead of silently falling back to advisory behavior.
- **Host-mode guideline payload is structurally non-blocking.** `diffgate_guidelines` host mode now returns `blocking: false` plus a `reason`, so a harness can honor the advisory constraint without parsing prose (in addition to the existing `independent:false`/`advisory:true`).
- **`diffgate_capabilities` protocol text** now states plainly that the loop budget is *self-enforced* (DiffGate cannot reject the Nth fix per call) and that MCP/`--session` runs emit a hard-stop budget signal.

### Fixed

- **`--agent-mode` space form no longer silently ignored.** `diffgate check --agent-mode gated` (no `=`) warns to stderr instead of quietly staying advisory; an unknown value also warns. Documented in `--help`.

## [0.4.0] — 2026-06-20

### Added — native security signal (no code graph required)

The whole product thesis is "flag what needs attention, in a gradient, without noise." These land for **every** user; CodeGraph remains strictly optional and only adds cross-file reach on top.

- **Sanitizer-aware XSS down-tiering.** A dynamic `innerHTML`/`document.write`/`insertAdjacentHTML` value that is produced by a recognized sanitizer (`DOMPurify.sanitize`, `escapeHtml`, `encodeURIComponent`, `he.encode`, …) is **down-tiered from a blocking orange to a yellow review note** ("sink, but sanitized in place — verify") instead of blocking the gate. Resolves one level of local-variable aliasing (`const clean = DOMPurify.sanitize(x); el.innerHTML = clean`). We **never suppress** a security finding — a missed sanitizer keeps it blocking — so this can only reduce noise, never hide a vulnerability.
- **Secret-finding precision.** The broad `hardcoded-secret` catch-all now runs an entropy + placeholder filter: env/interpolation references (`process.env.X`, `${…}`) and obvious placeholders (`changeme`, `your-key-here`, low-entropy fixtures) are dropped, while **known provider key formats (AWS/GitHub/Stripe/Google/Slack) are always kept and labeled "high confidence."**
- **Wider taint sources.** Request-derived input detection now covers `req.cookies` / `req.signedCookies` in addition to `query`/`body`/`params`/`headers`, improving recall for the path-traversal and SQL sinks.
- **New engine hooks** (internal): pattern rules gain an optional `validate(match)` for per-match precision; AST findings can carry a `blocking` override and `tierAdjusted` natively (previously only the graph passes set tiers).

### Changed

- **The CodeGraph adoption tip now fades.** The one-line "install CodeGraph for blast radius" nudge on `check` shows at most **3 times per repo** (tracked in `.diffgate/state.json`), then goes quiet — CodeGraph is good-to-have, not mandatory, and the engine is fully useful without it.

### Added — team-adoption suite

- **PR-native review** — `diffgate check --pr[=<n>]` posts an inline PR review + a `diffgate` commit status via the GitHub API (uses `GITHUB_TOKEN` and the Actions env); orange findings fail the check so they gate merge. `--pr-dry-run` previews the payload offline. `--base=<ref>` reviews the whole PR/branch against a base branch (needed in CI, where the working tree is clean). Updated [`.github/workflows/diffgate.yml`](.github/workflows/diffgate.yml) + GitHub App scaffold ([docs/github-app.md](docs/github-app.md), [docs/app-manifest.json](docs/app-manifest.json)).
- **Noise benchmark** — `diffgate bench` scores precision/recall/F1 per rule on a versioned, offline corpus and reports the headline trust metric: **false blocks per clean change** (0 on the shipped corpus). Methodology in [BENCHMARK.md](BENCHMARK.md).
- **Org-wide policy packs** — config `extends` (path or npm package; base-first, local wins; arrays concat, objects merge, with circular/depth guards) and `learnings.shared` (merge dismiss/confirm verdicts across repos; local overrides shared).
- **Review metrics** — `diffgate report` summarizes tiers, hotspot files, top rules, and the learnings loop. `diffgate report --compliance` emits SOC 2 control evidence (rule→control mapping in [src/compliance.ts](src/compliance.ts); narrative in [COMPLIANCE.md](COMPLIANCE.md)).
- **Agent gate** — `diffgate check --agent` emits a compact pass/blocked JSON verdict for coding-agent harnesses (exit 1 when blocked). Positioning in [docs/ai-agents.md](docs/ai-agents.md).
- **Smarter onboarding** — `diffgate init` now auto-detects the test command (npm/pytest/go/cargo/make), languages, and guideline files, and writes a tailored config (`--minimal` for the old static template).

---

## [0.3.0] — 2026-06-20

### Added

- **Deeper code-graph use** — DiffGate now drives more of CodeGraph than a single `analyze_impact` call:
  - **`pr_context` is the primary source.** One whole-diff call returns callers, test gaps, suggested reviewers, **stale-doc warnings**, and **cyclomatic complexity** per changed symbol. Findings are enriched from that single payload; symbols it doesn't cover — or any time it's unavailable — fall back to the per-finding `analyze_impact` lookup, so behavior degrades cleanly. Complexity (when high) and stale-doc flags now show in the CLI report, SARIF `properties`, and the VS Code hover.
  - **`find_related_tests` for authoritative test gaps.** In the fallback path, a changed public symbol with zero covering tests is marked untested directly from the graph instead of inferred.
  - **`get_edit_context` in the MCP loop.** `diffgate_analyze` attaches callers/tests/recent-history for the highest-blast finding, so a coding agent can fix the call sites **before the generated code is written to disk**.
- **`diffgate graph` command** — `graph status` shows whether the graph is enabled, the binary is on PATH, and an index exists; `graph index` bootstraps the index (or prints install help when CodeGraph isn't installed). `check` also shows a one-line, non-nagging tip when a public-surface change would benefit from a graph that isn't indexed yet.
- **Graph-aware security (optional, Pro)** — for injection-class findings (`sql-injection`, `xss-sink`, `nosql-injection`, `path-traversal`, `dangerous-exec`, `prototype-pollution`), a CodeGraph Pro taint analysis answers "does user input actually reach this sink?". A **confirmed taint path** is attached to the finding (source → … → sink) and keeps the gate; a **proven-clean** sink can de-escalate **only when `graph.securityDeescalate` is explicitly enabled** (enrich-only by default — a false "no taint" must never silently hide a vulnerability). Fully optional and a no-op when no security graph is present.
- **New `graph` config keys** — `prContext`, `relatedTests`, `editContext` (all default `true`), `security` (`"auto"`), and `securityDeescalate` (`false`).

### Notes

- The CodeGraph driver tries each tool by its bare name and retries with the `codegraph_` namespace, tolerating version/profile differences in tool naming.
- The security pass is validated against CodeGraph's documented tool contract and injected fakes, **not a live Pro binary** — treat the security integration as untested-against-a-real-server until exercised in your environment.

---

## [0.2.0] — 2026-06-20

### Added

- **Cross-file blast radius (code graph)** — public-surface findings (`public-api-change`, `signature-drift`, `deprecated-api`) are enriched with deterministic impact from an optional code graph ([codegraph-ai/CodeGraph](https://github.com/codegraph-ai/CodeGraph)): caller count, suggested reviewers, and test gaps. The pass uses that impact to **route human attention rather than emit more comments**:
  - a changed public surface with **callers stays orange**, names the reviewers, and flags untested call sites (`tierAdjusted: "escalated"`);
  - a changed public surface the graph says **nobody calls de-escalates to yellow** and stops blocking the gate (`tierAdjusted: "deescalated"`) — cutting the largest false-positive class for compatibility rules.
  - Pin a rule's tier in config (e.g. `"signature-drift": { "tier": "orange" }`) to opt out of de-escalation.
- **Optional, graceful dependency** — configured via the new `graph` block. `enabled: "auto"` (default) uses the graph when an index exists and is otherwise a complete no-op (zero subprocess cost, no errors). Talks to CodeGraph via one-shot `codegraph-server --run-tool analyze_impact` queries; a host can also inject its own provider.
- **Impact on every surface** — CLI report blast-radius line, GitHub PR annotations, SARIF `properties` (caller count, reviewers, test gaps, `tierAdjusted`), the MCP `diffgate_analyze` output (so a coding agent sees blast radius before code hits disk), and the VS Code hover card (on saved files).
- **`diffgate stats`** — a signal-vs-noise report. *Realized* signal from reviewer verdicts in `.diffgate/learnings.json` (confirm vs dismiss), including a list of chronically-noisy rules to consider disabling; *predicted* signal from the current diff's tier mix.

### Fixed

- **SARIF** now emits a per-result `level` (orange → error, yellow → warning, green → note) and the real package version (was hard-coded `0.1.2`).

---

## [0.1.5] — 2026-06-16

### Added

- **Feedback → learnings** — `diffgate feedback <ruleId> <file> <line>` (and the `diffgate_feedback` MCP tool) records a verdict on a finding. `dismiss` suppresses that exact flagged code (ruleId + code hash) in all future reviews (noise reduction); `confirm` marks it a real catch. Stored in `.diffgate/learnings.json` (commit it to share across the team). Applied automatically by `check`, `scan`, and the MCP `analyze`.
- **GitHub PR annotations** — `diffgate check --github` emits Actions workflow-command annotations that render inline on the PR "Files changed" tab (orange → error, yellow → warning, green → notice). Ships with a ready-to-use `.github/workflows/diffgate.yml`.

### Fixed

- **Version drift** — the CLI and MCP server version strings are now injected from `package.json` at build time (single source of truth) instead of being hand-maintained.

---

## [0.1.4] — 2026-06-16

### Added

- **Coding-guideline review** — DiffGate now reviews the diff against your repo's own guideline files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`) — the same files your coding agents already read. New `diffgate guidelines` CLI command and `diffgate_guidelines` MCP tool. Configurable via the `guidelines` block.
- **Per-directory scoping** — a guideline file applies to its own directory and all subdirectories; the nearest file wins. Deep nesting is capped (`maxDepth`, default 3): the nearest files plus the repo-root file are kept and the middle is dropped, with a logged note (no silent truncation).
- **Agent-credit (host) evaluation** — `guidelines.evaluator: "auto"` delegates the natural-language judgment to the calling agent's own model when no provider is configured (zero API-key setup), and uses the configured provider otherwise. Guideline findings are advisory (`yellow`, non-blocking) by default since they are non-deterministic.

---

## [0.1.3] — 2026-06-16

### Changed

- **Explain with AI is now thinking-free** — the single-shot explain path suppresses model "thinking" so reasoning models (e.g. Qwen on LM Studio) answer directly instead of burning the budget deliberating. Deep Review still reasons + sweeps.

### Fixed

- **Model-agnostic thinking suppression** — non-standard params (`chat_template_kwargs`, `/no_think`) are only sent to local templated runtimes (LM Studio/Ollama) by default, so hosted APIs (OpenAI, Groq, etc.) no longer 400. Opt in on a custom gateway via `ai.noThink: true`. Residual empty `<think>` blocks are stripped from output.

---

## [0.1.2] — 2026-06-15

### Added

- **Inspector webview** — risk-aware VS Code webview panel for explaining and performing agentic Deep Review. Includes live agent stepper showing tool calls and final verdict.
- **SARIF export** — `--sarif` flag on CLI emits valid SARIF 2.1.0 output for CI/CD integration.
- **Rule packs toggling** — config options to enable/disable whole groups of rules (e.g. `web-security`).
- **Structured verdict** — Deep Review agent now returns structured `verdictClass` (`confirmed-risk`, `likely-safe`, or `needs-human`) parsed from the model output.

### Changed

- **AST rewrites** — `sql-injection`, `xss-sink`, and `path-traversal` rules rewritten with Babel AST matching to identify true security risks while eliminating false positives on parameterized/safe patterns.
- **Smart annotations** — inline diagnostics, gutter icons, and CodeLenses are now displayed on high-impact lines, with CodeLens gated to orange-tier findings.
- **VS Code Engine** — bumped requirement to `^1.90.0` for webview and chat support.

---

## [0.1.1] — 2026-06-14

### Changed

- **Full TypeScript migration** — all source files (`src/**`, `extension/src/extension`) converted from `.js` to `.ts` with `strict: true`. Types are enforced at build time via `tsc --noEmit`.
- **esbuild bundler** — CLI ships as a single bundled file (`dist/cli.js`) with shebang. Core library and MCP server are compiled individually to `dist/` for tree-shaking by consumers.
- **6 new security rules** — `sql-injection` (blocking orange), `permissive-cors`, `xss-sink`, `path-traversal`, `nosql-injection`, `prototype-pollution`. Rule count: 21 → 27.
- **Inline verdict badge** — after Deep Review runs, the hover card shows `$(error) Confirmed risk`, `$(pass) Likely safe`, or `$(question) Needs human review` directly in the tooltip. No need to open the output channel.
- **MCP `diffgate_analyze` agent-review workflow** — documented with diagram in README. Enables coding agents (Claude Code, Cursor, etc.) to check generated code before writing it to disk.
- Package entry points updated: `bin.diffgate → dist/cli.js`, `main / exports → dist/core/index.js`.

---

## [0.1.0] — 2024-06-14

Initial public release.

### Engine (`src/core`)

- **Diff-aware analysis** — reports findings only on lines changed vs the git baseline; falls back to whole-file when outside a git repo.
- **Real AST for JS/TS** — `@babel/parser` powers precise rules that are not fooled by comments or strings.
- **21 built-in rules** across three tiers (green / yellow / orange):
  - Secrets: `hardcoded-secret`
  - SQL / NoSQL injection: `sql-injection`, `nosql-injection`, `raw-query`, `db-schema-change`, `db-schema-destructive`
  - Web security: `permissive-cors`, `xss-sink`, `path-traversal`, `prototype-pollution`
  - Execution: `dangerous-exec`
  - Auth / crypto: `auth-crypto`
  - Public surface: `public-api-change`, `signature-drift`, `deprecated-api` (with auto-fix)
  - Network / deps: `network-call`, `dependency-manifest`, `migration-file`
  - Dev hygiene: `leftover-debugger`, `debug-logging`, `todo-marker`
- **Signature-drift detection** — warns when an exported function's parameter list changes.
- **Real gate** — runs the project's `testCommand` when an orange finding is gated.
- **Provider-agnostic LLM** — optional AI layer with 8 providers (Anthropic, OpenAI, OpenRouter, Groq, Together, LM Studio, Ollama, custom). Per-tier model routing.
- **Deep Review** — ReAct agent loop that uses grep, read_file, find_references, and git_blame to investigate blast radius of orange findings, returning a `confirmed-risk / likely-safe / needs-human` verdict.

### CLI (`diffgate`)

- `check` — diff gate, exits 1 on orange/blocking findings.
- `check --staged` — staged-only diff.
- `check --json` — machine-readable output.
- `scan <path>` — analyze a directory without git.
- `watch [path]` — live re-analysis on file change.
- `explain <path> <line>` — AI explanation for a specific finding.
- `init` — write a starter `.diffgate.json`.
- `install-hook` — add a git pre-commit gate.
- `mcp` — start the MCP stdio server.

### VS Code extension

- Inline diagnostics on changed lines (or whole-file mode).
- Hover cards: tier, message, git-blame attribution, AI explain link, Deep Review link.
- Deep Review verdict badge in hover (confirmed-risk / likely-safe / needs-human) after the agent runs.
- Quick-fixes for `deprecated-api` findings.
- Risk Review tree (activity bar): all pending changes by file and tier.
- Status-bar risk summary.
- Verification gate command.
- Settings: `diffgate.scanMode`, `diffgate.diffMode`, `diffgate.ai.*`.

### MCP server

- `diffgate_analyze` — deterministic analysis of a file; accepts unsaved `content` parameter (zero LLM tokens).
- `diffgate_check_staged` — scan all working-tree / staged changes.
- `diffgate_deep_review` — agentic blast-radius analysis for an orange finding.
- `diffgate_explain` — single-shot AI explanation.
- JSON-RPC 2.0 over stdin/stdout with Content-Length framing (LSP-style). No SDK dependency.
- Compatible with Claude Code (`~/.claude/mcp.json`), Cursor, and any MCP-capable agent.

### Tests

- 47 unit and integration tests (`node:test`).
- Extension smoke test (module-stub harness, no VS Code process needed).
