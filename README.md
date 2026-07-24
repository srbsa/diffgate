# DiffGate

[![npm version](https://img.shields.io/npm/v/diffgate-review?logo=npm)](https://www.npmjs.com/package/diffgate-review)
[![npm downloads](https://img.shields.io/npm/dm/diffgate-review)](https://www.npmjs.com/package/diffgate-review)
[![VS Code Marketplace](https://vsmarketplacebadges.dev/version/srbsa.diffgate-review.svg)](https://marketplace.visualstudio.com/items?itemName=srbsa.diffgate-review)
[![Open VSX](https://img.shields.io/open-vsx/v/srbsa/diffgate-review?logo=eclipseide&label=Open%20VSX)](https://open-vsx.org/extension/srbsa/diffgate-review)
[![License](https://img.shields.io/github/license/srbsa/diffgate)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/srbsa/diffgate?style=social)](https://github.com/srbsa/diffgate)

**Coding agents don't write textbook vulnerabilities anymore — they delete your guardrails while editing.**

We measured it across local and frontier models: **0%** classic OWASP bugs (SQL injection, XSS, hardcoded secrets) in code written from scratch. But the same frontier model that wrote flawless greenfield code reintroduced security footguns in **13% of edits** — an unguarded recursive merge (prototype pollution), a bare `cors()` (any origin), a path built from request data with no containment check. And editing existing code is most of what an agent does. [The measurement →](docs/MEASUREMENT.md)

DiffGate is the deterministic tripwire for exactly that residue — a review pass that runs **before any review bot sees a PR**, at the keystroke and the commit, where fixing is cheapest. It grades **only the lines that changed** (🟢 merge · 🟡 glance · 🟠 verify) in milliseconds, runs your tests only when a change earns it, and blocks only when it's earned: **0 false blocks** on a public, versioned corpus ([BENCHMARK.md](BENCHMARK.md)). Not a model grading its own homework — the same verdict inside your coding agent (MCP), your editor, your pre-commit hook, and your CI.

![DiffGate demo: diffgate check on a real repo, mostly green with one orange finding and its reason](https://raw.githubusercontent.com/srbsa/diffgate/main/assets/diffgate.gif)

| Tier | Meaning | What you do | Examples |
|------|---------|-------------|----------|
| 🟢 **Green** | Safe / self-contained | merge freely | comments, local logging |
| 🟡 **Yellow** | Review (soft dependency) | take a look | deprecated APIs, raw SQL, network calls, dependency edits |
| 🟠 **Orange** | High-impact, gate it | verify before merge | schema/migrations, hardcoded secrets, auth/crypto, public-API changes, injection sinks |

---

## Why a tripwire, not another review bot

Review bots comment after the PR exists; linters and scanners flag everything they see. Neither guarantees the risky line gets discussed: [we scanned 350 merged AI-assisted PRs](docs/posts/the-pr-was-reviewed-the-risky-line-wasnt.md) — of the 109 with flagged AI-attributed changes, only 3 drew public discussion from any human besides the author. DiffGate sits earlier — with the agent and the human writing the code — and **decides what deserves your attention, your tests, or a block**, staying quiet otherwise. That's the whole product:

- **Diff-scoped.** Findings report only on the lines that changed, against the committed baseline — no whole-file noise, no re-litigating code you didn't touch.
- **Tiered triage, not a flat list.** Three tiers route attention: green merges, yellow is a glance, orange is gated.
- **The gate runs *your* tests — selectively.** On an orange change, DiffGate runs your `testCommand` and shows the real exit code and output. Green and yellow pass instantly. The pre-commit hook is fast because tests fire only when a change is genuinely high-impact.
- **Earns the right to block.** Broad cross-language injection findings stay advisory on their own; they escalate to a blocking finding **only when the optional code graph proves the sink is reachable from an untrusted entry point** (an HTTP/event handler). Recall from the rules, the right to block from the graph.
- **Change-impact aware.** With an optional code graph, a finding carries its cross-file blast radius — caller counts, suggested reviewers, untested call sites — and an exported symbol nobody calls is *de-escalated*. Cross-file context makes reviews **quieter**, not louder.
- **Fast.** A review runs in milliseconds on the changed lines — quick enough to sit in the agent and editor inner loop, not only in CI.
- **Provably low-noise.** `diffgate bench` runs a versioned corpus offline: **100% precision / 0 false blocks** on clean changes. Reproduce it yourself — that's the point of shipping the corpus. See [BENCHMARK.md](BENCHMARK.md).

### The measurement is reproducible

The 0% / 13% numbers aren't a marketing line — they come from a scripted experiment (four models from local to frontier, greenfield vs. edit mode, Wilson confidence intervals) that you can rerun with `diffgate marginal`. Methodology, per-model tables, and caveats: [docs/MEASUREMENT.md](docs/MEASUREMENT.md). DiffGate's security rules are tuned to that measured residue, not to maximizing rule count.

---

## Quick start

```bash
npm install -g diffgate-review
cd your-repo
diffgate init                    # auto-detects language + test command, writes .diffgate.json
diffgate check --since=HEAD~20   # see what it catches in your own history — no PR required
diffgate check                   # review your pending changes right now
```

No git history or uncommitted changes yet? See the output on bundled examples first:

```bash
diffgate init --demo   # live scan, no config or git changes needed
```

---

## The surfaces (one shared engine, one verdict)

### 1. In your coding agent (via MCP)

The highest-leverage spot: the agent **self-checks generated code before it's written to disk**, gets back structured findings (zero LLM tokens), and surfaces what it corrected (original + fix + why) instead of silently rewriting. A trustworthy, deterministic self-check is what makes it safe to grant the agent more autonomy.

```bash
# Claude Code — one command:
claude mcp add diffgate -- diffgate mcp

# One-click via Smithery (zero config):
npx @smithery/cli install diffgate-review --client claude

# Cursor — add to MCP settings:
# { "diffgate": { "command": "diffgate", "args": ["mcp"] } }
```

Or one-click in Claude Desktop: download [`diffgate.mcpb`](https://github.com/srbsa/diffgate/releases/latest) and open it. The server also exposes **prompts** and **resources**; see [MCP.md](MCP.md).

### 2. In your editor (VS Code / Cursor)

Inline squiggles on changed lines, hover cards (why · who owns it · quick-fix), a Risk Review tree, a status-bar summary, and **Deep Review** (agentic blast-radius analysis for orange findings). The same verdict you'd get from the CLI, on the diff you're reviewing.

Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=srbsa.diffgate-review) or [Open VSX](https://open-vsx.org/extension/srbsa/diffgate-review) (Cursor / Windsurf / Gitpod).

### 3. On the command line — and in CI

`diffgate check` reviews your diff and exits non-zero on high-impact findings: a pre-commit hook locally, the same gate in your pipeline.

```bash
diffgate install-hook  # adds .git/hooks/pre-commit; only runs tests on 🟠 orange changes
```

The local loop is the wedge — fix while the context is fresh — and the **same engine runs as a PR gate** so the verdict carries to where it's enforced for the whole team. See [docs/TEAM.md](docs/TEAM.md) for the GitHub Action, shared learnings, and org policy packs. CI runs can optionally layer an external scanner (Semgrep) through the same gate for broader language coverage — advisory-only, off by default ([docs/CONFIG.md](docs/CONFIG.md)).

**Common commands:**

```bash
diffgate check                 # review pending changes (the gate)
diffgate check --staged        # staged-only (pre-commit)
diffgate check --since=HEAD~20 # audit recent history, per-commit (see below)
diffgate check --agent         # machine verdict for coding agents
diffgate scan <path>           # analyze files directly (no git needed)
diffgate watch                 # live review as you edit
diffgate guidelines            # review diff against AGENTS.md / CLAUDE.md etc.
diffgate feedback <rule> <f> <l> --dismiss   # suppress a false positive (shared via git)
diffgate mcp                   # start the MCP stdio server
```

**Audit recent AI-authored history.** Point `check` at commits already in your log — each
finding is attributed to a specific commit, so you get a story, not a repo-wide report card:

```bash
diffgate check --since=HEAD~20        # last 20 commits, one block per commit
diffgate check --since="2 weeks ago"  # by date instead of a rev
diffgate check --ai-authored          # only agent commits (Claude/Copilot/Cursor/… — heuristic)
diffgate check --author="Claude"      # matches author *and* Co-authored-by trailers
diffgate check <sha>                  # a single commit by hash
```

History mode is report-only (it audits the past — it never runs your test command or blocks a
commit) and honors `--json` and `--limit=<n>` (default 50). Merge commits are skipped.

Run `diffgate --help` for the full list (`report`, `bench`, `stats`, `graph`, `marginal`, …).

---

## How it works

- **Diff-aware:** `git diff` (CLI) or an in-memory LCS diff (editor, accurate on unsaved buffers) finds changed lines; findings only report on those lines.
- **Real AST where it counts:** `@babel/parser` (JS/TS) and tree-sitter (Python, PHP, Go, Ruby, Java, C#, Kotlin — via WASM, no native build) power precise rules: deprecated calls aren't matched inside comments or strings, exported-signature changes are detected structurally, and SQL injection is **sink-targeted, parameter-aware, and sanitizer-aware** — `cur.execute(f"… {uid}")` / `$pdo->query("… $id")` block, while `cur.execute("… %s", (uid,))`, `$pdo->prepare("… ?")`, a single-quoted `'… $id'`, and a `SELECT` in a log line don't.
- **A deterministic floor everywhere else:** comment-aware pattern rules for secrets, destructive/schema changes, auth/crypto, dynamic execution / shell-out, raw queries, and network calls across Go, Java, Ruby, and any text. Commented-out code (`# os.system(x)`) isn't flagged; a secret committed *inside* a comment still is. Docs/prose files (`.md`, `.rst`, …) are held to the same standard: the word "oauth2-provider" in a changelog isn't auth code, but a key pasted in a README is still a leak.
- **Earned blocking:** broad cross-language injection advisories for the non-AST languages (Ruby `#{}`, Go/Ruby shell-out) escalate to blocking **only when the optional code graph proves reachability from an untrusted entry point** — community CodeGraph, no Pro taint engine required. (JS/TS, Python, and PHP block on local AST evidence and don't need this.)
- **The gate:** on a high-impact change, DiffGate runs your `testCommand` and shows the actual exit code and output.
- **Learnings:** `diffgate feedback` records dismiss/confirm verdicts; dismissed findings (same rule + same code) are suppressed everywhere. Stored in `.diffgate/learnings.json`; commit it to share across the team.
- **Optional add-ons:** a provider-agnostic AI layer (plain-English explanations + fixes) and a cross-file blast-radius pass via an optional code graph. Both are off by default and degrade gracefully to a no-op.

Engine layout: [`src/core`](src/core) (shared) · [`src/cli.ts`](src/cli.ts) (CLI) · [`src/mcp.ts`](src/mcp.ts) (MCP) · [`extension/`](extension) (VS Code).

---

## Coverage scales with language

How deeply DiffGate analyzes a change depends on the file's language — be explicit about this so you can calibrate how much to trust a clean result.

| Tier | Languages | Depth |
|------|-----------|-------|
| **Deep (AST)** | JS / TS (`@babel`) | All injection classes + public-API & signature changes + deprecated-API quick-fixes. **Prototype pollution** and **NoSQL injection** are JS/TS-only; JS/TS findings are also eligible for code-graph **taint confirmation**. |
| **Deep (AST)** | Python, PHP, Go, Ruby, Java, C#, Kotlin (tree-sitter) | Sink-targeted, parameter- and sanitizer-aware injection detection — placeholders, argument-vectors, and escapers are correctly treated as safe. Sink classes per language below. |

Sink classes per Deep-AST language (full detail — every sanitizer and safe-form, plus the code-graph boundary — in [docs/SCOPE.md](docs/SCOPE.md)):

- **Python** (7) — SQL · XSS · path traversal · CORS · command · code · deserialization
- **PHP** (8) — SQL · command · code · file inclusion · deserialization · XSS · path traversal · CORS
- **Go** (4) — SQL · command · path traversal · CORS
- **Ruby** (6) — SQL · command · code · deserialization · XSS · CORS
- **Java** (6) — SQL · command · deserialization · path traversal · XXE · CORS
- **C#** (7) — SQL · command · deserialization · path traversal · XSS · XXE · CORS
- **Kotlin** (6) — SQL · command · deserialization · path traversal · XXE · CORS

**SSRF** is a cross-language advisory across all eight Deep-AST languages (a request-tainted URL into an outbound-request sink; library-qualified and tainted-only, so static/config URLs aren't flagged). **XXE** covers the JVM (Java, Kotlin) and .NET (C#), suppressed when the file shows recognized hardening. **Permissive CORS** now also covers all eight — wildcard `Access-Control-Allow-Origin`, allow-all framework configs (gin/rs-cors, Spring `@CrossOrigin`, ASP.NET `AllowAnyOrigin()`, Ktor `anyHost()`, rack-cors), and request-reflected origins; explicit allowlists aren't flagged.

| Tier | Languages | Depth |
|------|-----------|-------|
| **Floor (pattern)** | C/C++, Rust, Swift, Scala, … | Secrets, destructive/schema changes, auth/crypto, dynamic exec / shell-out, raw queries, network calls, TODO. Cross-language injection advisories that escalate via the code graph. |
| **Text** | YAML, Terraform, JSON, any text | Secrets and TODO/FIXME markers. |

**Fast by design — and scoped to match.** A review runs in milliseconds on the changed lines, which is exactly what lets the same check sit in the agent and editor inner loop. That speed is a deliberate trade: DiffGate is the deterministic **gate on the diff**, not an exhaustive whole-repo taint engine. Coverage is per-language (deep where there's an AST, a pattern floor elsewhere), the security rules are tuned to the residue agents actually ship rather than to maximize raw rule count, and a clean result means *"nothing matched at this language's tier,"* not *"proven safe."* For deep cross-file taint analysis across many languages, pair it with a dedicated SAST. Full per-language detail and the code-graph boundary: **[docs/SCOPE.md](docs/SCOPE.md)**.

---

## Configuration

`diffgate init` writes a tailored `.diffgate.json` at your repo root. Minimal example:

```jsonc
{
  "testCommand": "npm test",          // run for orange changes (the gate)
  "gate": { "mode": "working", "failOn": "orange" },
  "deprecated": [
    { "pattern": "StripeClient.charge", "replacedBy": "StripeClient.createPaymentIntent" }
  ]
}
```

Any rule — built-in or custom — can be path-scoped with `include`/`exclude` globs, the escape hatch for the one file where a forbidden idiom is legitimate (e.g. `process.env` inside the config loader itself). Full schema, the built-in rule table, LLM providers, and per-rule tuning: **[docs/CONFIG.md](docs/CONFIG.md)**.

---

## More

- **[The PR was reviewed. The risky line wasn't.](docs/posts/the-pr-was-reviewed-the-risky-line-wasnt.md)** — our PR-trail study: 350 merged AI-assisted PRs, 109 with flagged AI-attributed changes, 3 with public human discussion beyond the author.
- **[docs/SCOPE.md](docs/SCOPE.md):** per-language coverage tiers (deep AST vs. pattern vs. text-only) and what the code graph does and doesn't do.
- **[docs/CONFIG.md](docs/CONFIG.md):** full `.diffgate.json` schema, all built-in rules, LLM providers, native precision & test-scope behavior.
- **[docs/TEAM.md](docs/TEAM.md):** rolling DiffGate out to a team (GitHub Action / PR gate, shared learnings, org-wide policy packs, SOC 2 evidence, metrics for leaders).
- **[docs/CODE-GRAPH.md](docs/CODE-GRAPH.md):** optional cross-file blast radius (caller counts, suggested reviewers, test gaps, reachability, taint analysis).
- **[docs/STRUCTURAL-RULES.md](docs/STRUCTURAL-RULES.md):** the `structural` pack — over-engineering rather than vulnerabilities (needless abstractions, pass-through wrappers, complexity spikes), all non-blocking, with per-language thresholds.
- **[docs/MEASUREMENT.md](docs/MEASUREMENT.md):** what agents actually ship unprompted and how to reproduce it (`diffgate marginal`).
- **[MCP.md](MCP.md):** MCP tools, prompts, resources, and AI configuration.

---

## Try it

```bash
diffgate scan mock_project
```

You'll see green findings (logging), yellow findings (a deprecated call), and orange findings (a `DROP COLUMN` migration, a public export).

## Tests

```bash
npm test    # builds the extension, runs the full unit/integration suite + extension smoke test
```

## Support the project

If DiffGate caught something for you — or you just like the idea of a deterministic gate for agent code — **[star the repo ⭐](https://github.com/srbsa/diffgate)**. It's the signal that tells other people this is worth trying.

- 🐛 **Found a false block, or a sink it missed?** [Open an issue](https://github.com/srbsa/diffgate/issues/new) — a false block is a bug we treat as P0.
- 💡 **Want a language or rule covered?** [File a feature request](https://github.com/srbsa/diffgate/issues/new) with the idiom you'd like caught.
- 🔒 **Security report?** Please disclose privately — see [SECURITY.md](SECURITY.md).

## Contributing & License

See [CONTRIBUTING.md](CONTRIBUTING.md). Apache 2.0; see [LICENSE](LICENSE).
