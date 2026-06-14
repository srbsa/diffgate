# Contributing to DiffGate

Thank you for your interest in contributing. DiffGate is Apache 2.0 licensed and welcomes pull requests, bug reports, and feature ideas.

## Prerequisites

- Node.js 18 or later
- npm 8 or later
- Git (for diff-aware features)

## Setup

```bash
git clone https://github.com/srbsa/diffgate.git
cd diffgate
npm install
npm install --prefix extension
```

## Running tests

```bash
npm test
```

This builds the VS Code extension bundle, then runs 47 unit/integration tests and the extension smoke test.

## Project layout

```
src/
  cli.js              CLI entry point
  mcp.js              MCP stdio server
  core/
    analyzer.js       Orchestrates rules + AI + signature drift
    rules/
      builtin.js      All built-in rules (pattern, AST, file)
      index.js        Rule runner and registration
    llm/              Provider-agnostic LLM adapters
    agent/            Deep Review ReAct loop
    git.js            Git diff helpers
    linediff.js       In-memory LCS diff (for editor)
    parsers/          @babel/parser wrapper for JS/TS

extension/
  src/extension.js    VS Code extension (bundled by esbuild)
  test/smoke.cjs      Extension smoke test

test/                 Core unit tests (node:test)
mock_project/         Demo files for `diffgate scan mock_project`
```

## Adding a rule

Rules live in `src/core/rules/builtin.js` as entries in the `BUILTIN_RULES` array. Three types:

- **`pattern`** — regex on changed lines (works for any language)
- **`ast`** — Babel visitor for JS/TS (precise, comment-aware)
- **`file`** — path/filename heuristics, runs once per file

```javascript
// Minimal pattern rule:
{
  id: "my-rule",
  type: "pattern",
  tier: "orange",      // green | yellow | orange
  blocking: false,     // true = also gates the commit
  title: "Short title",
  languages: ["*"],    // or ["javascript", "typescript"]
  message: "What's wrong and how to fix it.",
  patterns: [/regex1/, /regex2/],
}
```

Add a test in `test/core.test.js` for the triggering case and at least one safe case. Run `npm test` before opening a PR.

## Extension development

Press **F5** in VS Code to launch an Extension Development Host with the current source.

Changes to `extension/src/extension.js` need a rebuild before the smoke test sees them:

```bash
npm run build:ext      # or: npm run build --prefix extension
node extension/test/smoke.cjs
```

## PR guidelines

- Keep changes focused — one feature or fix per PR.
- If you add a rule, include test cases for both the triggering and safe scenarios.
- If you change the MCP protocol or tool schemas, update `MCP.md`.
- All tests must pass (`npm test`).

## Reporting issues

Open an issue on GitHub. Include:
- DiffGate version (`diffgate --version`)
- Node.js version (`node --version`)
- The command or operation that failed
- Relevant output or error messages

## Code of conduct

Be respectful. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).
