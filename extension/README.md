# DiffGate Review (VS Code Extension)

Diff-aware, three-tiered code review **inline in your editor**. DiffGate looks at the lines you actually changed (vs the committed baseline) and tells you which edits are safe, which need a second look, and which are high-impact enough to gate — before you ever open a pull request.

## Tiers

| Tier | Meaning | Examples |
|------|---------|----------|
| 🟢 Green | Safe / self-contained | comments, local logging |
| 🟡 Yellow | Review — soft dependency | deprecated APIs, raw queries, network calls |
| 🟠 Orange | High-impact — gate it | schema changes, secrets, auth/crypto, injection sinks, public-API & signature changes |

## Features

- **Inline diagnostics** on changed lines only (configurable to whole-file mode).
- **Hover cards**: why it's risky, who owns the baseline line (git blame), and quick links to AI explain or Deep Review.
- **Deep Review**: for orange findings, an agentic loop uses real repo tools (grep, read_file, git_blame, find_references) to investigate blast radius and shows a verdict badge directly in the hover card.
- **Quick-fixes**: replace a deprecated call with its successor (⌘. / Ctrl+.).
- **Risk Review** tree: every pending change across the workspace, grouped by file and tier.
- **Status bar** risk summary for the active file.
- **Verification gate**: run your project's `testCommand` for high-impact changes.
- **Signature-drift detection**: warns when you change an exported function's parameter list (callers may break).
- **Hybrid AI** (optional, provider-agnostic): works with Anthropic, OpenAI, OpenRouter, Groq, Together, LM Studio, Ollama, or any OpenAI-compatible endpoint.

## Configuration

Project rules live in a `.diffgate.json` at the repo root (run `diffgate init` from the CLI, or **DiffGate: Open Config**). Editor settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `diffgate.scanMode` | `diff` | `diff` = changed lines only; `file` = whole file |
| `diffgate.diffMode` | `working` | `working` = all uncommitted changes; `staged` = staged only |
| `diffgate.ai.enabled` | `false` | Enable AI explanations (needs provider API key, except for local models) |
| `diffgate.ai.provider` | *(from config)* | LLM provider override |
| `diffgate.ai.model` | *(from config)* | Model id override |
| `diffgate.ai.deepReview.model` | *(from config)* | Stronger model for Deep Review (e.g. `claude-opus-4-8`, `gpt-4o`) |
| `diffgate.runGateOnSave` | `false` | Auto-run the gate on save when orange findings are present |

## Develop / run

From the repo root: press **F5** ("Run DiffGate Extension") to launch an Extension Development Host. Open a file (e.g. in `mock_project/`) to see findings; open a git repo to see diff-aware mode and the Risk Review tree.

Build a `.vsix` to install permanently:

```bash
npm install --prefix extension
npm run package --prefix extension   # produces extension/diffgate-0.1.2.vsix
code --install-extension extension/diffgate-0.1.2.vsix
```

## License

Apache 2.0
