# Configuration: `.diffgate.json`

Place it at your repo root (`diffgate init` generates one). See [example.diffgate.json](../example.diffgate.json) for the full annotated schema.

```jsonc
{
  "extends": ["../../shared/.diffgate.json"],  // path (no npm required) or npm package e.g. "@acme/diffgate-policy"
  "testCommand": "npm test",                 // run for orange changes (the gate)
  "testScope": true,                         // down-tier orange findings in test/fixture files (secrets & destructive schema stay blocking)
  "gate": {
    "mode": "working", "failOn": "orange",
    "agent": { "mode": "advisory", "autoFixFloor": "orange", "maxFixesPerTurn": 3, "escalateAfterTurns": 2, "trustSource": "deterministic" }
  },                                          // agent autonomy ladder: advisory by default (only hard rules block)
  "learnings": { "shared": ["../shared-policy"] }, // merge dismiss/confirm verdicts across repos
  "ai": { "enabled": false, "model": "claude-sonnet-4-6", "apiKeyEnv": "ANTHROPIC_API_KEY" },

  "guidelines": {                            // review diff against AGENTS.md/CLAUDE.md etc.
    "enabled": true,
    "autoDetect": true,                      // walk up to find AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, etc.
    "maxDepth": 3,                           // keep nearest 2 + repo-root; drop middle (logged)
    "tier": "yellow",                        // cap guideline findings here (non-blocking by default)
    "blocking": false,
    "evaluator": "auto"                      // "host" = calling agent judges (no API key); "model" = configured provider
  },

  "deprecated": [                            // drives the deprecated-api rule + quick-fix
    { "pattern": "StripeClient.charge", "replacedBy": "StripeClient.createPaymentIntent",
      "author": "Finance Team", "pr": "PR #204" }
  ],

  "customPatterns": [                        // your own pattern rules
    { "id": "no-process-env", "tier": "yellow", "pattern": "process\\.env\\.",
      "message": "Use the typed config module, not process.env." }
  ],

  "rules": {                                 // tune built-ins
    "todo-marker": false,                    //  - disable a rule
    "network-call": { "tier": "green" }      //  - or change its tier
  },

  "graph": {                                 // optional cross-file blast radius (see docs/CODE-GRAPH.md)
    "enabled": "auto",
    "provider": "codegraph",
    "escalateThreshold": 1,
    "security": "auto",
    "securityDeescalate": false
  },

  "ignore": ["**/node_modules/**", "**/dist/**"]
}
```

---

## Built-in rules

| Rule | Tier | Notes |
|------|------|-------|
| `hardcoded-secret` | 🟠 blocking | AWS keys, GitHub PATs, Stripe secrets, generic credential patterns |
| `db-schema-destructive` | 🟠 blocking | `DROP`, `TRUNCATE`, `DELETE` without `WHERE` |
| `sql-injection` | 🟠 blocking | template literals / concatenation inside SQL calls |
| `db-schema-change` | 🟠 | `ALTER TABLE`, `ADD COLUMN`, `RENAME` |
| `auth-crypto` | 🟠 | passport, JWT, bcrypt, session handlers |
| `dangerous-exec` | 🟠 | `eval()`, `exec()`, `os.system()`, `pickle.loads` |
| `public-api-change` | 🟠 | exported symbols (JS/TS AST) |
| `signature-drift` | 🟠 | exported function parameter changes (JS/TS) |
| `permissive-cors` | 🟠 | `origin: '*'` |
| `xss-sink` | 🟠 | `innerHTML`, `document.write`, `insertAdjacentHTML` (JS/TS) |
| `path-traversal` | 🟠 | `path.join/readFile` called with `req.params/query/body` |
| `nosql-injection` | 🟠 | `$where`, `db.eval`, `Model.find(req.body)` passthrough |
| `prototype-pollution` | 🟠 | `Object.assign(existing, req.body)`, `_.merge` with request data (JS/TS) |
| `deprecated-api` | 🟡 | configured via `deprecated[]`, offers a quick-fix |
| `raw-query` | 🟡 | `db.query()`, bare SQL keywords |
| `network-call` | 🟡 | `fetch`, `axios`, `requests.*` |
| `migration-file` | 🟡 | migration file names |
| `dependency-manifest` | 🟡 | `package.json`, `requirements.txt`, etc. |
| `leftover-debugger` | 🟡 | `debugger` statement (JS/TS) |
| `debug-logging` | 🟢 | `console.log`, `fmt.Print`, `System.out.println` |
| `todo-marker` | 🟢 | `TODO`, `FIXME`, `HACK` |

Disable or re-tier any rule via the `rules` key.

### Native precision (no code graph needed)

Injection and secret findings are refined deterministically from the file's own AST: an XSS sink whose value comes from a recognized sanitizer (`DOMPurify.sanitize`, `escapeHtml`, `encodeURIComponent`, …) is **down-tiered to a yellow "verify" note** rather than blocking, and `hardcoded-secret` drops env/placeholder/low-entropy matches while always keeping (and labeling) known provider key formats. Down-tiering never *suppresses* a security finding, so a missed sanitizer stays blocking (the safe default).

### Test-file noise control (`testScope`, on by default)

Security findings in test, fixture, and mock files are almost always intentional scaffolding (mock SQL, `eval` in a harness, sample payloads), so a 🟠 orange finding there **down-tiers to 🟡 yellow and stops blocking the gate** (surfaced as a review note, never suppressed). The catastrophic-if-real classes stay blocking even in tests: `hardcoded-secret`, `db-schema-destructive`, and the graph-owned public-surface rules. Pin a rule's tier to opt it out, or set `"testScope": false` to gate test code exactly like production.

---

## LLM providers (optional AI layer)

The deterministic engine always runs offline. When `ai.enabled` is true it adds plain-English explanations and fix suggestions. The engine is **provider-agnostic**: two wire adapters (Anthropic Messages API and OpenAI Chat Completions), and OpenAI's format is spoken by almost everything else.

| `provider` | Key env | Notes |
|------------|---------|-------|
| `anthropic` *(default)* | `ANTHROPIC_API_KEY` | Claude models |
| `openai` | `OPENAI_API_KEY` | any model you have access to |
| `openrouter` | `OPENROUTER_API_KEY` | model as `vendor/model` |
| `groq` / `together` | `GROQ_API_KEY` / `TOGETHER_API_KEY` | fast hosted OSS models |
| `lmstudio` / `ollama` | *(none)* | **local models, no key needed** |
| `custom` | your `apiKeyEnv` | any OpenAI-compatible server + `baseURL` |

**Multi-model routing by complexity.** `model` can be a per-tier map so cheap edits use a small model and high-impact ones use a strong one:

```jsonc
"ai": { "enabled": true, "provider": "openai",
        "model": { "orange": "gpt-5.5", "default": "gpt-5.4-mini" } }
```

---

## Guideline review (AGENTS.md / CLAUDE.md)

Reviews the diff against your repo's coding-agent instruction files.

**Detected automatically:** `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`

**Per-directory scoping:** nearest file wins; deep nesting is capped at `maxDepth` (default 3), keeping the closest files + repo-root.

**`evaluator`:** `"auto"` (default) uses the configured provider when available, otherwise returns the guideline text + diff hunks for the calling agent to evaluate with its own model (no API key needed). `"model"` always uses the configured provider.

```bash
diffgate guidelines            # run manually
```

Findings are `yellow` / non-blocking by default (configurable).

---

## Agent autonomy ladder (`gate.agent`)

The deterministic core is the trustable checkpoint between agent-written code and a human. The autonomy ladder grades each finding into `block` / `escalate` / `autofix` / `advisory` with a per-turn fix budget, so agents only hard-stop on genuine hard rules and surface everything else as `review`. `diffgate_capabilities` tells the agent which layers are live up front. See [docs/ai-agents.md](ai-agents.md).
