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
    "security": "auto",                       // Pro taint tracing (enrich-only)
    "securityDeescalate": false,
    "reachability": "auto",                   // community-edition reachability escalation
    "reachabilityDeescalate": false,          // never auto-clear "unreachable" (fail-safe)
    "untrustedEntryKinds": ["http_handler", "event_handler"],
    "reachabilityMaxDepth": 6,                // caller-chain hops before giving up
    "reachabilityTimeoutMs": 4000
  },

  "ignore": ["**/node_modules/**", "**/dist/**"]
}
```

---

## Built-in rules

| Rule | Tier | Notes |
|------|------|-------|
| `hardcoded-secret` | 🟠 blocking | AWS keys, GitHub PATs, Stripe secrets, AI-provider keys (Anthropic `sk-ant-…`, OpenAI `sk-proj-…`/legacy), Hugging Face, GitLab PATs, npm tokens, generic credential patterns |
| `db-schema-destructive` | 🟠 blocking | `DROP`, `TRUNCATE`, `DELETE` without `WHERE` |
| `sql-injection` | 🟠 blocking | Interpolation/concatenation/`sprintf` inside SQL calls. JS/TS AST; Python AST (f-string/`%`/`.format`); PHP AST (`mysqli_query`/`$pdo->query`/`->prepare`, Laravel `whereRaw`/`orderByRaw`); Go AST (`fmt.Sprintf`/concat into `database/sql`·`sqlx`·gorm sinks; `?`/`$1` placeholders safe); Ruby AST (`#{}` into ActiveRecord `where`/`find_by_sql`/`order`/…; placeholder & hash forms safe); Java AST (concat/`String.format` into JDBC/JPA/Hibernate/JdbcTemplate sinks incl. keyword-less HQL; `?`-placeholders safe); C# AST (`$"…"`/concat/`string.Format` into `SqlCommand`/`CommandText`/Dapper/EF `FromSqlRaw`; parameters & `FromSqlInterpolated` safe); Kotlin AST (`"$x"`/`"${expr}"`/concat into JDBC/JPA/Android `rawQuery`; `?`-placeholders & const templates safe); JS-shaped regex fallback elsewhere. Parameter- & sanitizer-aware. |
| `command-injection` | 🟠 blocking | PHP AST: `exec`/`shell_exec`/`passthru`/`system`/`proc_open`/`popen`/backticks with a dynamic arg (`escapeshellarg`/`escapeshellcmd` down-tier; arg-array form is safe). Python AST: `os.system`/`os.popen`/`subprocess.getoutput` (always-shell) and `subprocess.run`/`Popen`/… with `shell=True` and a dynamic arg (`shlex.quote` down-tier; the argument-list form is safe). Go AST: `exec.Command`/`CommandContext` — a static shell (`sh`/`bash`/`cmd`) with a dynamic arg, or a request-tainted program name (the arg-vector form is safe — Go uses no shell). Ruby AST: `system`/backticks/`%x`/`IO.popen`/`Open3` with a single interpolated string (the multi-arg form is safe; `Shellwords.escape` down-tier). Java AST: `Runtime.exec`/`ProcessBuilder` with a concat/`String.format`-built or request-tainted argument (a bare opaque parameter is not flagged). C# AST: `Process.Start`/`ProcessStartInfo` with a dynamic or request-tainted command. Kotlin AST: `Runtime.exec`/`ProcessBuilder` with a template/concat-built or request-tainted value. |
| `code-injection` | 🟠 blocking | PHP AST: `eval`/`create_function`/string-`assert` of a dynamic value (RCE). Python AST: `eval`/`exec`/`compile` of a dynamic value (a literal is safe; `df.eval`/`ast.literal_eval` are not flagged). Ruby AST: `eval`/`instance_eval`/`class_eval`/`module_eval` of a dynamic value (the block form is not flagged). |
| `file-inclusion` | 🟠 blocking | PHP AST: `include`/`require`(`_once`) of a dynamic path — LFI/RFI (`basename()` down-tier; `__DIR__`/constant-built paths are safe). |
| `unsafe-deserialization` | 🟠 blocking | PHP AST: `unserialize()` of a dynamic value — object injection / POP chains (`['allowed_classes'=>false]` down-tier). Python AST: `pickle`/`marshal`/`dill` `.load`/`.loads` and `yaml.load` of a dynamic value (`yaml.safe_load` / `Loader=SafeLoader` down-tier; `FullLoader` still blocks). Ruby AST: `Marshal.load`/`YAML.load`/`Oj.load` of a dynamic value (`YAML.safe_load` is safe). Java AST: `ObjectInputStream.readObject`/`readUnshared`, `XStream.fromXML` — the canonical native-deserialization RCE sink. C# AST: `BinaryFormatter`/`SoapFormatter`/`LosFormatter`/`NetDataContractSerializer` `.Deserialize` (resolved via the receiver's `new …()`). Kotlin AST: `ObjectInputStream.readObject`/`readUnshared` on a receiver. |
| `db-schema-change` | 🟠 | `ALTER TABLE`, `ADD COLUMN`, `RENAME` |
| `auth-crypto` | 🟠 | passport, JWT, bcrypt, session handlers |
| `dangerous-exec` | 🟠 | `eval()`, `exec()`, `os.system()`, `pickle.loads`, Go `exec.Command`, Ruby `system`/`%x{}` — blocks when reachable. (Defers to the precise `command-injection`/`code-injection`/`unsafe-deserialization` AST rules on PHP and Python.) |
| `public-api-change` | 🟠 | exported symbols (JS/TS AST) |
| `signature-drift` | 🟠 | exported function parameter changes (JS/TS) |
| `permissive-cors` | 🟠 | JS/TS: `origin: '*'`, bare `cors()`. Python: flask-cors `CORS(...)`/`@cross_origin`, `CORS_ALLOW_ALL_ORIGINS=True`, manual `Access-Control-Allow-Origin: *`. PHP: wildcard `header("Access-Control-Allow-Origin: *")` or a request-reflected origin, incl. `$resp->headers->set(...)`/`->withHeader(...)` (a generic `->set` on a non-CORS header is not flagged). Go: header wildcard/reflected, gin `AllowAllOrigins`/`AllowOrigins: {"*"}`/`AllowOriginFunc { return true }`/`cors.Default()`, rs/cors `AllowedOrigins: {"*"}`/`cors.AllowAll()`. Ruby: rack-cors `origins '*'`, header wildcard/reflected. Java/Kotlin: bare or `"*"` `@CrossOrigin`, `.allowedOrigins("*")` + variants, header wildcard/reflected, Ktor `anyHost()`. C#: `.AllowAnyOrigin()`, `.WithOrigins("*")`, `Response.Headers` wildcard/reflected. Explicit allowlists are never flagged |
| `xss-sink` | 🟠 | JS/TS: `innerHTML`, `document.write`, `insertAdjacentHTML`. Python: `mark_safe`/`Markup`/`render_template_string`. PHP: `echo`/`print`/`printf`/`<?=` of request superglobals (escaper-aware). Ruby: `raw`/`.html_safe`/`safe_concat` of a dynamic value (`sanitize`/`h` down-tier). C#: `@Html.Raw`/`Response.Write`/`new HtmlString` of a dynamic value (`HttpUtility.HtmlEncode` down-tier). |
| `ssrf` | 🟠 (advisory) | A **request-tainted** URL/host into an outbound-request sink, across all 8 Deep-AST languages — JS `fetch`/`axios`, Python `requests`/`urllib`, Go `http.Get`/`NewRequest`, Ruby `Net::HTTP`/`HTTParty`, PHP `curl`/`fsockopen`, Java `new URL`/`RestTemplate`, C# `HttpClient`/`WebRequest`, Kotlin `URL(...)`/OkHttp. Library-qualified, so a generic `.get` on a dict/cache is not flagged; a static/config URL is never flagged. |
| `xxe` | 🟠 (advisory) | An XML parser created without disabling DOCTYPE/external entities, on the JVM (Java, Kotlin: `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`TransformerFactory`/dom4j `SAXReader`) and .NET (C#: legacy `XmlTextReader`, `DtdProcessing.Parse` without a null resolver, explicit `XmlUrlResolver`). **Suppressed** when the file shows recognized hardening (JVM `disallow-doctype-decl`/`FEATURE_SECURE_PROCESSING`/`SUPPORT_DTD=false`/…; .NET `DtdProcessing.Prohibit`/`XmlResolver=null`). Modern safe-by-default APIs (`XmlReader.Create`, `XmlSecureResolver`) are not flagged. |
| `path-traversal` | 🟠 | JS/TS: `path.join/readFile` with `req.params/query/body`. Python: `open`/`send_file` of request data. PHP: `fopen`/`readfile`/`file_get_contents`/`unlink`/… of request data, incl. SSRF (`basename`/`realpath` aware). |
| `nosql-injection` | 🟠 | `$where`, `db.eval`, `Model.find(req.body)` passthrough (JS/TS) |
| `prototype-pollution` | 🟠 | `Object.assign(existing, req.body)`, `_.merge` with request data (JS/TS) |
| `deprecated-api` | 🟡 | configured via `deprecated[]`, offers a quick-fix |
| `sql-injection-candidate` | 🟡 advisory | non-AST injection idioms (Ruby `#{}`, etc.); **never blocks alone** — escalates to blocking 🟠 only when CodeGraph confirms reachability from an untrusted entry point. JS/TS, Python, and PHP use their precise AST `sql-injection` rule instead (this is their fallback only when the grammar can't load). |
| `raw-query` | 🟡 | `db.query()`, bare SQL keywords; escalates when reachable |
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

### Borrowed recall (`recall`, optional, off by default)

For broader language coverage at the **CI/PR layer**, DiffGate can run an external scanner ([Semgrep](https://semgrep.dev)) and pass its findings through the same gate. This is for CI, not the local inner loop: Semgrep's startup cost is invisible in a pipeline but too slow for live editing. Borrowed findings are **advisory** — diff-scoped, deduped against DiffGate's own findings (by line + vulnerability class), capped at 🟡 yellow, and **never block the gate** (the 0-false-block guarantee is preserved). They appear with a `semgrep:` rule prefix.

```jsonc
{
  "recall": {
    "enabled": "ci",        // false (default) · "ci" = only when CI is set · true = always
    "provider": "semgrep",  // requires the `semgrep` binary on PATH (e.g. `pip install semgrep`)
    "config": "auto",       // semgrep --config (e.g. "p/python", "auto")
    "timeoutMs": 60000
  }
}
```

`enabled: "ci"` activates it only when `process.env.CI` is set, so it runs in your pipeline but not when a developer runs `diffgate check` locally. `diffgate check --recall` force-enables it for a single run. If the binary isn't found, recall is silently skipped — the gate behaves exactly as if `recall` were off. In your CI workflow, install semgrep (e.g. `pip install semgrep`) before the DiffGate step.

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
