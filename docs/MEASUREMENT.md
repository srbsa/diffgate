# What agents actually ship unprompted (and what DiffGate adds)

The honest question behind DiffGate's agent value isn't *absolute* detection (that's [`diffgate bench`](../BENCHMARK.md)). It's the counterfactual: **of the risky code DiffGate catches, how much would a coding agent ship on its own, with no security hint?**

`diffgate marginal` ([src/marginal.ts](../src/marginal.ts)) measures it directly. Hand a model a realistic task with **no security hint**, run the gate over its output. A "defect catch" means the gate would have fired on objectively unsafe code the model wrote unprompted.

---

## The headline

**Textbook OWASP issues: 0% across every model, both modes.** SQL injection (models parameterize), XSS (they use `textContent`), secrets (they read from env), `eval`/`exec`, NoSQL `find(req.body)`, Python yaml/pickle/subprocess. A decent model (local 9B to frontier) already avoids these unprompted. Leading DiffGate's agent story with OWASP-top-10 detection would overstate the value.

**The marginal value is real but narrow, and it's frontier-resistant.** Second-order footguns (**prototype pollution** and **permissive CORS**) show up even when a flagship model writes the code, especially when editing an existing file.

---

## Cross-model × cross-mode defect-catch

4 models (local 9B → frontier), no security hint, whole-file (greenfield) **and** edit-an-existing-file modes. Wilson 95% CIs over pooled (scenario × sample) trials.

| model | mode | samples | defect-catch | 95% CI | trials |
|---|---|--:|--:|:--:|--:|
| qwen3.5-9b (local) | greenfield | 5 | 16% | [9–26%] | 11/70 |
| qwen3.5-9b (local) | **edit** | 5 | **19%** | [11–29%] | 14/75 |
| gpt-5.4-nano | greenfield | 1 | 7% | [1–30%] | 1/15 |
| gpt-5.4-nano | **edit** | 1 | **20%** | [7–45%] | 3/15 |
| gpt-5.4-mini | greenfield | 1 | 13% | [4–38%] | 2/15 |
| gpt-5.4-mini | **edit** | 1 | **20%** | [7–45%] | 3/15 |
| gpt-5.5 (flagship) | greenfield | 1 | **0%** | [0–20%] | 0/15 |
| gpt-5.5 (flagship) | **edit** | 1 | **13%** | [4–38%] | 2/15 |

### Reading the table

1. **Edit > greenfield for every model.** The realistic case, an agent editing existing code, is where guards get dropped. The flagship model is **0% from scratch but 13% editing**: it writes a *guarded* `deepMerge` (`if (key === '__proto__') continue`) from scratch, then drops the guard when editing a file. A greenfield-only measurement *understates* the value.
2. **The catches concentrate in 3 scenarios:** prototype-pollution (`deepMerge`), permissive-CORS (bare `cors()`), path-traversal (`download`):
   - **High confidence: proto-pollution + permissive-CORS.** Precise AST/pattern rules that fire *only* on the unsafe form (`cors()` but not `cors({ origin: allowlist })`). Proven by the flagship's guarded-vs-unguarded split above.
   - **Softer: path-traversal.** The pattern fires on `req → path.resolve/readFile` even when a `startsWith(baseDir)` containment guard follows. About half the greenfield "catches" here are guarded-safe code; edit-mode ones (`path.join(__dirname, '..', 'uploads', name)` with no check) are real. Report it discounted.
3. **Advisory rate 27–33%** (auth-crypto / destructive-migration / shell-out): these fire on correct code too and are **never** counted as defects.

---

## The takeaway

Lead the agent story with the defensible claim, not OWASP detection:

> DiffGate catches the second-order footguns even frontier models drop when editing code (prototype pollution, permissive-CORS defaults) before the diff reaches you.

Edit mode is the proof.

---

## Reproduce it

```bash
# OpenAI (needs OPENAI_API_KEY)
diffgate marginal --provider=openai --model=gpt-5.5 --mode=both --samples=1 --max-tokens=8000 --json --out=./out

# Local (LM Studio / Ollama, no key)
diffgate marginal --provider=lmstudio --base-url=http://localhost:1234/v1 \
  --model=qwen/qwen3.5-9b --mode=both --samples=5 --temperature=0.7 --max-tokens=6000
```

Assemble the table from the per-model `--json` files. The corpus is 17 scenarios spanning JS + Python + SQL (all defect rules + Python deserialization/shell-out), with two known-gap probes excluded from the headline. gpt-5.x reject non-default temperature (forced to 1); qwen ran at 0.7.
