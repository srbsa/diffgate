# Design: recall strategy & language parity

**Status:** proposal · 2026-06-27
**Decision owner:** @srbsa
**TL;DR:** Two ways to widen what DiffGate catches beyond JS/TS: (A) hand-roll AST rules per language, or (B) borrow recall from an external engine and run it *through the gate*. Recommendation is a **hybrid** — hand-roll the handful of high-value, AST-precise footguns for Python (the #1 AI-codegen language), and borrow recall for the long tail and every other language. This protects the one moat that's hard to rebuild: provable low noise.

---

## 1. Context

DiffGate's strategic identity is **the deterministic gate, not the scanner** (see the strategy note): diff-scoping, tiered triage, selective test-running, "earn-the-block" reachability, blast radius, shared learnings — a layer that is *recall-source-agnostic*. Today its recall (the rules that produce findings) is hand-rolled, and outside JS/TS it is thin:

| Language | Today |
|---|---|
| JS / TS | Full footgun set (SQLi, XSS, path-traversal, proto-pollution, CORS, NoSQL, public-API, signature-drift) via `@babel` AST. |
| Python | AST-precise across **7 sink classes** (SQLi, XSS, path-traversal, permissive-CORS, command-injection, code-injection, unsafe-deserialization) + the cross-language regex floor. |
| PHP | AST-precise across **7 sink classes** (SQLi, command-injection, code-injection, file-inclusion, unsafe-deserialization, XSS, path-traversal) + the floor. |
| Go | AST-precise **SQLi** (`fmt.Sprintf`/concat into `database/sql`·`sqlx`·gorm sinks), **command-injection** (`exec.Command` shell/dynamic-name — arg-vector form safe), **path-traversal** (`os.ReadFile`/`http.ServeFile` of request data) + the floor. |
| Ruby | AST-precise across **5 sink classes** (SQLi via `#{}` into ActiveRecord, command-injection, code-injection, unsafe-deserialization, XSS via `raw`/`html_safe`) + the floor. |
| Java | AST-precise across **4 sink classes** (SQLi via concat/`String.format` into JDBC/JPA/Hibernate, command-injection, native-deserialization `readObject`, path-traversal) + the floor. |
| C# | AST-precise across **5 sink classes** (SQLi via `$"…"`/concat into `SqlCommand`/Dapper/EF, command-injection, `BinaryFormatter` deserialization, path-traversal, XSS via `@Html.Raw`) + the floor. |
| Kotlin / C/C++ / … | Regex floor only (secrets, exec, schema, raw-query, network) + cross-language injection advisories that escalate via the code graph. |

The competitive reality (June 2026): **Semgrep Guardian** owns "deterministic security in the agent via MCP" with 5,000+ rules across 30+ languages, official Cursor + Claude Code partnerships, 3M scans/week. **We cannot win on rule breadth.** Hand-rolling one vuln × one language at a time is a race we lose at scale.

So the question this doc answers: *how do we get useful coverage on Python (and beyond) without that losing race?*

---

## 2. Can we bring Python to JS/TS parity? Yes — here is the cost.

The tree-sitter infrastructure is already in place (`src/core/parsers/treesitter.ts`, the `tsast` rule type) and the SQLi + XSS rules prove the recipe extends. "Parity" = the remaining JS/TS rules, hand-rolled for Python:

| JS/TS rule | Python form | Effort | Marginal value | Notes |
|---|---|:--:|:--:|---|
| sql-injection | ✅ done | — | high | |
| xss-sink | ✅ done | — | med–high | `mark_safe`/`Markup`/`render_template_string`, escaper-aware |
| path-traversal | ✅ done | — | high | `open`/`send_file` from request data, `secure_filename`/`safe_join`/`basename` wrappers down-tier; a mix of sanitized + raw stays orange. |
| permissive-cors | ✅ done | — | med–high | flask-cors `CORS(app)`/`origins='*'`, django `CORS_ALLOW_ALL_ORIGINS = True`, manual `Access-Control-Allow-Origin: *`; explicit allowlist not flagged. |
| nosql-injection | pymongo `collection.find(request.json)`, `$where` | L–M | low | Models avoid it; less common in Python than Node/Mongo. |
| prototype-pollution | n/a (no prototype chain) | — | — | Python analog = **mass-assignment** (`setattr(obj, user_key, …)`, `obj.__dict__.update(request.json)`) — a *different* rule, optional. |
| public-api-change / signature-drift | changed signature of a public (no leading `_`, or in `__all__`) def/class | M | med | Requires prev-vs-current tree-sitter AST diff (today `detectSignatureDrift` is babel-only). This is **blast-radius, not security** → aligns with the gate identity. |
| deprecated-api | already cross-language via regex | ✅ | — | Effectively at parity already. |

**Status (0.6.0):** the four security classes that apply to Python — sql-injection, xss-sink, path-traversal, permissive-cors — are **done**. What remains to call it full JS/TS parity: `signature-drift`/`public-api` (the only item with merit — blast-radius, not security; needs a tree-sitter prev-vs-current diff since `detectSignatureDrift` is babel-only) and two low/different-value optionals (nosql-injection, mass-assignment). Closing the rest would start the per-language treadmill (Ruby/Go/Java/C#/…), which is why §3 (borrow recall) is the breadth answer instead.

---

## 3. Option B: borrow recall, run it through the gate

Instead of authoring rules, consume an external recall engine and pipe its raw findings into DiffGate's existing pipeline (diff-scope → tier-map → reachability escalation → test-gate → learnings). The incumbent becomes a **backend**, not a competitor.

### Interface (mirrors the existing `GraphProvider` optionality)

```ts
interface RecallProvider {
  id: string;
  // Raw findings for a file; null/empty when the engine is absent (→ no-op, never an error).
  scan(file: string, content: string): RawFinding[] | null;
}
interface RawFinding { ruleId: string; line: number; endLine?: number; severity: string; message: string; }
```

A `SemgrepProvider` shells out to `semgrep --json --config auto` (optional dep; degrade to no-op if the binary is absent, exactly like `codegraph-server`). Map Semgrep severity → DiffGate tier **conservatively**, then run the mapped findings through the *same* gate machinery:

1. **diff-scope** — drop anything off the changed lines (Semgrep scans whole files; the gate only cares about the diff).
2. **tier-map** — `ERROR→orange`, `WARNING→yellow`, `INFO→green`; **never auto-block** on a borrowed finding — make borrowed findings advisory and let reachability/learnings decide, same contract as `sql-injection-candidate`.
3. **dedup** — prefer DiffGate's own rule when both fire on the same sink (our hand-tuned JS rules stay authoritative).
4. **learnings + diff-scope** carry over for free.

### Alternative: bundled tree-sitter-query packs
Ship `.scm` query files per language (we already load tree-sitter grammars). Lighter than Semgrep (no external binary, sub-second, no licensing entanglement) — but we'd still author the queries, so it's hand-work in a query DSL rather than TS. Good middle path for languages where we want control without a Semgrep dependency.

### Spike (1–2 days, measure then decide)
Build `SemgrepProvider` behind a flag; run on a real Python repo and on the clean bench corpus. **Go/no-go on three numbers:**
- **recall gain** — net new true findings on the diff vs today;
- **false-block rate on the clean corpus** — must stay **0** (this is the brand; if borrowed findings push it off 0 even when mapped to advisory, the mapping is wrong);
- **latency** — Semgrep cold start vs our sub-second budget (matters for the MCP/editor inner loop).

### Spike results (2026-06-27 — real run, semgrep 1.168.0, `--config p/python`)

Built the integration (`src/core/recall/semgrep.ts`, `test/recall.test.js`) + harness (`scripts/recall-spike.mjs`) and ran it over a 10-file Python corpus (6 vulnerable, 4 clean). Numbers:

| Metric | Result | Verdict |
|---|---|---|
| **1. recall gain** | **+6 net-new true findings** DiffGate misses — Flask `debug=True`/bad-host (2), MD5-as-password (2), SSRF `requests.get(user_url)` (1), and a SQLi on a line ours didn't tag (1) | **real, and complementary** — these are classes we have no rule for |
| **2. false-block** | **0** (borrowed findings are advisory by construction) | ✅ the brand-critical invariant holds |
| **clean-corpus noise** | **0** borrowed findings on the 4 known-clean files | ✅ (small corpus — directional, not proof) |
| **3. latency** | **~2,600 ms/file** semgrep cold-start vs **~2.4 ms/file** DiffGate (~1000×) | ⛔ the deciding constraint |

**Read:** semgrep finds genuine vulnerabilities we don't (weak crypto, SSRF, framework misconfig) with **zero added noise on clean code and zero blocking** — exactly the complementary recall the borrow strategy promises. But the **~2.6 s cold start is fatal for the inner loop** (the editor/MCP self-check whose entire value is DiffGate's millisecond latency). It is a non-issue at the CI/PR layer, where a few seconds is invisible. Even Semgrep's curated `p/python` had gaps (missed tar-slip and a weak-RNG token) — confirming no single recall source is complete.

**Caveats:** small corpus (directional); line-based dedup is fragile (the SQLi double-counted because semgrep tagged a different line than ours — productionizing needs rule-class + line-range overlap, not exact-line); per-file latency overstates the cost for a real multi-file diff (one batched `semgrep` call amortizes startup); registry rulesets need a network fetch on first use.

**Spike verdict: GO at the CI/PR layer, NO-GO (as-is) for the inner loop.** This directly validates the hybrid: hand-rolled AST-precise rules carry the fast local loop; borrowed recall runs at the gate (async / batched) for breadth across all languages.

### Risks
- **Noise.** Semgrep's default rules are tuned for completeness, not our 0-false-block bar. Mitigate by mapping to advisory + diff-scope + learnings; if it still pollutes, prefer the tree-sitter-query pack route with our own curated queries.
- **Licensing.** Semgrep CE rules / Registry terms — verify redistribution is OK before bundling; safest is "use the user's installed semgrep," not vendoring rules.
- **Latency & dep weight.** Semgrep is a Python binary; the inner-loop budget is tight. The provider must be off by default and fully no-op when absent.

---

## 4. Recommendation — hybrid

1. **Hand-roll the high-value, AST-precise Python footguns now:** `path-traversal` (guard-aware — turns the JS rule's weak spot into a strength) and `permissive-cors`. These are measured footguns, precise, low-noise, DiffGate-owned. (SQLi + XSS already done.)
2. **Do *not* hand-roll the long tail** (Python nosql/mass-assignment, and every footgun for Ruby/Go/Java/C#/…). Run the **borrow-recall spike** and let the three numbers decide. If green, that path delivers breadth for *all* languages at once — the only way to answer Semgrep's 30-language coverage without the treadmill.
3. **For the "change-impact gate" identity:** bring `signature-drift`/`public-api` to Python (prev-vs-current tree-sitter AST diff). This is blast-radius, not security, and it's the part of the product Semgrep/CodeRabbit *don't* do — worth owning regardless of the recall decision.
4. **Guardrail for every new rule:** does it protect or erode the 0-false-block low-noise brand, and does it serve the gate identity (precision / reachability / impact) rather than just adding scanner recall we'll lose to Semgrep? If borrowed recall can cover it acceptably, prefer that over hand-rolling.

**Done this session (both tracks):**
- **(a) Python parity rules** — AST-precise `xss-sink`, `path-traversal` (request-source + sanitizer-wrapper aware), and `permissive-cors` added to `src/core/rules/python.ts` (joining `sql-injection`). Python now covers 4 of the JS/TS footgun classes at AST precision. +19 tests.
- **(b) borrow-recall spike** — `src/core/recall/semgrep.ts` + `test/recall.test.js` + `scripts/recall-spike.mjs`, run against real semgrep (results above). Verdict: GO at CI/PR, NO-GO inner-loop.

**Productionized (2026-06-27):** `RecallProvider` is wired into `reviewChanges` behind a config gate (`recall.enabled`: `false` default · `"ci"` only under CI · `true` always; `diffgate check --recall` forces it on). One **batched** semgrep call per review (`scanFiles`), not per-file. Borrowed findings are diff-scoped, deduped against native findings by **line + vulnerability class** (`classOf` — so `network-call` no longer suppresses a semgrep SSRF on the same line), **capped at yellow** so they never trip the `failOn: orange` gate, and namespaced `semgrep:`. Off by default and a no-op when the binary is absent, so the inner loop (MCP/editor, which don't call `reviewChanges` with recall active locally) is untouched. Verified end-to-end against real semgrep: a Flask SSRF DiffGate's own rules miss surfaces as a 🟡 advisory and the gate stays green. `test/recall.test.js` covers gating, batching, class-dedup, and the never-block invariant.

**Still open (optional):** hand-roll the remaining Python rules (nosql, mass-assignment, signature-drift) only if the gate identity needs them; broaden the class map as new rule families land.
