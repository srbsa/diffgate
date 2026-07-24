# Structural rules

Everything else DiffGate ships asks *"is this line dangerous?"*. This pack asks a different
question: **"is this more code than the change needed?"**

LLMs are good at producing code that passes review. They are also biased, by their training
distribution, toward enterprise shapes — an interface for one implementation, a wrapper around a
one-line call, a class where a function would do. The result is syntactically flawless, well
formatted, and convincing in a diff, which is exactly why human reviewers wave it through. These
rules are a tripwire for that.

> **Every rule here is 🟡 yellow and non-blocking.** A threshold is a judgement call, and judgement
> calls must never block a gate. The worst case for a mis-tuned rule is a review note you dismiss.

---

## The rules

### Universal metrics

Computed on the AST that the security rules already parsed, so the added cost is one extra walk.

| Rule | Fires when | Languages |
|---|---|---|
| `cognitive-complexity-spike` | Cognitive complexity (SonarSource) exceeds the language threshold | 8 |
| `deep-nesting` | Control-flow nesting exceeds the language threshold | 8 |
| `long-function` | Function line count exceeds the language threshold | 8 |
| `too-many-parameters` | Parameter count exceeds the language threshold | 8 |

Cognitive complexity is not cyclomatic complexity. It charges +1 per decision point, **plus the
current nesting depth**, so a branch buried three levels deep costs far more than a flat one — which
is the thing that actually makes code hard to read. A `switch` with twelve flat cases scores low; a
triple-nested `if` scores high.

### Language anti-patterns

Each is written narrowly. The idiomatic lookalike must stay quiet, so these check for the *exact*
shape and bail at the first sign the author had a reason.

| Rule | Fires when | Stays quiet when |
|---|---|---|
| `py-unnecessary-class` | Class is `__init__` + exactly one method | Any base class, any decorator (`@dataclass`, `@property`), 0 or 2+ methods |
| `py-unnecessary-abc` | An `ABC` with no second implementor in the file | A second implementor exists; the base is not an ABC |
| `go-premature-interface` | Interface with ≤2 methods that nothing in the file consumes | A call site accepts it; the interface is rich (>2 methods) |
| `java-single-impl-interface` | Interface with exactly one implementing class in the file | Zero implementors (likely external) or two or more |
| `ts-over-generic` | Type alias nests generics more than 3 deep | Shallower types |

### Indirection

| Rule | Fires when |
|---|---|
| `pass-through-wrapper` | A single-statement body that forwards its parameters unchanged — same arity, same identifiers, same order |
| `diff-churn-ratio` | Many changed lines for very few net AST statements |

`pass-through-wrapper` deliberately does **not** fire when the call reshapes arguments, injects a
default, validates first, or reorders parameters. Those wrappers are doing work.

### Graph-backed

| Rule | Fires when |
|---|---|
| `single-caller-abstraction` | A new class or interface has ≤1 caller **across the repository** |

This is the one rule a file-local linter cannot write, and the only one here that proves rather than
estimates. It runs in two passes: a detector emits a candidate for every new abstraction, then
[`attachStructuralImpact`](../src/core/structural-impact.ts) asks the code graph for the real caller
count and confirms or retracts.

**An unknown is never treated as a zero.** No graph, no coverage for that language, a walk that hit
its budget, a provider that threw — every one of those drops the finding rather than reporting
"0 callers". Crying wolf on an incomplete graph is the one failure mode that would make this rule
worthless, so it is inert by default:

```jsonc
{ "rules": { "single-caller-abstraction": { "enabled": true } } }
```

---

## Tuning

### Turn the whole family off (or on)

```jsonc
{ "rules": { "structural": false } }
```

`"structural": true` does the reverse — it opts in the whole pack including the default-off
graph-backed rule.

### Per-rule

```jsonc
{
  "rules": {
    "py-unnecessary-class": false,
    "deep-nesting": { "exclude": ["**/generated/**"] }
  }
}
```

### Per-language thresholds

Defaults follow SonarSource, Clippy, and golangci-lint conventions. A 50-line Go function is a red
flag; a 50-line Rust `match` with exhaustive arms is normal — so a single global ceiling would
systematically over-flag some languages and under-flag others.

```jsonc
{
  "languageOverrides": {
    "python": { "maxCognitiveComplexity": 10, "maxNestingDepth": 3, "maxFunctionLines": 25, "maxParameters": 4 },
    "go":     { "maxCognitiveComplexity": 10, "maxNestingDepth": 3, "maxFunctionLines": 35, "maxParameters": 4 },
    "java":   { "maxCognitiveComplexity": 15, "maxNestingDepth": 4, "maxFunctionLines": 50, "maxParameters": 5 },
    "_default": { "maxCognitiveComplexity": 12, "maxNestingDepth": 4, "maxFunctionLines": 40, "maxParameters": 5 }
  }
}
```

Resolution order, most specific wins:

```
built-in defaults  ←  built-in language defaults  ←  languageOverrides._default  ←  languageOverrides.<lang>
```

Findings are dismissible through the normal learnings flow (CLI and the VS Code Code Action), same
as any other rule.

---

## How noisy is it, really?

Measured over this repository's own 68 hand-written TypeScript files — code that should be close to
silent — with default configuration:

| Mode | Files with a finding | Findings per file |
|---|---|---|
| Whole-file (`diffgate scan`, audit) | 72% | 2.62 |
| **Diff-scoped (`diffgate check`)** | **9%** | **0.12** |

Diff-scoping is the number that matters, because that is what the gate actually runs. A rule only
surfaces when its anchor line is inside the diff, so unchanged legacy complexity stays silent — you
are told about the complexity *you just added*.

If you run whole-file audits regularly and find that noisy, disable the pack for that path or raise
the thresholds; the diff path is tuned independently of it.
