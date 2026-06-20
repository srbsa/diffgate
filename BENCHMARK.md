# DiffGate noise benchmark

The differentiator for a code reviewer isn't catch rate — it's noise. A tool the team
learns to scroll past is worthless no matter how much it catches. This benchmark measures
the two things that actually predict adoption, and keeps them separate:

1. **Detection accuracy** on a labeled set of known-bad and look-alike-safe snippets
   (precision / recall / F1 per rule).
2. **Gate noise** — how often the deterministic gate would **falsely block a safe change**.

Run it:

```bash
diffgate bench          # human table
diffgate bench --json   # machine-readable, for CI tracking or publishing
```

## Methodology

- The corpus is versioned in [`src/bench.ts`](src/bench.ts) as `CORPUS` — every case is a
  small diff labeled with the rule ids that *should* fire (empty = a clean change that
  must not trip the gate). It is deterministic and offline: no model, no network, so
  results are reproducible by anyone.
- Each case is analyzed by the same engine the CLI/extension use.
- **Positive cases** (a real issue is present) measure detection: recall (did we catch the
  labeled issue?) and cross-rule confusion (a fired rule not in the label set).
- **Clean cases** (safe code) measure noise, split by tier:
  - **false blocks** = 🟠 orange (gating) findings on safe code. **This must be 0** — the
    gate may never falsely block.
  - **advisories** = 🟡 yellow / 🟢 green findings on safe code. These are by design
    (informational, non-blocking) and are reported separately so they never inflate the
    blocking number.

This split is the honest version of the "low noise" claim: advisories on, say, a `fetch()`
call or a `db.query()` are intentional yellow nudges — they are not gate noise, and we
don't pretend they're zero.

## Current results

`diffgate bench` on the versioned corpus: **100% precision / 100% recall** on the labeled
positives, **0.00 false blocks per clean change**. (Reproduce with the command above —
don't take the number on faith; that's the point of shipping the corpus.)

## Comparing against other tools

To position against catch-rate-first reviewers, run their tool over the same corpus and
record false-blocks-per-clean-change and precision. The corpus is plain data — extend it
with cases from your own codebase (especially your historical false positives) so the
benchmark reflects *your* noise, not ours.
