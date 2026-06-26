# Rolling DiffGate out to a team

DiffGate earns trust by being quiet and deterministic, then spreads by living where review actually happens: the pull request. Because the deterministic core runs **offline, in your CI, with no data egress**, it's adoptable by teams that can't send source to a hosted reviewer at all.

---

## Step 1: Add the GitHub Action (zero infrastructure)

Drop [`.github/workflows/diffgate.yml`](../.github/workflows/diffgate.yml) into your repo. On every PR it posts inline review comments + a `diffgate` commit status. Make it a required status check (Settings → Branches → require `diffgate`) and orange findings block merge.

```yaml
on: [pull_request]
jobs:
  diffgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: git reset --mixed "origin/${{ github.base_ref }}"
      - run: npx diffgate-review@latest check --working --github
```

See [docs/github-app.md](github-app.md) for the one-click org-wide App option.

### CLI flags for CI / pre-commit

```bash
diffgate check --staged              # pre-commit hook
diffgate check --fail-on=orange      # exit 1 blocks the build
diffgate check --json                # machine-readable output
diffgate check --github              # emit GitHub Actions inline PR annotations
diffgate check --pr                  # post PR review + commit status (gates merge)
```

---

## Step 2: Provable low noise

Before rolling it out, show the team the numbers. `diffgate bench` runs against a versioned corpus offline; anyone can reproduce it:

```bash
diffgate bench
# 100% precision / 100% recall / 0.00 false blocks per clean change
```

The gate only ever fires on changes that are genuinely high-impact. Safe edits (comments, logging, formatting) are never blocked. See [BENCHMARK.md](../BENCHMARK.md).

---

## Step 3: Spread noise suppression across the team

When DiffGate flags something that *isn't* actually risky, dismiss it once and it's gone for everyone:

```bash
diffgate feedback <ruleId> <file> <line> --dismiss   # suppress this pattern org-wide
git add .diffgate/learnings.json && git commit -m "chore: suppress <ruleId> false positive"
```

Committed `learnings.json` is automatically applied by every developer and in CI. `diffgate install-hook` sets up a **git merge driver** that auto-resolves parallel dismissals from different branches (no merge conflicts on the file). To merge verdicts from a shared policy repo:

```jsonc
// .diffgate.json
{ "learnings": { "shared": ["../shared-policy/.diffgate"] } }
```

---

## Step 4: Org-wide policy (no npm package required)

Policy packs can be a local path, no npm publishing needed:

```jsonc
// repos/<any-repo>/.diffgate.json
{ "extends": ["../../shared/.diffgate.json"] }   // relative path to a shared config file
```

Or an npm package when you're ready to formalize: `"extends": ["@acme/diffgate-policy"]`.

---

## Step 5: Metrics & signal

```bash
diffgate report            # tier breakdown, hotspot files, noise-reduction trend
diffgate report --compliance  # SOC 2 control evidence (see below)
diffgate stats             # signal-vs-noise: realized verdicts + predicted ratio
```

**Signal report.** `diffgate stats` turns the `confirm`/`dismiss` verdicts in `.diffgate/learnings.json` into a ratio of real catches to noise, lists **chronically-noisy rules** worth disabling, and scores the current diff (🟠/🟡 = signal, 🟢 = low-signal). Use it to prove and maintain a low-noise review.

---

## SOC 2 evidence

SOC 2's change-management criterion **CC8.1** requires changes be authorized, designed, tested, and approved before deployment. DiffGate's orange gate mechanizes exactly that control: a high-impact change cannot merge until it's reviewed (and, with a `testCommand`, until tests pass). Every run is reproducible, deterministic audit evidence.

```bash
diffgate report --compliance            # human-readable control evidence for the diff
diffgate report --compliance --json     # machine-readable, for attaching to an audit
```

Full rule → control mapping in [COMPLIANCE.md](../COMPLIANCE.md). (This is a control mapping to help you produce audit evidence, not a legal attestation.)
