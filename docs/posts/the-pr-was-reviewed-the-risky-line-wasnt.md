# The PR was reviewed. The risky line wasn't.

AI has made code cheaper to write. It has not made code cheaper to trust.

That is the part of the AI coding story that feels under-discussed. The industry has spent a lot of energy asking whether AI writes good code. It does, often. But even when the code is good on average, review does not scale the same way generation does. More code arrives. More diffs touch auth, databases, shells, migrations, and public APIs. Someone still has to decide which of those changes deserve a second pair of eyes.

That decision is where the bottleneck moved. Here is the number that convinced us: we found 109 merged pull requests where an AI-attributed commit tripped a DiffGate flag, and in only 3 of them did any human other than the author leave a public comment.

The rest of this post is how we got to that number, and what we think it means.

GitLab's [2026 AI Accountability Report](https://about.gitlab.com/resources/ai-accountability-survey-2026/) describes AI shifting work downstream into review, security, compliance, and deployment. Sonar's [2026 State of Code Developer Survey](https://www.sonarsource.com/state-of-code-developer-survey-report.pdf) says developers report that 42% of their code is now AI-generated or assisted, while 96% do not fully trust AI output and only 48% always check it before committing.

Recent research points in the same direction, but from a different angle. [AI Code in the Wild](https://arxiv.org/abs/2512.18567), a large empirical study of AI-generated code in GitHub repositories and CVE-linked changes, found that AI code is already substantial but concentrated in glue code, tests, refactoring, documentation, and boilerplate. The same paper argues that humans still act as security gatekeepers, and that when review is shallow, AI-introduced defects persist longer and spread further.

The review layer is not magically solved by adding another AI. A study of [GitHub Copilot Code Review](https://arxiv.org/abs/2509.13650) on labeled vulnerable code samples found that it frequently missed critical vulnerability classes such as SQL injection, XSS, and insecure deserialization, while focusing more on lower-severity issues. Another 2026 study of [security-related AI-generated pull requests](https://arxiv.org/abs/2604.19965) analyzed more than 33,000 AI-generated PRs, identified 675 security-related submissions, and found recurring weakness classes including injection flaws and path traversal. Many flawed contributions still merged.

So we asked a narrower question:

**When AI-assisted code touches a risky surface, does the normal PR process visibly notice?**

To answer that, we scanned 768 merge-range commits from 350 merged pull requests across 11 open-source repositories with visible AI-agent activity. We were not trying to prove that AI code is worse than human code. In fact, our data did not support that simple story. We were trying to see whether a small deterministic gate, run before or during PR creation, could catch review-worthy changes that current methods often leave implicit.

That gate is [DiffGate](https://github.com/srbsa/diffgate), the open-source tool we built for this problem. It is not a black-box benchmark artifact or a closed scanner. The rules and CLI live in the public repo, and the tool is intended to stay open source.

DiffGate is deliberately boring. It reads a diff and flags a small set of review-routing signals:

- auth or verification logic changed
- shell/process execution appeared
- SQL was built dynamically
- a schema or migration changed
- a public API boundary moved

Those flags do not all mean "vulnerability." They mean "do not let this pass as just another generated diff."

## What we scanned

We took 11 active OSS repositories across TypeScript, Python, Go, Ruby, and Kotlin. For each repo, we pulled roughly the last 40 merged PRs and ran DiffGate over the commits represented in each merged PR range.

The corpus:

- 350 merged PRs
- 768 scanned merge-range commits
- 327 commits with explicit AI-agent attribution, usually `Co-Authored-By` trailers
- 431 human-attributed commits
- 10 bot commits, split out from both groups

DiffGate flagged 43.1% of AI-attributed commits with at least one finding. More importantly, 22.3% tripped a non-advisory security-signal rule. About one in five.

The obvious headline would be: "AI commits are more dangerous."

We do not think the data supports that.

In the pooled data, AI-attributed commits had a higher hit rate than human commits. But the gap was mostly repository mix. AI-attributed commits were concentrated in repos with agent, shell, database, sandbox, and verification surfaces. Human commits were concentrated differently. In the repositories where both groups had enough commits to compare, the direction was mixed. In two of the three comparable repos, human commits had the higher non-advisory hit rate.

So this is not an "AI code is uniquely bad" post.

This is a review-routing post.

## What the PR trail showed

Next, we looked at the public GitHub review trail for the 109 PRs where at least one AI-attributed commit had a DiffGate finding. For each PR, we pulled every review submission, inline review comment, and conversation comment, filtered out deployment and CI status posts, and classified who — if anyone — actually discussed the change. The classification script — including exactly which bots count as status noise and what counts as discussion — is [in the repo](../../research/review-state.mjs).

The result was the part that made us lean forward:

- 73 of those PRs had no review submission and no inline review comment.
- 65 had no non-status public discussion at all after filtering out deployment/status comments.
- 41 had non-status discussion, but only from review bots or the PR author.
- Only 3 had public discussion from someone other than the PR author or a bot.

This does not prove nobody reviewed the code privately. Maintainers can review locally, in chat, in a meeting, or in their head. Open-source GitHub history is an imperfect window.

But it does show something useful: **most flagged AI-assisted changes had no public independent human discussion attached to the risky surface.**

That is exactly where a deterministic local gate can help. Not by replacing PR review. By making sure the risky line has a chance to become a review topic before the PR is already merged.

## Receipt 1: verification logic with no public review trail

[theonaai/Heron PR #115](https://github.com/theonaai/Heron/pull/115) changed OAuth evidence-verification logic in `slf-evidence-reconciliation.ts`.

The AI-co-authored commit [`55044bfa`](https://github.com/theonaai/Heron/commit/55044bfa) modified subject-scoped OAuth reconciliation. DiffGate flagged it as an auth/verification-path change.

The PR had zero GitHub reviews, zero review comments, and zero conversation comments.

Later in the same PR, [`4c2a664`](https://github.com/theonaai/Heron/commit/4c2a664) says a live audit exposed residual overclaim issues in that subject-scoped cross-reference logic and changed matching to prefer false negatives over overclaims.

This is not a "DiffGate found an exploit" receipt. It is better understood as a routing receipt.

The commit changed how verification claims were attached. DiffGate would have made that fact explicit at the moment the change was written. The PR history shows the same surface needed careful follow-up. The public review trail shows no second reviewer.

## Receipt 2: reviewed by an AI, but not on this risk

[Conway-Research/automaton PR #246](https://github.com/Conway-Research/automaton/pull/246) added recovery tools for a self-modifying agent.

The AI-co-authored commit [`146da515`](https://github.com/Conway-Research/automaton/commit/146da515) added seven `ctx.conway.exec(...)` calls to the agent tool layer. DiffGate flagged them as `dangerous-exec`.

The PR was reviewed by Devin. The public review comments were useful, but they focused on other issues: sandbox tier fallback and top-up error handling. The dynamic execution surface still merged without visible discussion of that risk class.

This is the cleanest comparison with current methods.

An AI reviewer and a deterministic gate are different tools. The reviewer reads broadly and decides what to say. It may summarize, prioritize, or spend attention elsewhere. The gate does not understand the whole system. But it can reliably say: a self-modifying agent just gained shell-execution recovery tools.

That is enough to require a second look.

## Receipt 3: the false positives matter too

The scan also found noise.

The raw findings included JavaScript `RegExp.prototype.exec()` calls, SQLite `db.exec(...)` in tests and migrations, and a documentation hit. Some were true process-execution surfaces. Some were not.

That is not an embarrassing footnote. It is part of the finding.

A local gate has a different failure mode from a dashboard scanner. If a dashboard is noisy, people ignore the dashboard. If a pre-commit or agent-loop gate is noisy, people turn it off.

The JS/TS regex `.exec()` false positive has already been fixed: DiffGate now distinguishes regex execution from process execution while still flagging `child_process`, `spawn`, `eval`, `new Function`, and custom shell-out wrappers such as `ctx.conway.exec(...)`.

The promise cannot be "zero false positives." The credible promise is narrower: small rule set, deterministic behavior, and fast correction when a rule proves too broad.

## Why position matters

Most review tools arrive after the PR exists.

That is useful, but late.

By then, the author may have moved on. The agent may have lost context. The diff may have grown from one risky line into forty changed files. Review comments become project management: assign a reviewer, wait, respond, patch, rerun CI.

DiffGate is meant to run earlier:

- locally, before commit
- in a pre-commit or pre-push hook
- in CI as a small deterministic gate
- inside an agent's MCP loop, before it hands work to a human

Editing is also where the risk concentrates. In a separate lab measurement, textbook OWASP bugs showed up 0% of the time across every model we tested — but the frontier model that wrote flawless code from scratch reintroduced second-order footguns (an unguarded recursive merge, a bare `cors()`) in 13% of edits to existing files ([the measurement](../MEASUREMENT.md)). Most of what an agent does is edit.

The cheapest time to fix a risky AI-assisted edit is when the agent has just written it.

That is the difference between "please review this PR" and "regenerate this change without shelling out."

## What we are claiming

We are not claiming AI code is worse than human code. Our within-repo check does not support that.

We are not claiming DiffGate found a pile of confirmed exploitable vulnerabilities. It did not.

We are not claiming public GitHub comments are the whole review process. They are only the public trail.

We are claiming this:

**In this corpus, one in five AI-attributed commits touched a non-advisory security-sensitive surface, and in only 3 of the 109 PRs containing flagged AI-attributed changes did anyone other than the author publicly discuss the change. A deterministic local gate can route attention before PR review has to rediscover the risk from scratch.**

That is a modest claim. It is also the claim we can defend.

## Why engineers should care

The scary version of AI coding is not always spectacular.

It is the PR that looks reviewed because a bot left comments, while the shell-execution surface was never discussed.

It is the verification logic change that merges with no public review trail.

It is the generated migration, the dynamic SQL helper, the new dependency, the auth-adjacent refactor.

Each one might be fine. But "might be fine" is exactly where review attention should go.

DiffGate's job is to put a hand on the commit and say:

This one.

You can run this study's core move on your own repo in one command — point it at the commits your agents already merged:

```
npx diffgate-review check --since=HEAD~20
```

Every flag is a line that shipped without a second pair of eyes, or with them — you'll know which, because it's your repo. Or wire the MCP server into your coding agent and make the agent read its own diff before handing the PR to a human.

## Methodology notes

- The harness scans each PR's merge range (`mergeCommit^..mergeCommit`); squash-merged PRs appear as squash commits, not original branch commits.
- Hit rates are per commit and not size-normalized. If AI commits are systematically larger, that inflates their per-commit rate.
- Attribution is trailer/author-based. Unattributed AI work counts as human, which biases the AI-vs-human comparison against us.
- The corpus overrepresents a few high-activity agent repos; that is exactly why we report the within-repo check instead of the pooled ratio.
- Review-state counts are public-trail evidence only, drawn from a fixed classification rule (status/deployment bot comments excluded, everything else counted as discussion). The classification script is published at [`research/review-state.mjs`](../../research/review-state.mjs). The PR-discovery harness and its findings dataset are not distributed — they enumerate specific third-party PRs, and we would rather not ship a call-out list. The receipts above are the public evidence, and the script documents the input contract if you want to run the same classification on your own corpus.
- All receipts were last re-verified against live GitHub on 2026-07-04.

---

## Sources

- [GitLab 2026 AI Accountability Report](https://about.gitlab.com/resources/ai-accountability-survey-2026/)
- [Sonar 2026 State of Code Developer Survey PDF](https://www.sonarsource.com/state-of-code-developer-survey-report.pdf)
- [Sonar State of Code report page](https://www.sonarsource.com/resources/developer-survey-report/)
- [AI Code in the Wild](https://arxiv.org/abs/2512.18567)
- [GitHub's Copilot Code Review: Can AI Spot Security Flaws Before You Commit?](https://arxiv.org/abs/2509.13650)
- [Insights into Security-Related AI-Generated Pull Requests](https://arxiv.org/abs/2604.19965)
- [What agents actually ship unprompted — the DiffGate lab measurement](../MEASUREMENT.md)
- [DiffGate source repository](https://github.com/srbsa/diffgate)
