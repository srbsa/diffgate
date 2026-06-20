# DiffGate on GitHub — PR-native review

DiffGate meets teams where review happens: the pull request. It posts inline review
comments on the changed lines and sets a `diffgate` commit status that gates merge on
high-impact (🟠 orange) findings.

There are two ways to run it. **Start with the Action** — it's zero-infrastructure and
works today. Graduate to the **App** when you want one-click org-wide rollout.

---

## Path 1 — GitHub Action (recommended start)

Drop [`.github/workflows/diffgate.yml`](../.github/workflows/diffgate.yml) into a repo.
On every PR it runs:

```bash
diffgate check --base="origin/$BASE" --pr="$PR_NUMBER" --no-gate
```

- `--base=<ref>` diffs the whole PR against the base branch (the working tree is clean
  in CI, so plain `--working` would see nothing).
- `--pr[=<n>]` posts a PR review (inline comments + summary) and a `diffgate` commit
  status. It uses `GITHUB_TOKEN` / `GITHUB_REPOSITORY` / the event payload from the
  Actions environment automatically.
- Exit code is `1` when orange findings are present, which fails the check.

Make it a **required status check** (Settings → Branches → Branch protection → require
`diffgate`) and orange findings now block merge — a gate, not just another comment.

Preview locally without posting:

```bash
diffgate check --base=origin/main --pr-dry-run   # prints the exact payload it would POST
```

## Path 2 — GitHub App (one-click org rollout)

The Action lives per-repo. An **App** installs once across an org and reviews every repo,
which is the bottom-up adoption motion the market leaders use.

A hosted webhook service is required (DiffGate's engine is the same; the App is the
transport). [`app-manifest.json`](app-manifest.json) is a ready-to-use
[App manifest](https://docs.github.com/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app-from-a-manifest):

1. Host a small webhook server (receives `pull_request` events, runs
   `diffgate check --base=<base> --pr=<n>` with the installation token).
2. Create the App from the manifest (fill in `hook_attributes.url` and `redirect_url`),
   or register it interactively.
3. Install on the org; reviews start on the next PR.

Permissions requested (least-privilege): `pull_requests: write`, `statuses: write`,
`contents: read`, `metadata: read`.

> The webhook server is intentionally out of this repo — deploy it on your own infra so
> code never leaves your boundary. The CLI's `--pr` path is the exact call the server makes.
