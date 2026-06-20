// PR-native review: turn a DiffGate review into GitHub PR review comments + a commit status.
// The payload builder (buildPrReview) is pure and unit-tested; postPrReview does the I/O
// and takes an injectable fetch so it can be tested offline.
import path from "path";
import { TIER_ORDER, TIER_META } from "./core/tiers.js";
import type { AnalyzeResult, Tier } from "./core/types.js";

export interface PrComment {
  path: string;
  line: number;
  side: "RIGHT";
  body: string;
}

export interface PrReviewPayload {
  /** GitHub review action. We never auto-APPROVE — teams dislike bots approving. */
  event: "REQUEST_CHANGES" | "COMMENT";
  body: string;
  comments: PrComment[];
  /** Commit-status conclusion for the required check. */
  conclusion: "success" | "failure";
  counts: { green: number; yellow: number; orange: number };
  blocked: boolean;
}

export interface GithubContext {
  repo: string | null; // "owner/repo"
  prNumber: number | null;
  sha: string | null;
  token: string | null;
  apiUrl: string;
}

const MAX_COMMENTS = 50; // GitHub rejects oversized reviews; keep the signal, note the rest.

function commentBody(icon: string, title: string, ruleId: string, message: string, hasFix: boolean): string {
  const fix = hasFix ? "\n\n_A quick-fix is available in the editor extension._" : "";
  return `${icon} **${title}** \`${ruleId}\`\n\n${message}${fix}`;
}

/** Pure: map a review into a GitHub review payload + status conclusion. */
export function buildPrReview(
  files: AnalyzeResult[],
  cwd: string,
  opts: { failOn?: Tier } = {}
): PrReviewPayload {
  const failRank = TIER_ORDER[opts.failOn || "orange"] ?? 2;
  const counts = { green: 0, yellow: 0, orange: 0 };
  const all: PrComment[] = [];
  let blocked = false;

  for (const file of files) {
    const rel = path.relative(cwd, file.filePath).split(path.sep).join("/");
    for (const f of file.findings) {
      if (f.tier in counts) counts[f.tier as keyof typeof counts] += 1;
      if (f.blocking || (TIER_ORDER[f.tier] ?? 0) >= failRank) blocked = true;
      const meta = TIER_META[f.tier as Tier] || TIER_META.green;
      all.push({
        path: rel,
        line: f.endLine || f.line,
        side: "RIGHT",
        body: commentBody(meta.icon, f.title, f.ruleId, f.message, !!f.fix),
      });
    }
  }

  // Highest-impact comments first, then cap.
  all.sort((a, b) => rankOf(b) - rankOf(a));
  const comments = all.slice(0, MAX_COMMENTS);
  const omitted = all.length - comments.length;

  const total = counts.green + counts.yellow + counts.orange;
  const summary =
    total === 0
      ? "✅ **DiffGate**: no findings on the changed lines."
      : `**DiffGate** reviewed the changed lines — 🟢 ${counts.green} · 🟡 ${counts.yellow} · 🟠 ${counts.orange}.` +
        (blocked ? `\n\n🚫 **Blocked**: high-impact (orange) findings must be resolved before merge.` : "") +
        (omitted > 0 ? `\n\n_${omitted} lower-priority finding(s) not shown inline._` : "");

  return {
    event: blocked ? "REQUEST_CHANGES" : "COMMENT",
    body: summary,
    comments,
    conclusion: blocked ? "failure" : "success",
    counts,
    blocked,
  };
}

function rankOf(c: PrComment): number {
  if (c.body.startsWith("🟠")) return 2;
  if (c.body.startsWith("🟡")) return 1;
  return 0;
}

/** Resolve owner/repo, PR number, SHA and token from CI env + an optional --pr flag. */
export function resolveGithubContext(
  env: Record<string, string | undefined>,
  prFlag?: string,
  readEventFile?: (p: string) => string | null
): GithubContext {
  const apiUrl = env["GITHUB_API_URL"] || "https://api.github.com";
  const token = env["GITHUB_TOKEN"] || env["GH_TOKEN"] || null;
  const repo = env["GITHUB_REPOSITORY"] || null;
  let sha = env["GITHUB_SHA"] || null;

  let prNumber: number | null = null;
  if (prFlag && /^\d+$/.test(prFlag)) {
    prNumber = parseInt(prFlag, 10);
  } else {
    // refs/pull/<n>/merge
    const ref = env["GITHUB_REF"] || "";
    const m = ref.match(/^refs\/pull\/(\d+)\//);
    if (m) prNumber = parseInt(m[1], 10);
    // pull_request event payload
    if (prNumber === null && env["GITHUB_EVENT_PATH"] && readEventFile) {
      try {
        const raw = readEventFile(env["GITHUB_EVENT_PATH"]);
        const ev = raw ? JSON.parse(raw) : null;
        if (ev?.pull_request?.number) prNumber = Number(ev.pull_request.number);
        if (!sha && ev?.pull_request?.head?.sha) sha = String(ev.pull_request.head.sha);
      } catch {
        /* ignore malformed event payload */
      }
    }
  }
  return { repo, prNumber, sha, token, apiUrl };
}

type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;

/** Post the review + commit status. Returns a human summary of what was sent. */
export async function postPrReview(
  payload: PrReviewPayload,
  ctx: GithubContext,
  fetchImpl: FetchLike
): Promise<{ posted: boolean; reason?: string }> {
  if (!ctx.token) return { posted: false, reason: "no GITHUB_TOKEN/GH_TOKEN in env" };
  if (!ctx.repo) return { posted: false, reason: "no GITHUB_REPOSITORY in env" };

  const headers = {
    Authorization: `Bearer ${ctx.token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
  };

  // 1) Commit status (the required check). Needs a SHA.
  if (ctx.sha) {
    const desc =
      payload.counts.orange > 0
        ? `${payload.counts.orange} high-impact finding(s)`
        : payload.blocked
          ? "blocked"
          : "no high-impact findings";
    const res = await fetchImpl(`${ctx.apiUrl}/repos/${ctx.repo}/statuses/${ctx.sha}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ state: payload.conclusion === "failure" ? "failure" : "success", context: "diffgate", description: desc.slice(0, 140) }),
    });
    if (!res.ok) return { posted: false, reason: `status POST failed (${res.status}): ${(await res.text()).slice(0, 200)}` };
  }

  // 2) PR review with inline comments. Needs a PR number.
  if (ctx.prNumber) {
    const res = await fetchImpl(`${ctx.apiUrl}/repos/${ctx.repo}/pulls/${ctx.prNumber}/reviews`, {
      method: "POST",
      headers,
      body: JSON.stringify({ event: payload.event, body: payload.body, comments: payload.comments }),
    });
    if (!res.ok) return { posted: false, reason: `review POST failed (${res.status}): ${(await res.text()).slice(0, 200)}` };
  } else if (!ctx.sha) {
    return { posted: false, reason: "no PR number and no SHA — nothing to post to" };
  }

  return { posted: true };
}
