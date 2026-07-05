#!/usr/bin/env node
// Review-state audit for PRs where an AI-attributed commit had >=1 DiffGate finding.
//
// Input:  a findings JSONL from scan-prs.mjs (fields: repo, pr, pop, ...)
// Output: research/out/review-state-<ts>.json + a summary table on stdout.
//
// scan-prs.mjs and its findings output are not distributed — they enumerate
// specific third-party PRs. To run this classification on your own corpus,
// provide a JSONL with one object per finding, minimally:
//   {"repo":"owner/name","pr":123,"pop":"ai"}
//
// For each distinct (repo, pr) with pop=="ai", fetches via `gh api`:
//   - review submissions        GET /repos/{r}/pulls/{n}/reviews
//   - inline review comments    GET /repos/{r}/pulls/{n}/comments
//   - conversation comments     GET /repos/{r}/issues/{n}/comments
//   - PR metadata (author)      GET /repos/{r}/pulls/{n}
//
// Classification (mutually exclusive partition over the PR set):
//   no_discussion        no non-status public discussion at all
//   bot_or_author_only   non-status discussion exists, but only from bots or the PR author
//   non_author_human     at least one non-status comment/review by a human who isn't the author
// Plus one overlapping count:
//   no_review_submission_or_inline   PRs with zero review submissions AND zero inline comments
//
// "Status" comments are deployment/CI/preview noise: authored by a known
// status bot, or a bot comment whose body matches deploy/preview/coverage
// boilerplate. Review bots (CodeRabbit, Devin, Copilot, ...) are NOT status
// bots — their comments count as discussion, attributed to "bot".

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const findingsPath = process.argv[2] ?? "research/out/findings-1782977478499.jsonl";

const STATUS_BOTS = new Set([
  "vercel[bot]", "netlify[bot]", "github-actions[bot]", "railway-app[bot]",
  "render[bot]", "cloudflare-workers-and-pages[bot]", "codecov[bot]",
  "coveralls[bot]", "deepsource-io[bot]", "sonarqubecloud[bot]", "socket-security[bot]",
  "changeset-bot[bot]", "vercel-deployment[bot]", "netlify-deploy[bot]",
]);
const STATUS_BODY_RE = /deployment|deploy preview|preview url|visit preview|coverage report|latest commit|inspect:|all checks|build (succeeded|failed)/i;

const isBot = (login, type) => type === "Bot" || /\[bot\]$/i.test(login ?? "");
const isStatus = (login, type, body) =>
  STATUS_BOTS.has(login) || (isBot(login, type) && STATUS_BODY_RE.test(body ?? ""));

function gh(path) {
  return JSON.parse(execFileSync("gh", ["api", "--paginate", "--slurp", path], {
    encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
  })).flat();
}

const prSet = new Map(); // "repo#pr" -> {repo, pr}
for (const line of readFileSync(findingsPath, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const f = JSON.parse(line);
  if (f.pop === "ai") prSet.set(`${f.repo}#${f.pr}`, { repo: f.repo, pr: f.pr });
}
console.error(`PRs with AI-attributed findings: ${prSet.size}`);

const results = [];
for (const { repo, pr } of prSet.values()) {
  const meta = gh(`repos/${repo}/pulls/${pr}`)[0];
  const author = meta.user?.login;
  const reviews = gh(`repos/${repo}/pulls/${pr}/reviews`);
  const inline = gh(`repos/${repo}/pulls/${pr}/comments`);
  const convo = gh(`repos/${repo}/issues/${pr}/comments`);

  // discussion units: conversation comments + inline comments + review
  // submissions that carry a body (empty approve-clicks are not discussion)
  const units = [
    ...convo.map(c => ({ login: c.user?.login, type: c.user?.type, body: c.body })),
    ...inline.map(c => ({ login: c.user?.login, type: c.user?.type, body: c.body })),
    ...reviews.filter(r => (r.body ?? "").trim()).map(r => ({ login: r.user?.login, type: r.user?.type, body: r.body })),
  ].filter(u => !isStatus(u.login, u.type, u.body));

  const nonAuthorHuman = units.some(u => !isBot(u.login, u.type) && u.login !== author);
  const cls = units.length === 0 ? "no_discussion"
    : nonAuthorHuman ? "non_author_human"
    : "bot_or_author_only";

  results.push({
    repo, pr, author,
    reviewSubmissions: reviews.length,
    inlineComments: inline.length,
    convoComments: convo.length,
    nonStatusDiscussionUnits: units.length,
    discussants: [...new Set(units.map(u => u.login))],
    classification: cls,
    noReviewSubmissionOrInline: reviews.length === 0 && inline.length === 0,
  });
  console.error(`${repo}#${pr}: ${cls} (reviews=${reviews.length} inline=${inline.length} convo=${convo.length})`);
}

const count = k => results.filter(r => r.classification === k).length;
const summary = {
  generatedAt: new Date().toISOString(),
  findingsInput: findingsPath,
  totalPRs: results.length,
  no_review_submission_or_inline: results.filter(r => r.noReviewSubmissionOrInline).length,
  no_discussion: count("no_discussion"),
  bot_or_author_only: count("bot_or_author_only"),
  non_author_human: count("non_author_human"),
};
console.log(JSON.stringify(summary, null, 2));
const out = `research/out/review-state-${Date.now()}.json`;
writeFileSync(out, JSON.stringify({ summary, results }, null, 2));
console.error(`wrote ${out}`);
