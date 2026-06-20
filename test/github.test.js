import test from "node:test";
import assert from "node:assert";
import { buildPrReview, resolveGithubContext, postPrReview } from "../dist/github.js";

function finding(ruleId, tier, over = {}) {
  return {
    ruleId, tier, blocking: tier === "orange", title: `${ruleId} title`,
    message: `${ruleId} message`, line: 10, column: 0, endLine: 10, endColumn: 5,
    code: "x", fix: null, ...over,
  };
}
function file(filePath, findings) {
  return { filePath, language: "javascript", findings, tier: "green", counts: { green: 0, yellow: 0, orange: 0 }, blocking: false };
}

test("buildPrReview", async (t) => {
  await t.test("blocks and REQUEST_CHANGES on orange", () => {
    const p = buildPrReview([file("/repo/a.js", [finding("sql-injection", "orange")])], "/repo");
    assert.equal(p.event, "REQUEST_CHANGES");
    assert.equal(p.conclusion, "failure");
    assert.equal(p.blocked, true);
    assert.equal(p.comments.length, 1);
    assert.equal(p.comments[0].path, "a.js");
    assert.equal(p.comments[0].side, "RIGHT");
    assert.match(p.comments[0].body, /sql-injection/);
  });

  await t.test("COMMENT (not block) when only yellow", () => {
    const p = buildPrReview([file("/repo/a.js", [finding("network-call", "yellow")])], "/repo");
    assert.equal(p.event, "COMMENT");
    assert.equal(p.conclusion, "success");
    assert.equal(p.blocked, false);
  });

  await t.test("clean review", () => {
    const p = buildPrReview([], "/repo");
    assert.equal(p.event, "COMMENT");
    assert.equal(p.blocked, false);
    assert.match(p.body, /no findings/i);
  });

  await t.test("caps comments at 50 and prioritizes orange", () => {
    const yellows = Array.from({ length: 60 }, (_, i) => finding("network-call", "yellow", { line: i + 1 }));
    const p = buildPrReview([file("/repo/a.js", [finding("sql-injection", "orange"), ...yellows])], "/repo");
    assert.equal(p.comments.length, 50);
    assert.match(p.comments[0].body, /🟠/); // orange surfaced first
    assert.match(p.body, /not shown inline/);
  });

  await t.test("failOn=yellow blocks on yellow", () => {
    const p = buildPrReview([file("/repo/a.js", [finding("network-call", "yellow")])], "/repo", { failOn: "yellow" });
    assert.equal(p.blocked, true);
  });
});

test("resolveGithubContext", async (t) => {
  await t.test("parses repo/sha/token + PR from refs/pull", () => {
    const ctx = resolveGithubContext({
      GITHUB_REPOSITORY: "acme/app", GITHUB_SHA: "abc123",
      GITHUB_TOKEN: "tok", GITHUB_REF: "refs/pull/42/merge",
    });
    assert.equal(ctx.repo, "acme/app");
    assert.equal(ctx.sha, "abc123");
    assert.equal(ctx.token, "tok");
    assert.equal(ctx.prNumber, 42);
  });

  await t.test("--pr flag overrides", () => {
    const ctx = resolveGithubContext({ GITHUB_REPOSITORY: "acme/app" }, "7");
    assert.equal(ctx.prNumber, 7);
  });

  await t.test("reads PR number + head sha from event payload", () => {
    const ctx = resolveGithubContext(
      { GITHUB_REPOSITORY: "acme/app", GITHUB_EVENT_PATH: "/x/event.json" },
      undefined,
      () => JSON.stringify({ pull_request: { number: 99, head: { sha: "deadbeef" } } })
    );
    assert.equal(ctx.prNumber, 99);
    assert.equal(ctx.sha, "deadbeef");
  });
});

test("postPrReview", async (t) => {
  await t.test("no token → not posted", async () => {
    const r = await postPrReview(buildPrReview([], "/repo"), { repo: "a/b", prNumber: 1, sha: "s", token: null, apiUrl: "https://api.github.com" }, async () => ({ ok: true, status: 200, text: async () => "" }));
    assert.equal(r.posted, false);
    assert.match(r.reason, /token/i);
  });

  await t.test("posts status + review", async () => {
    const calls = [];
    const fetchImpl = async (url, init) => { calls.push({ url, body: JSON.parse(init.body) }); return { ok: true, status: 200, text: async () => "" }; };
    const p = buildPrReview([file("/repo/a.js", [finding("sql-injection", "orange")])], "/repo");
    const r = await postPrReview(p, { repo: "acme/app", prNumber: 42, sha: "abc", token: "tok", apiUrl: "https://api.github.com" }, fetchImpl);
    assert.equal(r.posted, true);
    assert.equal(calls.length, 2);
    assert.match(calls[0].url, /statuses\/abc/);
    assert.equal(calls[0].body.state, "failure");
    assert.match(calls[1].url, /pulls\/42\/reviews/);
    assert.equal(calls[1].body.event, "REQUEST_CHANGES");
  });

  await t.test("surfaces API failure", async () => {
    const fetchImpl = async () => ({ ok: false, status: 422, text: async () => "bad" });
    const r = await postPrReview(buildPrReview([], "/repo"), { repo: "a/b", prNumber: 1, sha: "s", token: "t", apiUrl: "https://api.github.com" }, fetchImpl);
    assert.equal(r.posted, false);
    assert.match(r.reason, /422/);
  });
});
