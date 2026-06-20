import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";

import { loadState, shouldShowGraphTip, recordGraphTipShown, GRAPH_TIP_LIMIT } from "../dist/core/index.js";

function tmpRepo() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "diffgate-state-"));
}

test("loadState: missing store returns a zeroed default", () => {
  const root = tmpRepo();
  assert.deepEqual(loadState(root), { graphTipShown: 0 });
});

test("graph tip shows up to the limit, then goes quiet", () => {
  const root = tmpRepo();
  let shows = 0;
  for (let i = 0; i < GRAPH_TIP_LIMIT + 5; i++) {
    if (shouldShowGraphTip(root)) {
      shows++;
      recordGraphTipShown(root);
    }
  }
  assert.equal(shows, GRAPH_TIP_LIMIT, "tip should appear exactly GRAPH_TIP_LIMIT times");
  assert.equal(shouldShowGraphTip(root), false, "tip is silent once the limit is reached");
  assert.equal(loadState(root).graphTipShown, GRAPH_TIP_LIMIT);
});

test("state persists across loads and ignores corrupt files", () => {
  const root = tmpRepo();
  recordGraphTipShown(root);
  assert.equal(loadState(root).graphTipShown, 1);
  fs.writeFileSync(path.join(root, ".diffgate", "state.json"), "{ not json");
  assert.deepEqual(loadState(root), { graphTipShown: 0 }, "corrupt state degrades to default, never throws");
});
