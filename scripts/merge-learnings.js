#!/usr/bin/env node
// Git merge driver for .diffgate/learnings.json.
// Merges two branches' verdict sets by id, with no conflicts.
// Latest timestamp wins when the same id appears in both branches.
//
// Setup (run once per repo):
//   git config merge.diffgate-learnings.driver 'node scripts/merge-learnings.js %O %A %B'
//   echo '.diffgate/learnings.json merge=diffgate-learnings' >> .gitattributes
//
// Git passes three temp-file paths: %O = base, %A = ours (written back), %B = theirs.
// Exit 0 = resolved; exit 1 = leave conflict markers for manual resolution.

import fs from "fs";

const [, , base, ours, theirs] = process.argv;

function readStore(file) {
  try {
    const raw = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (raw && Array.isArray(raw.entries)) return raw.entries;
  } catch {}
  return [];
}

const oursEntries = readStore(ours);
const theirsEntries = readStore(theirs);

// Merge: theirs first, then ours — ours wins when ids collide (local > incoming).
const byId = new Map();
for (const e of theirsEntries) byId.set(e.id, e);
for (const e of oursEntries)   byId.set(e.id, e);

// Within ties, prefer the newer timestamp.
for (const [id, e] of byId) {
  const other = theirsEntries.find((t) => t.id === id);
  if (other && other.at && e.at && other.at > e.at) byId.set(id, other);
}

const merged = {
  version: 1,
  entries: [...byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
};

fs.writeFileSync(ours, JSON.stringify(merged, null, 2) + "\n");
process.exit(0);
